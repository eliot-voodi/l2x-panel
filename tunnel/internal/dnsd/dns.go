package dnsd

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	dnsHeaderSize     = 12
	maxDNSLabelLen    = 63
	maxTXTStringLen   = 255
	dnsTypeA          = 1
	dnsTypeNS         = 2
	dnsTypeSOA        = 6
	dnsTypeTXT        = 16
	dnsTypeAAAA       = 28
	dnsTypeOPT        = 41
	dnsClassIN        = 1
	rcodeNoError      = 0
	rcodeFormatError  = 1
	rcodeNameError    = 3
	rcodeNotImplemented = 4
	rcodeRefused      = 5
)

var (
	errDNSTooShort = errors.New("dns packet too short")
	errDNSName     = errors.New("invalid dns name")
)

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
	Raw   []byte // wire bytes for the question (name+type+class)
}

type dnsHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func parseDNSHeader(pkt []byte) (dnsHeader, error) {
	if len(pkt) < dnsHeaderSize {
		return dnsHeader{}, errDNSTooShort
	}
	return dnsHeader{
		ID:      binary.BigEndian.Uint16(pkt[0:2]),
		Flags:   binary.BigEndian.Uint16(pkt[2:4]),
		QDCount: binary.BigEndian.Uint16(pkt[4:6]),
		ANCount: binary.BigEndian.Uint16(pkt[6:8]),
		NSCount: binary.BigEndian.Uint16(pkt[8:10]),
		ARCount: binary.BigEndian.Uint16(pkt[10:12]),
	}, nil
}

func parseFirstQuestion(pkt []byte) (dnsQuestion, int, error) {
	h, err := parseDNSHeader(pkt)
	if err != nil {
		return dnsQuestion{}, 0, err
	}
	if h.QDCount < 1 {
		return dnsQuestion{}, 0, errDNSTooShort
	}
	name, end, err := readDNSName(pkt, dnsHeaderSize)
	if err != nil {
		return dnsQuestion{}, 0, err
	}
	if end+4 > len(pkt) {
		return dnsQuestion{}, 0, errDNSTooShort
	}
	q := dnsQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(pkt[end : end+2]),
		Class: binary.BigEndian.Uint16(pkt[end+2 : end+4]),
		Raw:   append([]byte(nil), pkt[dnsHeaderSize:end+4]...),
	}
	return q, end + 4, nil
}

func readDNSName(pkt []byte, offset int) (string, int, error) {
	var labels []string
	jumped := false
	start := offset
	for {
		if offset >= len(pkt) {
			return "", 0, errDNSName
		}
		l := int(pkt[offset])
		if l == 0 {
			offset++
			break
		}
		if l&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				return "", 0, errDNSName
			}
			ptr := int(binary.BigEndian.Uint16(pkt[offset:offset+2]) & 0x3FFF)
			if !jumped {
				start = offset + 2
			}
			offset = ptr
			jumped = true
			continue
		}
		if l > maxDNSLabelLen || offset+1+l > len(pkt) {
			return "", 0, errDNSName
		}
		labels = append(labels, string(pkt[offset+1:offset+1+l]))
		offset += 1 + l
		if !jumped {
			start = offset
		}
	}
	end := start
	if jumped {
		end = start
	} else {
		end = offset
	}
	return strings.Join(labels, "."), end, nil
}

func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return []byte{0}
	}
	parts := strings.Split(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, p := range parts {
		if len(p) == 0 || len(p) > maxDNSLabelLen {
			continue
		}
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	out = append(out, 0)
	return out
}

// extractTunnelPayload returns concatenated payload labels for a query under domain.
func extractTunnelPayload(qname, domain string) (payload string, ok bool) {
	qname = normalizeDomain(qname)
	domain = normalizeDomain(domain)
	if qname == domain {
		return "", true // bare domain / authority query
	}
	if !strings.HasSuffix(qname, "."+domain) {
		return "", false
	}
	prefix := strings.TrimSuffix(qname, "."+domain)
	if prefix == "" {
		return "", true
	}
	return strings.ReplaceAll(prefix, ".", ""), true
}

func matchTunnelDomain(qname string, domains []string) (domain string, payload string, ok bool) {
	qname = normalizeDomain(qname)
	for _, d := range domains {
		d = normalizeDomain(d)
		if qname == d || strings.HasSuffix(qname, "."+d) {
			payload, _ = extractTunnelPayload(qname, d)
			return d, payload, true
		}
	}
	return "", "", false
}

func buildResponseFlags(reqFlags uint16, rcode uint16) uint16 {
	// QR=1, copy opcode, AA=1, keep RD, set RA=0
	flags := uint16(0x8400) | (reqFlags & 0x7800) | (reqFlags & 0x0100) | (rcode & 0xF)
	return flags
}

func buildErrorResponse(req []byte, rcode uint16) []byte {
	h, err := parseDNSHeader(req)
	if err != nil {
		return nil
	}
	q, qEnd, err := parseFirstQuestion(req)
	if err != nil {
		out := make([]byte, dnsHeaderSize)
		binary.BigEndian.PutUint16(out[0:2], h.ID)
		binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(h.Flags, rcode))
		return out
	}
	out := make([]byte, dnsHeaderSize+len(q.Raw))
	binary.BigEndian.PutUint16(out[0:2], h.ID)
	binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(h.Flags, rcode))
	binary.BigEndian.PutUint16(out[4:6], 1)
	copy(out[dnsHeaderSize:], q.Raw)
	_ = qEnd
	return out
}

func buildTXTVPNResponse(req []byte, answerName string, frame []byte, baseEncode bool) ([]byte, error) {
	chunk := buildTXTChunk(frame, baseEncode)
	return buildSingleTXTResponse(req, answerName, chunk)
}

func buildTXTChunk(data []byte, baseEncode bool) []byte {
	if baseEncode {
		enc := []byte(base64.StdEncoding.EncodeToString(data))
		return lengthPrefixedTXT(enc)
	}
	return lengthPrefixedTXT(data)
}

func lengthPrefixedTXT(data []byte) []byte {
	if len(data) <= maxTXTStringLen {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out
	}
	// Multi character-string inside one RDATA
	var out []byte
	for i := 0; i < len(data); i += maxTXTStringLen {
		end := i + maxTXTStringLen
		if end > len(data) {
			end = len(data)
		}
		out = append(out, byte(end-i))
		out = append(out, data[i:end]...)
	}
	return out
}

func buildSingleTXTResponse(req []byte, answerName string, rdata []byte) ([]byte, error) {
	h, err := parseDNSHeader(req)
	if err != nil {
		return nil, err
	}
	q, qEnd, err := parseFirstQuestion(req)
	if err != nil {
		return nil, err
	}
	nameBytes := encodeDNSName(answerName)
	if raw, _, ok := extractQuestionNameWire(req); ok && len(raw) > 0 {
		nameBytes = raw
	}
	optStart, optLen := findOPT(req, qEnd)

	out := make([]byte, dnsHeaderSize+len(q.Raw)+len(nameBytes)+10+len(rdata)+optLen)
	binary.BigEndian.PutUint16(out[0:2], h.ID)
	binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(h.Flags, rcodeNoError))
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 1)
	binary.BigEndian.PutUint16(out[8:10], 0)
	ar := uint16(0)
	if optLen > 0 {
		ar = 1
	}
	binary.BigEndian.PutUint16(out[10:12], ar)

	off := dnsHeaderSize
	off += copy(out[off:], q.Raw)
	off += copy(out[off:], nameBytes)
	binary.BigEndian.PutUint16(out[off:off+2], dnsTypeTXT)
	binary.BigEndian.PutUint16(out[off+2:off+4], dnsClassIN)
	binary.BigEndian.PutUint32(out[off+4:off+8], 0)
	binary.BigEndian.PutUint16(out[off+8:off+10], uint16(len(rdata)))
	off += 10
	off += copy(out[off:], rdata)
	if optLen > 0 {
		copy(out[off:], req[optStart:optStart+optLen])
	}
	return out, nil
}

func extractQuestionNameWire(pkt []byte) ([]byte, string, bool) {
	if len(pkt) < dnsHeaderSize+1 {
		return nil, "", false
	}
	off := dnsHeaderSize
	start := off
	for {
		if off >= len(pkt) {
			return nil, "", false
		}
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			return nil, "", false
		}
		if off+1+l > len(pkt) {
			return nil, "", false
		}
		off += 1 + l
	}
	name, _, err := readDNSName(pkt, start)
	if err != nil {
		return nil, "", false
	}
	return append([]byte(nil), pkt[start:off]...), name, true
}

func findOPT(pkt []byte, afterQuestion int) (start, length int) {
	h, err := parseDNSHeader(pkt)
	if err != nil || h.ARCount == 0 {
		return 0, 0
	}
	off := afterQuestion
	// skip answers + authority (usually 0 on queries)
	for i := 0; i < int(h.ANCount+h.NSCount); i++ {
		_, nOff, err := readDNSName(pkt, off)
		if err != nil || nOff+10 > len(pkt) {
			return 0, 0
		}
		rdlen := int(binary.BigEndian.Uint16(pkt[nOff+8 : nOff+10]))
		off = nOff + 10 + rdlen
	}
	for i := 0; i < int(h.ARCount); i++ {
		nameOff := off
		_, nOff, err := readDNSName(pkt, off)
		if err != nil || nOff+10 > len(pkt) {
			return 0, 0
		}
		typ := binary.BigEndian.Uint16(pkt[nOff : nOff+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[nOff+8 : nOff+10]))
		end := nOff + 10 + rdlen
		if end > len(pkt) {
			return 0, 0
		}
		if typ == dnsTypeOPT {
			return nameOff, end - nameOff
		}
		off = end
	}
	return 0, 0
}

func buildAuthorityResponse(req []byte, domain, nsHost, nsIP string, qtype uint16) []byte {
	h, err := parseDNSHeader(req)
	if err != nil {
		return nil
	}
	q, _, err := parseFirstQuestion(req)
	if err != nil {
		return buildErrorResponse(req, rcodeFormatError)
	}
	domain = normalizeDomain(domain)
	nsHost = normalizeDomain(nsHost)
	if nsHost == "" {
		nsHost = "ns." + domain
	}

	var answers []byte
	anCount := 0
	switch qtype {
	case dnsTypeNS:
		rdata := encodeDNSName(nsHost)
		answers = appendRR(encodeDNSName(domain), dnsTypeNS, 300, rdata)
		anCount = 1
	case dnsTypeA:
		ip := net.ParseIP(nsIP)
		if ip4 := ip.To4(); ip4 != nil && (normalizeDomain(q.Name) == nsHost || strings.HasPrefix(normalizeDomain(q.Name), "ns.")) {
			answers = appendRR(encodeDNSName(q.Name), dnsTypeA, 300, ip4)
			anCount = 1
		} else if ip4 != nil && normalizeDomain(q.Name) == domain {
			// Glue not for apex unless configured; NXDOMAIN-ish NOERROR empty
		}
	case dnsTypeAAAA:
		// empty NOERROR
	case dnsTypeSOA:
		// mname rname serial refresh retry expire minimum
		soa := append(encodeDNSName(nsHost), encodeDNSName("hostmaster."+domain)...)
		serial := make([]byte, 20)
		binary.BigEndian.PutUint32(serial[0:4], 1)
		binary.BigEndian.PutUint32(serial[4:8], 3600)
		binary.BigEndian.PutUint32(serial[8:12], 600)
		binary.BigEndian.PutUint32(serial[12:16], 86400)
		binary.BigEndian.PutUint32(serial[16:20], 60)
		soa = append(soa, serial...)
		answers = appendRR(encodeDNSName(domain), dnsTypeSOA, 300, soa)
		anCount = 1
	default:
		return buildErrorResponse(req, rcodeNotImplemented)
	}

	out := make([]byte, dnsHeaderSize+len(q.Raw)+len(answers))
	binary.BigEndian.PutUint16(out[0:2], h.ID)
	binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(h.Flags, rcodeNoError))
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(anCount))
	copy(out[dnsHeaderSize:], q.Raw)
	copy(out[dnsHeaderSize+len(q.Raw):], answers)
	return out
}

func appendRR(name []byte, typ uint16, ttl uint32, rdata []byte) []byte {
	out := make([]byte, 0, len(name)+10+len(rdata))
	out = append(out, name...)
	tmp := make([]byte, 10)
	binary.BigEndian.PutUint16(tmp[0:2], typ)
	binary.BigEndian.PutUint16(tmp[2:4], dnsClassIN)
	binary.BigEndian.PutUint32(tmp[4:8], ttl)
	binary.BigEndian.PutUint16(tmp[8:10], uint16(len(rdata)))
	out = append(out, tmp...)
	out = append(out, rdata...)
	return out
}
