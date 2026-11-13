package dnsd

import (
	"encoding/binary"
	"errors"
)

// Packet type constants (MasterDnsVPN wire IDs).
const (
	pktMTUUpReq   = 0x01
	pktMTUUpRes   = 0x02
	pktMTUDownReq = 0x03
	pktMTUDownRes = 0x04

	pktSessionInit   = 0x05
	pktSessionAccept = 0x06
	pktPing          = 0x07
	pktPong          = 0x08

	pktStreamSYN          = 0x09
	pktStreamSYNAck       = 0x0A
	pktStreamConnected    = 0x0B
	pktStreamConnectedAck = 0x0C
	pktStreamConnectFail  = 0x0D
	pktStreamConnectFailA = 0x0E
	pktStreamData         = 0x0F
	pktStreamDataAck      = 0x10
	pktStreamDataNack     = 0x11
	pktStreamResend       = 0x12
	pktPackedControl      = 0x13
	pktStreamCloseWrite   = 0x14
	pktStreamCloseWriteA  = 0x15
	pktStreamCloseRead    = 0x16
	pktStreamCloseReadA   = 0x17
	pktStreamRST          = 0x18
	pktStreamRSTA         = 0x19

	pktSocks5SYN                 = 0x1A
	pktSocks5SYNAck              = 0x1B
	pktSocks5ConnectFail         = 0x1C
	pktSocks5ConnectFailA        = 0x1D
	pktSocks5RulesetDenied       = 0x1E
	pktSocks5RulesetDeniedA      = 0x1F
	pktSocks5NetworkUnreachable  = 0x20
	pktSocks5NetworkUnreachA     = 0x21
	pktSocks5HostUnreachable     = 0x22
	pktSocks5HostUnreachA        = 0x23
	pktSocks5ConnectionRefused   = 0x24
	pktSocks5ConnectionRefusedA  = 0x25
	pktSocks5TTLExpired          = 0x26
	pktSocks5TTLExpiredA         = 0x27
	pktSocks5CommandUnsupported  = 0x28
	pktSocks5CommandUnsupportedA = 0x29
	pktSocks5AddrTypeUnsupported = 0x2A
	pktSocks5AddrTypeUnsuppA     = 0x2B
	pktSocks5AuthFailed          = 0x2C
	pktSocks5AuthFailedA         = 0x2D
	pktSocks5UpstreamUnavailable = 0x2E
	pktSocks5UpstreamUnavailA    = 0x2F
	pktSocks5Connected           = 0x30
	pktSocks5ConnectedAck        = 0x31

	pktSessionClose = 0x36
	pktSessionBusy  = 0x37
	pktErrorDrop    = 0xFF
)

const (
	flagValid = 1 << iota
	flagStream
	flagSequence
	flagFragment
	flagCompression
)

var (
	errPacketTooShort    = errors.New("vpn packet too short")
	errInvalidPacketType = errors.New("invalid vpn packet type")
	errInvalidHeaderChk  = errors.New("invalid vpn header check")
)

var packetFlags = buildPacketFlags()

// Packet is a parsed VPN frame.
type Packet struct {
	SessionID       uint8
	PacketType      uint8
	SessionCookie   uint8
	HasStreamID     bool
	StreamID        uint16
	HasSequenceNum  bool
	SequenceNum     uint16
	HasFragmentInfo bool
	FragmentID      uint8
	TotalFragments  uint8
	HasCompression  bool
	CompressionType uint8
	HeaderLength    int
	Payload         []byte
}

type BuildOptions struct {
	SessionID       uint8
	PacketType      uint8
	SessionCookie   uint8
	StreamID        uint16
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
}

func ParsePacket(data []byte) (Packet, error) {
	if len(data) < 4 {
		return Packet{}, errPacketTooShort
	}
	packetType := data[1]
	flags := packetFlags[packetType]
	if flags&flagValid == 0 {
		return Packet{}, errInvalidPacketType
	}
	minLen := 2 + 2
	if flags&flagStream != 0 {
		minLen += 2
	}
	if flags&flagSequence != 0 {
		minLen += 2
	}
	if flags&flagFragment != 0 {
		minLen += 2
	}
	if flags&flagCompression != 0 {
		minLen++
	}
	if len(data) < minLen {
		return Packet{}, errPacketTooShort
	}

	p := Packet{SessionID: data[0], PacketType: packetType}
	offset := 2
	if flags&flagStream != 0 {
		p.HasStreamID = true
		p.StreamID = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if flags&flagSequence != 0 {
		p.HasSequenceNum = true
		p.SequenceNum = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if flags&flagFragment != 0 {
		p.HasFragmentInfo = true
		p.FragmentID = data[offset]
		p.TotalFragments = data[offset+1]
		offset += 2
	}
	if flags&flagCompression != 0 {
		p.HasCompression = true
		p.CompressionType = data[offset]
		offset++
	}
	p.SessionCookie = data[offset]
	checkByte := data[offset+1]
	if checkByte != computeHeaderCheck(data[:offset+1]) {
		return Packet{}, errInvalidHeaderChk
	}
	p.HeaderLength = offset + 2
	p.Payload = append([]byte(nil), data[p.HeaderLength:]...)
	return p, nil
}

func BuildRaw(opts BuildOptions) ([]byte, error) {
	flags := packetFlags[opts.PacketType]
	if flags&flagValid == 0 {
		return nil, errInvalidPacketType
	}
	headerLen := 4
	if flags&flagStream != 0 {
		headerLen += 2
	}
	if flags&flagSequence != 0 {
		headerLen += 2
	}
	if flags&flagFragment != 0 {
		headerLen += 2
	}
	if flags&flagCompression != 0 {
		headerLen++
	}
	raw := make([]byte, headerLen+len(opts.Payload))
	raw[0] = opts.SessionID
	raw[1] = opts.PacketType
	offset := 2
	if flags&flagStream != 0 {
		binary.BigEndian.PutUint16(raw[offset:], opts.StreamID)
		offset += 2
	}
	if flags&flagSequence != 0 {
		binary.BigEndian.PutUint16(raw[offset:], opts.SequenceNum)
		offset += 2
	}
	if flags&flagFragment != 0 {
		raw[offset] = opts.FragmentID
		raw[offset+1] = opts.TotalFragments
		offset += 2
	}
	if flags&flagCompression != 0 {
		raw[offset] = opts.CompressionType
		offset++
	}
	raw[offset] = opts.SessionCookie
	offset++
	raw[offset] = computeHeaderCheck(raw[:offset])
	offset++
	copy(raw[offset:], opts.Payload)
	return raw, nil
}

func computeHeaderCheck(header []byte) byte {
	acc := byte(len(header)*17 + 0x5D)
	for idx, value := range header {
		acc += value + byte(idx)
		acc ^= value << (idx & 0x03)
	}
	return acc
}

func buildPacketFlags() [256]uint8 {
	var flags [256]uint8
	set := func(t uint8, extra uint8) { flags[t] |= flagValid | extra }
	setValid := func(t uint8) { flags[t] |= flagValid }

	for _, t := range []uint8{
		pktMTUUpRes, pktMTUDownReq, pktSessionInit, pktSessionAccept,
		pktSessionBusy, pktSessionClose, pktPing, pktPong, pktErrorDrop,
		pktMTUUpReq, pktMTUDownRes,
	} {
		setValid(t)
	}
	streamSeq := []uint8{
		pktStreamSYN, pktStreamSYNAck, pktStreamData, pktStreamDataAck,
		pktStreamDataNack, pktStreamResend, pktStreamCloseWrite, pktStreamCloseWriteA,
		pktStreamCloseRead, pktStreamCloseReadA, pktStreamRST, pktStreamRSTA,
		pktMTUUpReq, pktMTUDownRes, pktSocks5SYN, pktSocks5SYNAck,
		pktStreamConnected, pktStreamConnectedAck, pktStreamConnectFail, pktStreamConnectFailA,
		pktSocks5ConnectFail, pktSocks5ConnectFailA, pktSocks5RulesetDenied, pktSocks5RulesetDeniedA,
		pktSocks5NetworkUnreachable, pktSocks5NetworkUnreachA, pktSocks5HostUnreachable, pktSocks5HostUnreachA,
		pktSocks5ConnectionRefused, pktSocks5ConnectionRefusedA, pktSocks5TTLExpired, pktSocks5TTLExpiredA,
		pktSocks5CommandUnsupported, pktSocks5CommandUnsupportedA, pktSocks5AddrTypeUnsupported, pktSocks5AddrTypeUnsuppA,
		pktSocks5AuthFailed, pktSocks5AuthFailedA, pktSocks5UpstreamUnavailable, pktSocks5UpstreamUnavailA,
		pktSocks5Connected, pktSocks5ConnectedAck,
	}
	for _, t := range streamSeq {
		set(t, flagStream|flagSequence)
	}
	for _, t := range []uint8{pktStreamData, pktStreamResend, pktSocks5SYN, pktMTUUpReq, pktMTUDownRes} {
		flags[t] |= flagFragment
	}
	for _, t := range []uint8{pktStreamData, pktStreamResend, pktPackedControl, pktMTUUpReq, pktMTUDownRes} {
		flags[t] |= flagValid | flagCompression
	}
	return flags
}

// Session accept payload helpers (wire-compatible).

const (
	sessionAcceptBaseSize   = 7
	sessionAcceptPolicySize = 13
	sessionAcceptFullSize   = sessionAcceptBaseSize + sessionAcceptPolicySize
	sessionInitDataSize     = 10
)

type sessionAcceptPolicy struct {
	MaxPacketDuplicationCount  int
	MaxSetupDuplicationCount   int
	MaxUploadMTU               int
	MaxDownloadMTU             int
	MaxRxTxWorkers             int
	MinPingAggressiveInterval  float64
	MaxPacketsPerBatch         int
	MaxARQWindowSize           int
	MaxARQDataNackMaxGap       int
	MinCompressionMinSize      int
	MinARQInitialRTOSeconds    float64
}

func encodeSessionAccept(sessionID, cookie, compressionPair uint8, verify [4]byte, policy sessionAcceptPolicy) []byte {
	buf := make([]byte, sessionAcceptFullSize)
	buf[0] = sessionID
	buf[1] = cookie
	buf[2] = compressionPair
	copy(buf[3:7], verify[:])
	p := encodePolicy(policy)
	copy(buf[sessionAcceptBaseSize:], p[:])
	return buf
}

func encodePolicy(policy sessionAcceptPolicy) [sessionAcceptPolicySize]byte {
	var payload [sessionAcceptPolicySize]byte
	payload[0] = byte((clampInt(policy.MaxSetupDuplicationCount, 0, 15) << 4) |
		clampInt(policy.MaxPacketDuplicationCount, 0, 15))
	payload[1] = byte(clampInt(policy.MaxUploadMTU, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[2:4], uint16(clampInt(policy.MaxDownloadMTU, 0, 0xFFFF)))
	payload[4] = byte(clampInt(policy.MaxRxTxWorkers, 0, 0xFF))
	payload[5] = encodeScaled(policy.MinPingAggressiveInterval)
	payload[6] = byte(clampInt(policy.MaxPacketsPerBatch, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[7:9], uint16(clampInt(policy.MaxARQWindowSize, 0, 0xFFFF)))
	payload[9] = byte(clampInt(policy.MaxARQDataNackMaxGap, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[10:12], uint16(clampInt(policy.MinCompressionMinSize, 0, 0xFFFF)))
	payload[12] = encodeScaled(policy.MinARQInitialRTOSeconds)
	return payload
}

func encodeScaled(v float64) uint8 {
	const minV, maxV = 0.05, 1.0
	if v < minV {
		v = minV
	}
	if v > maxV {
		v = maxV
	}
	return uint8(((v - minV) / (maxV - minV)) * 255.0)
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func defaultPolicy() sessionAcceptPolicy {
	return sessionAcceptPolicy{
		MaxPacketDuplicationCount: 5,
		MaxSetupDuplicationCount:  6,
		MaxUploadMTU:              150,
		MaxDownloadMTU:            4096,
		MaxRxTxWorkers:            255,
		MinPingAggressiveInterval: 0.05,
		MaxPacketsPerBatch:        20,
		MaxARQWindowSize:          8000,
		MaxARQDataNackMaxGap:      255,
		MinCompressionMinSize:     120,
		MinARQInitialRTOSeconds:   0.05,
	}
}
