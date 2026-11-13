package dnsd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	mtuProbeModeRaw    = 0
	mtuProbeModeBase64 = 1
	mtuProbeCodeLength = 4
	mtuProbeMetaLength = mtuProbeCodeLength + 2
	mtuProbeUpMinSize  = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = 6
	mtuProbeMaxDownSize = 8192
)

// Server is the DNS-tunnel sidecar.
type Server struct {
	cfg      *Config
	codec    *Codec
	sessions *sessionStore
	queries atomic.Uint64
}

func New(cfg *Config) (*Server, error) {
	codec, err := NewCodec(cfg.EncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		codec:    codec,
		sessions: newSessionStore(cfg.MaxSessions, time.Duration(cfg.SessionTimeoutSec)*time.Second),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 3)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", s.handleHealth)
		srv := &http.Server{Addr: s.cfg.HealthListen, Handler: mux}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		log.Printf("l2x-dnsd health on %s", s.cfg.HealthListen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenUDP)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp listen %s: %w", s.cfg.ListenUDP, err)
	}
	defer udp.Close()
	_ = udp.SetReadBuffer(8 << 20)
	_ = udp.SetWriteBuffer(8 << 20)
	log.Printf("l2x-dnsd udp %s domains=%v method=%d", s.cfg.ListenUDP, s.cfg.Domains, s.cfg.EncryptionMethod)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			pkt := append([]byte(nil), buf[:n]...)
			go s.serveUDP(udp, addr, pkt)
		}
	}()

	go func() {
		ln, err := net.Listen("tcp", s.cfg.ListenTCP)
		if err != nil {
			errCh <- fmt.Errorf("tcp listen %s: %w", s.cfg.ListenTCP, err)
			return
		}
		defer ln.Close()
		log.Printf("l2x-dnsd tcp %s", s.cfg.ListenTCP)
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go s.serveTCP(conn)
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"service":  "l2x-dnsd",
		"domains":  s.cfg.Domains,
		"queries":  s.queries.Load(),
		"sessions": s.sessions.count(),
		"method":   s.cfg.EncryptionMethod,
	})
}

func (s *Server) serveUDP(udp *net.UDPConn, addr *net.UDPAddr, pkt []byte) {
	resp := s.handleDNS(pkt)
	if resp == nil {
		return
	}
	_, _ = udp.WriteToUDP(resp, addr)
}

func (s *Server) serveTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var lenBuf [2]byte
	if _, err := ioReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > 65535 {
		return
	}
	buf := make([]byte, n)
	if _, err := ioReadFull(conn, buf); err != nil {
		return
	}
	resp := s.handleDNS(buf)
	if resp == nil {
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	_, _ = conn.Write(lenBuf[:])
	_, _ = conn.Write(resp)
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *Server) handleDNS(pkt []byte) []byte {
	s.queries.Add(1)
	q, _, err := parseFirstQuestion(pkt)
	if err != nil {
		return buildErrorResponse(pkt, rcodeFormatError)
	}
	domain, payloadLabels, ok := matchTunnelDomain(q.Name, s.cfg.Domains)
	if !ok {
		return buildErrorResponse(pkt, rcodeRefused)
	}

	// Authority / empty payload: NS/SOA/A for ns host
	if payloadLabels == "" {
		return buildAuthorityResponse(pkt, domain, s.cfg.NSHostname, s.cfg.NSIP, q.Type)
	}
	// Tunnel payloads ride on TXT (and ANY) questions.
	if q.Type != dnsTypeTXT && q.Type != 255 {
		return buildErrorResponse(pkt, rcodeNotImplemented)
	}

	raw, err := s.codec.DecodeStringAndDecrypt(payloadLabels)
	if err != nil {
		return buildErrorResponse(pkt, rcodeFormatError)
	}
	vpn, err := ParsePacket(raw)
	if err != nil {
		return buildErrorResponse(pkt, rcodeFormatError)
	}

	switch vpn.PacketType {
	case pktSessionInit:
		return s.handleSessionInit(pkt, q.Name, vpn)
	case pktMTUUpReq:
		return s.handleMTUUp(pkt, q.Name, vpn)
	case pktMTUDownReq:
		return s.handleMTUDown(pkt, q.Name, vpn)
	case pktSessionClose:
		if vpn.SessionID != 0 {
			s.sessions.close(vpn.SessionID)
		}
		return s.replyPacket(pkt, q.Name, nil, false)
	}

	sess, ok := s.sessions.get(vpn.SessionID, vpn.SessionCookie)
	if !ok {
		return s.replyBuilt(pkt, q.Name, BuildOptions{
			SessionID:  vpn.SessionID,
			PacketType: pktErrorDrop,
			Payload:    []byte{1, 2, 3, 4},
		}, false)
	}

	out := s.handleSessionPacket(sess, vpn)
	base64 := sess.responseBase64
	if out != nil {
		return s.replyPacket(pkt, q.Name, out, base64)
	}
	// Poll: return queued downlink if any
	if queued, ok := sess.dequeue(); ok {
		return s.replyPacket(pkt, q.Name, &queued, base64)
	}
	if vpn.PacketType == pktPing {
		pong := &Packet{
			SessionID:     sess.id,
			PacketType:    pktPong,
			SessionCookie: sess.cookie,
			Payload:       append([]byte(nil), vpn.Payload...),
		}
		return s.replyPacket(pkt, q.Name, pong, base64)
	}
	return s.replyPacket(pkt, q.Name, nil, base64)
}

func (s *Server) handleSessionInit(req []byte, name string, vpn Packet) []byte {
	if vpn.SessionID != 0 || len(vpn.Payload) != sessionInitDataSize {
		return nil
	}
	base64 := vpn.Payload[0] == mtuProbeModeBase64
	sess, _, err := s.sessions.findOrCreate(vpn.Payload, base64)
	if err == errSessionTableFull {
		return s.replyBuilt(req, name, BuildOptions{
			PacketType: pktSessionBusy,
			Payload:    append([]byte(nil), vpn.Payload[6:10]...),
		}, base64)
	}
	if err != nil || sess == nil {
		return nil
	}
	payload := encodeSessionAccept(sess.id, sess.cookie, 0, sess.verify, defaultPolicy())
	return s.replyBuilt(req, name, BuildOptions{
		PacketType: pktSessionAccept,
		Payload:    payload,
	}, base64)
}

func (s *Server) handleMTUUp(req []byte, name string, vpn Packet) []byte {
	if len(vpn.Payload) < mtuProbeUpMinSize {
		return nil
	}
	baseEncode := vpn.Payload[0] == mtuProbeModeBase64
	meta := make([]byte, mtuProbeMetaLength)
	copy(meta[:mtuProbeCodeLength], vpn.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(meta[mtuProbeCodeLength:], uint16(len(vpn.Payload)))
	return s.replyBuilt(req, name, BuildOptions{
		SessionID:       vpn.SessionID,
		PacketType:      pktMTUUpRes,
		SessionCookie:   vpn.SessionCookie,
		StreamID:        vpn.StreamID,
		SequenceNum:     vpn.SequenceNum,
		FragmentID:      vpn.FragmentID,
		TotalFragments:  vpn.TotalFragments,
		CompressionType: vpn.CompressionType,
		Payload:         meta,
	}, baseEncode)
}

func (s *Server) handleMTUDown(req []byte, name string, vpn Packet) []byte {
	if len(vpn.Payload) < mtuProbeDownMinSize {
		return nil
	}
	baseEncode := vpn.Payload[0] == mtuProbeModeBase64
	downloadSize := int(binary.BigEndian.Uint16(vpn.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return nil
	}
	payload := make([]byte, downloadSize)
	copy(payload[:mtuProbeCodeLength], vpn.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	for i := mtuProbeMetaLength; i < downloadSize; i++ {
		payload[i] = byte(i)
	}
	return s.replyBuilt(req, name, BuildOptions{
		SessionID:       vpn.SessionID,
		PacketType:      pktMTUDownRes,
		SessionCookie:   vpn.SessionCookie,
		StreamID:        vpn.StreamID,
		SequenceNum:     vpn.SequenceNum,
		FragmentID:      vpn.FragmentID,
		TotalFragments:  vpn.TotalFragments,
		CompressionType: vpn.CompressionType,
		Payload:         payload,
	}, baseEncode)
}

func (s *Server) handleSessionPacket(sess *session, vpn Packet) *Packet {
	switch vpn.PacketType {
	case pktPing:
		if queued, ok := sess.dequeue(); ok {
			return &queued
		}
		return &Packet{
			SessionID:     sess.id,
			PacketType:    pktPong,
			SessionCookie: sess.cookie,
			Payload:       append([]byte(nil), vpn.Payload...),
		}
	case pktSocks5SYN:
		return s.handleSocks5SYN(sess, vpn)
	case pktSocks5ConnectedAck, pktSocks5SYNAck:
		return nil
	case pktStreamData, pktStreamResend:
		return s.handleStreamData(sess, vpn)
	case pktStreamDataAck, pktStreamDataNack:
		return nil
	case pktStreamCloseWrite:
		if st, ok := sess.getStream(vpn.StreamID); ok {
			st.mu.Lock()
			if tc, ok := st.conn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			st.mu.Unlock()
		}
		return &Packet{
			SessionID:      sess.id,
			PacketType:     pktStreamCloseWriteA,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		}
	case pktStreamCloseRead:
		return &Packet{
			SessionID:      sess.id,
			PacketType:     pktStreamCloseReadA,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		}
	case pktStreamRST:
		sess.removeStream(vpn.StreamID)
		return &Packet{
			SessionID:      sess.id,
			PacketType:     pktStreamRSTA,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		}
	case pktSocks5ConnectFailA, pktSocks5HostUnreachA, pktSocks5ConnectionRefusedA,
		pktSocks5NetworkUnreachA, pktSocks5AddrTypeUnsuppA:
		return nil
	default:
		if queued, ok := sess.dequeue(); ok {
			return &queued
		}
		return nil
	}
}

func (s *Server) handleSocks5SYN(sess *session, vpn Packet) *Packet {
	// Always ACK SYN first path: dial then CONNECTED
	host, port, err := parseSocksTarget(vpn.Payload)
	ack := &Packet{
		SessionID:      sess.id,
		PacketType:     pktSocks5SYNAck,
		SessionCookie:  sess.cookie,
		HasStreamID:    true,
		StreamID:       vpn.StreamID,
		HasSequenceNum: true,
		SequenceNum:    vpn.SequenceNum,
	}
	if err != nil {
		sess.enqueue(Packet{
			SessionID:      sess.id,
			PacketType:     pktSocks5AddrTypeUnsupported,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		})
		return ack
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	timeout := time.Duration(s.cfg.ConnectTimeoutSec) * time.Second
	conn, dialErr := net.DialTimeout("tcp", addr, timeout)
	if dialErr != nil {
		failType := uint8(pktSocks5HostUnreachable)
		if ne, ok := dialErr.(net.Error); ok && ne.Timeout() {
			failType = pktSocks5TTLExpired
		}
		sess.enqueue(Packet{
			SessionID:      sess.id,
			PacketType:     failType,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		})
		return ack
	}
	st := &stream{id: vpn.StreamID, conn: conn, sendSeq: 1, recvExpect: vpn.SequenceNum + 1}
	sess.putStream(st)
	sess.startReader(st)
	sess.enqueue(Packet{
		SessionID:      sess.id,
		PacketType:     pktSocks5Connected,
		SessionCookie:  sess.cookie,
		HasStreamID:    true,
		StreamID:       vpn.StreamID,
		HasSequenceNum: true,
		SequenceNum:    vpn.SequenceNum,
	})
	return ack
}

func (s *Server) handleStreamData(sess *session, vpn Packet) *Packet {
	st, ok := sess.getStream(vpn.StreamID)
	if !ok || st.conn == nil {
		return &Packet{
			SessionID:      sess.id,
			PacketType:     pktStreamRST,
			SessionCookie:  sess.cookie,
			HasStreamID:    true,
			StreamID:       vpn.StreamID,
			HasSequenceNum: true,
			SequenceNum:    vpn.SequenceNum,
		}
	}
	if len(vpn.Payload) > 0 {
		_, _ = st.conn.Write(vpn.Payload)
	}
	return &Packet{
		SessionID:      sess.id,
		PacketType:     pktStreamDataAck,
		SessionCookie:  sess.cookie,
		HasStreamID:    true,
		StreamID:       vpn.StreamID,
		HasSequenceNum: true,
		SequenceNum:    vpn.SequenceNum,
	}
}

func (s *Server) replyPacket(req []byte, name string, p *Packet, baseEncode bool) []byte {
	if p == nil {
		h, err := parseDNSHeader(req)
		if err != nil {
			return nil
		}
		q, _, err := parseFirstQuestion(req)
		if err != nil {
			return buildErrorResponse(req, rcodeFormatError)
		}
		out := make([]byte, dnsHeaderSize+len(q.Raw))
		binary.BigEndian.PutUint16(out[0:2], h.ID)
		binary.BigEndian.PutUint16(out[2:4], buildResponseFlags(h.Flags, rcodeNoError))
		binary.BigEndian.PutUint16(out[4:6], 1)
		copy(out[dnsHeaderSize:], q.Raw)
		return out
	}
	return s.replyBuilt(req, name, BuildOptions{
		SessionID:       p.SessionID,
		PacketType:      p.PacketType,
		SessionCookie:   p.SessionCookie,
		StreamID:        p.StreamID,
		SequenceNum:     p.SequenceNum,
		FragmentID:      p.FragmentID,
		TotalFragments:  p.TotalFragments,
		CompressionType: p.CompressionType,
		Payload:         p.Payload,
	}, baseEncode)
}

func (s *Server) replyBuilt(req []byte, name string, opts BuildOptions, baseEncode bool) []byte {
	raw, err := BuildRaw(opts)
	if err != nil {
		return nil
	}
	out, err := buildTXTVPNResponse(req, name, raw, baseEncode)
	if err != nil {
		return nil
	}
	return out
}
