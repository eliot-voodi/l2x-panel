package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

// ServeSOCKS5 listens for SOCKS5 CONNECT/UDP ASSOCIATE and opens tunnel streams.
// Username (if provided) selects the agent node_id on a multi-agent portal.
func (e *Engine) ServeSOCKS5(ctx context.Context, listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Printf("socks5 listen %s (CONNECT+UDP ASSOCIATE; user=node_id)", listen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go e.handleSOCKS5(conn)
	}
}

func (e *Engine) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	if !e.Online() {
		return
	}
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	wantUserPass := false
	for i := 0; i < nMethods; i++ {
		if buf[i] == 0x02 {
			wantUserPass = true
			break
		}
	}
	agentID := ""
	if wantUserPass {
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// RFC1929 username/password
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		if buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
			return
		}
		agentID = string(buf[:ulen])
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		plen := int(buf[0])
		if plen > 0 {
			if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
				return
			}
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	if agentID != "" && e.Role == "portal" && !e.agentOnline(agentID) {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	host, port, err := readSocksAddr(conn, atyp, buf)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = host
	_ = port

	if !e.Online() {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// If no username, use single registered agent when only one is online.
	if agentID == "" && e.Role == "portal" {
		st := e.AgentsStatus()
		if len(st) == 1 {
			for id := range st {
				agentID = id
			}
		}
	}
	if e.Role == "portal" && agentID == "" {
		log.Printf("socks: no agent selected (provide SOCKS user=node_id)")
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch cmd {
	case 0x01: // CONNECT
		e.socksConnect(conn, agentID, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	case 0x03: // UDP ASSOCIATE
		e.socksUDPAssociate(conn, agentID)
	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func readSocksAddr(r io.Reader, atyp byte, buf []byte) (host string, port uint16, err error) {
	switch atyp {
	case 0x01: // IPv4
		if _, err = io.ReadFull(r, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err = io.ReadFull(r, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err = io.ReadFull(r, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 0x04: // IPv6
		if _, err = io.ReadFull(r, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		err = fmt.Errorf("bad atyp %d", atyp)
		return
	}
	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])
	return
}

func (e *Engine) socksConnect(conn net.Conn, agentID, target string) {
	id := e.nextID.Add(1)
	st := &stream{id: id, conn: conn, pathID: 0, agentID: agentID, ready: make(chan struct{})}
	e.mu.Lock()
	e.streams[id] = st
	e.mu.Unlock()
	e.Stats.Streams.Add(1)
	if err := e.sendForAgent(agentID, proto.Frame{Type: proto.TypeOPEN, StreamID: id, Payload: []byte(target)}, 0); err != nil {
		e.closeStream(id, false)
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	select {
	case <-st.ready:
	case <-time.After(8 * time.Second):
		log.Printf("socks open ack timeout target=%s agent=%s", target, agentID)
		e.closeStream(id, true)
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		e.closeStream(id, true)
		return
	}
	e.pipeConn(st)
}

func (e *Engine) socksUDPAssociate(ctrl net.Conn, agentID string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer pc.Close()

	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil {
		_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	ip4 := ua.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], uint16(ua.Port))
	if _, err := ctrl.Write(reply); err != nil {
		return
	}

	var (
		mu      sync.Mutex
		streams = map[string]uint32{} // host:port → stream id
		ids     []uint32
	)
	defer func() {
		mu.Lock()
		toClose := append([]uint32(nil), ids...)
		mu.Unlock()
		for _, id := range toClose {
			e.closeStream(id, true)
		}
	}()

	// Keep ASSOCIATE alive while control TCP is open; Xray holds this until UDP stops.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1)
		for {
			if _, err := ctrl.Read(buf); err != nil {
				return
			}
		}
	}()

	pktBuf := make([]byte, 2048)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := pc.ReadFrom(pktBuf)
		select {
		case <-done:
			return
		default:
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		host, port, hdr, data, perr := parseSocksUDP(pktBuf[:n])
		if perr != nil || len(data) == 0 {
			continue
		}
		target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

		mu.Lock()
		sid, exists := streams[target]
		mu.Unlock()
		if !exists {
			sid, err = e.openUDPStream(agentID, target, pc, from, hdr)
			if err != nil {
				continue
			}
			mu.Lock()
			streams[target] = sid
			ids = append(ids, sid)
			mu.Unlock()
		} else {
			// Refresh client addr / hdr for replies (Xray may change ephemeral port rarely).
			e.mu.RLock()
			st := e.streams[sid]
			e.mu.RUnlock()
			if st != nil && st.udpMode {
				st.udpMu.Lock()
				st.udpClient = from
				st.udpHdr = append(st.udpHdr[:0], hdr...)
				st.udpPC = pc
				st.udpMu.Unlock()
			}
		}
		_ = e.sendForAgent(agentID, proto.Frame{Type: proto.TypeDATA, StreamID: sid, Payload: data}, 0)
	}
}

func (e *Engine) openUDPStream(agentID, target string, pc net.PacketConn, from net.Addr, hdr []byte) (uint32, error) {
	id := e.nextID.Add(1)
	st := &stream{
		id:        id,
		pathID:    0,
		agentID:   agentID,
		ready:     make(chan struct{}),
		udpMode:   true,
		udpPC:     pc,
		udpClient: from,
		udpHdr:    append([]byte(nil), hdr...),
	}
	e.mu.Lock()
	if len(e.streams) >= e.MaxStr {
		e.mu.Unlock()
		return 0, fmt.Errorf("max streams")
	}
	e.streams[id] = st
	e.mu.Unlock()
	e.Stats.Streams.Add(1)

	payload := []byte("udp:" + target)
	if err := e.sendForAgent(agentID, proto.Frame{Type: proto.TypeOPEN, StreamID: id, Payload: payload}, 0); err != nil {
		e.closeStream(id, false)
		return 0, err
	}
	select {
	case <-st.ready:
	case <-time.After(8 * time.Second):
		log.Printf("socks udp open ack timeout target=%s agent=%s", target, agentID)
		e.closeStream(id, true)
		return 0, fmt.Errorf("open ack timeout")
	}
	return id, nil
}

// parseSocksUDP extracts destination and payload from a SOCKS5 UDP request packet.
// Returns hdr = ATYP+ADDR+PORT (for reply wrapping).
func parseSocksUDP(b []byte) (host string, port uint16, hdr, data []byte, err error) {
	if len(b) < 7 {
		err = io.ErrUnexpectedEOF
		return
	}
	// RSV(2) FRAG(1) — reject fragmented packets
	if b[2] != 0 {
		err = fmt.Errorf("frag")
		return
	}
	atyp := b[3]
	off := 4
	switch atyp {
	case 0x01:
		if len(b) < off+4+2 {
			err = io.ErrUnexpectedEOF
			return
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if len(b) < off+1 {
			err = io.ErrUnexpectedEOF
			return
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			err = io.ErrUnexpectedEOF
			return
		}
		host = string(b[off : off+l])
		off += l
	case 0x04:
		if len(b) < off+16+2 {
			err = io.ErrUnexpectedEOF
			return
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	default:
		err = fmt.Errorf("bad atyp")
		return
	}
	port = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	hdr = append([]byte(nil), b[3:off]...)
	data = append([]byte(nil), b[off:]...)
	return
}
