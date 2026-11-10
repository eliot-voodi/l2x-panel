package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

// ServeSOCKS5 listens for SOCKS5 CONNECT and opens a tunnel stream to the requested host:port.
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
	log.Printf("socks5 listen %s (dynamic dial via tunnel; user=node_id)", listen)
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
	if buf[0] != 0x05 || buf[1] != 0x01 { // CONNECT
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	var port uint16
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

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
