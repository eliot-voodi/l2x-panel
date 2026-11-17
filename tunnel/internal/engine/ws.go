package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (e *Engine) hasWS() bool {
	e.wsMu.RLock()
	defer e.wsMu.RUnlock()
	return len(e.wsSlots) > 0
}

func (e *Engine) addWS(c *websocket.Conn) {
	if c == nil {
		return
	}
	e.wsMu.Lock()
	for _, s := range e.wsSlots {
		if s != nil && s.c == c {
			e.wsMu.Unlock()
			e.online.Store(true)
			e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
			return
		}
	}
	e.wsSlots = append(e.wsSlots, &wsSlot{c: c})
	var drop []*wsSlot
	for len(e.wsSlots) > maxAgentWS {
		drop = append(drop, e.wsSlots[0])
		e.wsSlots = e.wsSlots[1:]
	}
	e.wsMu.Unlock()
	for _, s := range drop {
		if s != nil && s.c != nil {
			_ = s.c.Close()
		}
	}
	e.online.Store(true)
	e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
}

func (e *Engine) clearWS(c *websocket.Conn) {
	e.wsMu.Lock()
	kept := e.wsSlots[:0]
	for _, s := range e.wsSlots {
		if s != nil && s.c == c {
			continue
		}
		kept = append(kept, s)
	}
	e.wsSlots = kept
	empty := len(e.wsSlots) == 0
	e.wsMu.Unlock()
	if empty {
		// Keep online if UDP peer is real (non-loopback).
		peer := e.GetPeer()
		if peer == nil || peer.IP == nil || peer.IP.IsLoopback() {
			e.online.Store(false)
		}
	}
}

func (e *Engine) writeWS(streamID uint32, packet []byte) error {
	e.wsMu.RLock()
	slots := e.wsSlots
	n := len(slots)
	e.wsMu.RUnlock()
	if n == 0 {
		return errNoPeer
	}
	idx := int(streamID) % n
	if streamID == 0 {
		idx = int(e.wsRR.Add(1)-1) % n
	}
	slot := slots[idx]
	if slot == nil || slot.c == nil {
		return errNoPeer
	}
	slot.writeMu.Lock()
	defer slot.writeMu.Unlock()
	_ = slot.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := slot.c.WriteMessage(websocket.BinaryMessage, packet)
	if err == nil {
		e.Stats.PacketsOut.Add(1)
	}
	return err
}

func (e *Engine) serveWSConn(c *websocket.Conn, remote string) {
	defer func() {
		if e.Role == "portal" {
			e.unregisterAgentWS(c)
		} else {
			e.clearWS(c)
		}
		_ = c.Close()
	}()

	agentID := ""
	if e.Role == "agent" {
		e.addWS(c)
		log.Printf("wss link up %s slots=%d", remote, e.wsSlotCount())
		payload := []byte(e.Token + "|" + e.NodeID)
		if err := e.SendCtrl(proto.TypeHELLO, payload); err != nil {
			log.Printf("wss hello send: %v", err)
		} else {
			log.Printf("wss hello sent node=%s", e.NodeID)
		}
	} else {
		log.Printf("wss link up %s (await hello)", remote)
	}

	for {
		_ = c.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, data, err := c.ReadMessage()
		if err != nil {
			log.Printf("wss read %s: %v", remote, err)
			return
		}
		e.Stats.PacketsIn.Add(1)

		if e.Role == "portal" && agentID == "" {
			if id := e.tryRegisterFromPacket(c, data); id != "" {
				agentID = id
				log.Printf("wss agent registered node=%s remote=%s", agentID, remote)
			}
		}
		e.handleCipherPacket(data, nil)
	}
}

func (e *Engine) wsSlotCount() int {
	e.wsMu.RLock()
	defer e.wsMu.RUnlock()
	return len(e.wsSlots)
}

// tryRegisterFromPacket decrypts one packet; on HELLO registers the agent WS.
func (e *Engine) tryRegisterFromPacket(c *websocket.Conn, packet []byte) string {
	if len(packet) < proto.HeaderSize+e.minOverhead() {
		return ""
	}
	hdr := packet[:proto.HeaderSize]
	body := packet[proto.HeaderSize:]
	typ := hdr[0] & 0x0f
	if typ != proto.TypeHELLO {
		return ""
	}
	seq := binary.BigEndian.Uint32(hdr[6:10])
	pathID := hdr[1] & 0x0f
	plain, used, err := e.openBody(pathID, seq, body, hdr)
	if err != nil {
		return ""
	}
	nodeID, ok := parseHelloPayload(plain, e.Token)
	if !ok {
		parts := strings.SplitN(string(plain), "|", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			nodeID = strings.TrimSpace(parts[1])
			ok = true
		}
	}
	if !ok || nodeID == "" {
		return ""
	}
	e.registerAgent(nodeID, c, used)
	return nodeID
}

// ServeWS listens for WebSocket upgrades; nginx terminates TLS (camouflage).
func (e *Engine) ServeWS(ctx context.Context, listen, path string) error {
	if path == "" {
		path = "/"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		c, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("ws upgrade: %v", err)
			return
		}
		go e.serveWSConn(c, r.RemoteAddr)
	})
	srv := &http.Server{Addr: listen, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("ws listen %s path=%s (HTTPS camouflage)", listen, path)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// DialWS keeps persistent WSS sessions to master (browser-like WebSocket over TLS).
// links controls parallel connections (default 4, max 4) for higher throughput.
func (e *Engine) DialWS(ctx context.Context, rawURL string, links int) error {
	if links < 1 {
		links = 4
	}
	if links > maxAgentWS {
		links = maxAgentWS
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	_ = u

	var wg sync.WaitGroup
	for i := 0; i < links; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e.dialWSLoop(ctx, rawURL, idx)
		}(i)
	}
	wg.Wait()
	return nil
}

func (e *Engine) dialWSLoop(ctx context.Context, rawURL string, idx int) {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("wss[%d] url: %v", idx, err)
		return
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   65536,
		WriteBufferSize:  65536,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.Hostname(),
			NextProtos: []string{"http/1.1"},
		},
	}
	header := http.Header{}
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	header.Set("Origin", "https://"+u.Host)

	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c, _, err := dialer.DialContext(ctx, rawURL, header)
		if err != nil {
			log.Printf("wss[%d] dial %s: %v (retry %s)", idx, rawURL, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		e.serveWSConn(c, rawURL)
		log.Printf("wss[%d] disconnected, reconnecting", idx)
	}
}
