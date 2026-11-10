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
	"time"

	"github.com/gorilla/websocket"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (e *Engine) getWS() wsConn {
	e.wsMu.RLock()
	defer e.wsMu.RUnlock()
	return e.ws
}

func (e *Engine) setWS(c *websocket.Conn) {
	e.wsMu.Lock()
	old, _ := e.ws.(*websocket.Conn)
	e.ws = c
	e.wsMu.Unlock()
	if old != nil && old != c {
		_ = old.Close()
	}
	if c != nil {
		e.online.Store(true)
		e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	}
}

func (e *Engine) clearWS(c *websocket.Conn) {
	e.wsMu.Lock()
	cur, _ := e.ws.(*websocket.Conn)
	if cur == c {
		e.ws = nil
	}
	e.wsMu.Unlock()
}

func (e *Engine) writeWS(packet []byte) error {
	c := e.getWS()
	if c == nil {
		return errNoPeer
	}
	e.wsWriteMu.Lock()
	defer e.wsWriteMu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := c.WriteMessage(websocket.BinaryMessage, packet)
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
		e.setWS(c)
		log.Printf("wss link up %s", remote)
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

// tryRegisterFromPacket decrypts one packet; on HELLO registers the agent WS.
func (e *Engine) tryRegisterFromPacket(c *websocket.Conn, packet []byte) string {
	if len(packet) < proto.HeaderSize {
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
	nonce := crypto.Nonce12(pathID, seq)
	plain, err := e.Cipher.Open(nil, nonce, body, hdr)
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
	e.registerAgent(nodeID, c)
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

// DialWS keeps a persistent WSS session to master (browser-like WebSocket over TLS).
func (e *Engine) DialWS(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
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
			return nil
		default:
		}
		c, _, err := dialer.DialContext(ctx, rawURL, header)
		if err != nil {
			log.Printf("wss dial %s: %v (retry %s)", rawURL, err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		e.serveWSConn(c, rawURL)
		log.Printf("wss disconnected, reconnecting")
	}
}
