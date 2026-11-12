package engine

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
)

// agentLink is one connected tunnel-agent (WSS and/or UDP) on the portal.
type agentLink struct {
	id      string
	ws      *websocket.Conn
	udp     *net.UDPAddr
	cipher  crypto.Cipher // nil → engine primary Cipher
	writeMu sync.Mutex
	online  bool
	seen    time.Time
}

func (e *Engine) initAgents() {
	e.agentsMu.Lock()
	if e.agents == nil {
		e.agents = map[string]*agentLink{}
	}
	e.agentsMu.Unlock()
}

func parseHelloPayload(payload []byte, expectToken string) (nodeID string, ok bool) {
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		return "", false
	}
	tok, id := parts[0], strings.TrimSpace(parts[1])
	if expectToken != "" && tok != expectToken {
		return "", false
	}
	if id == "" {
		return "", false
	}
	return id, true
}

func (e *Engine) SetAltCipher(c crypto.Cipher) {
	e.altMu.Lock()
	e.AltCipher = c
	e.altMu.Unlock()
}

func (e *Engine) registerAgent(nodeID string, c *websocket.Conn, ciph crypto.Cipher) {
	e.initAgents()
	e.agentsMu.Lock()
	old := e.agents[nodeID]
	link := &agentLink{id: nodeID, ws: c, online: true, seen: time.Now(), cipher: ciph}
	if old != nil {
		link.udp = old.udp
		if ciph == nil {
			link.cipher = old.cipher
		}
	}
	e.agents[nodeID] = link
	e.agentsMu.Unlock()
	e.online.Store(true)
	e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	if old != nil && old.ws != nil && old.ws != c {
		_ = old.ws.Close()
	}
}

func (e *Engine) registerAgentUDP(nodeID string, addr *net.UDPAddr, ciph crypto.Cipher) {
	if nodeID == "" || addr == nil {
		return
	}
	e.initAgents()
	e.agentsMu.Lock()
	old := e.agents[nodeID]
	link := &agentLink{id: nodeID, udp: addr, online: true, seen: time.Now(), cipher: ciph}
	if old != nil {
		link.ws = old.ws
		if ciph == nil {
			link.cipher = old.cipher
		}
	}
	e.agents[nodeID] = link
	e.agentsMu.Unlock()
	e.online.Store(true)
	e.SetPeer(addr)
}

func (e *Engine) setAgentCipher(nodeID string, ciph crypto.Cipher) {
	if nodeID == "" || ciph == nil {
		return
	}
	e.agentsMu.Lock()
	if a := e.agents[nodeID]; a != nil {
		a.cipher = ciph
		a.seen = time.Now()
		a.online = true
	}
	e.agentsMu.Unlock()
}

func (e *Engine) unregisterAgentWS(c *websocket.Conn) {
	e.agentsMu.Lock()
	defer e.agentsMu.Unlock()
	for id, a := range e.agents {
		if a != nil && a.ws == c {
			a.ws = nil
			if a.udp == nil {
				delete(e.agents, id)
			} else {
				a.online = true // UDP may still be live
			}
		}
	}
	if len(e.agents) == 0 {
		e.online.Store(false)
	}
}

func (e *Engine) touchAgentByUDP(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	key := addr.String()
	e.agentsMu.Lock()
	defer e.agentsMu.Unlock()
	for _, a := range e.agents {
		if a != nil && a.udp != nil && a.udp.String() == key {
			a.seen = time.Now()
			a.online = true
		}
	}
}

func (e *Engine) agentOnline(nodeID string) bool {
	e.agentsMu.RLock()
	defer e.agentsMu.RUnlock()
	a := e.agents[nodeID]
	if a == nil || !a.online {
		return false
	}
	if a.ws != nil {
		return true
	}
	if a.udp != nil && time.Since(a.seen) < 45*time.Second {
		return true
	}
	return false
}

func (e *Engine) AgentsStatus() map[string]bool {
	e.agentsMu.RLock()
	defer e.agentsMu.RUnlock()
	out := make(map[string]bool, len(e.agents))
	now := time.Now()
	for id, a := range e.agents {
		if a == nil || !a.online {
			out[id] = false
			continue
		}
		if a.ws != nil {
			out[id] = true
			continue
		}
		out[id] = a.udp != nil && now.Sub(a.seen) < 45*time.Second
	}
	return out
}

func (e *Engine) cipherForAgent(agentID string) crypto.Cipher {
	if agentID != "" {
		e.agentsMu.RLock()
		a := e.agents[agentID]
		e.agentsMu.RUnlock()
		if a != nil && a.cipher != nil {
			return a.cipher
		}
	}
	return e.Cipher
}

func (e *Engine) writeAgent(nodeID string, packet []byte) error {
	e.agentsMu.RLock()
	a := e.agents[nodeID]
	e.agentsMu.RUnlock()
	if a == nil {
		return errNoPeer
	}
	if a.ws != nil {
		a.writeMu.Lock()
		defer a.writeMu.Unlock()
		_ = a.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
		err := a.ws.WriteMessage(websocket.BinaryMessage, packet)
		if err == nil {
			e.Stats.PacketsOut.Add(1)
		}
		return err
	}
	if a.udp != nil && e.Pool != nil {
		path := e.Pool.Next()
		if path == nil {
			return errNoPeer
		}
		_, err := path.Conn.WriteToUDP(packet, a.udp)
		if err == nil {
			e.Stats.PacketsOut.Add(1)
		}
		return err
	}
	return errNoPeer
}
