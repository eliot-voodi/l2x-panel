package engine

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
)

const maxAgentWS = 4

// wsSlot is one WSS connection with its own write lock (parallel congestion windows).
type wsSlot struct {
	c       *websocket.Conn
	writeMu sync.Mutex
}

// agentLink is one connected tunnel-agent (WSS pool and/or UDP) on the portal.
type agentLink struct {
	id     string
	ws     []*wsSlot
	udp    *net.UDPAddr
	cipher crypto.Cipher // nil → engine primary Cipher
	rr     atomic.Uint32
	online bool
	seen   time.Time
}

func (a *agentLink) hasWS() bool {
	return a != nil && len(a.ws) > 0
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
	if nodeID == "" || c == nil {
		return
	}
	e.initAgents()
	e.agentsMu.Lock()
	a := e.agents[nodeID]
	if a == nil {
		a = &agentLink{id: nodeID, online: true, seen: time.Now(), cipher: ciph}
		e.agents[nodeID] = a
	} else {
		a.online = true
		a.seen = time.Now()
		if ciph != nil {
			a.cipher = ciph
		}
	}
	for _, s := range a.ws {
		if s != nil && s.c == c {
			e.agentsMu.Unlock()
			e.online.Store(true)
			e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
			return
		}
	}
	a.ws = append(a.ws, &wsSlot{c: c})
	var drop []*wsSlot
	for len(a.ws) > maxAgentWS {
		drop = append(drop, a.ws[0])
		a.ws = a.ws[1:]
	}
	e.agentsMu.Unlock()
	for _, s := range drop {
		if s != nil && s.c != nil {
			_ = s.c.Close()
		}
	}
	e.online.Store(true)
	e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
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
		link.rr.Store(old.rr.Load())
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
		if a == nil {
			continue
		}
		kept := a.ws[:0]
		found := false
		for _, s := range a.ws {
			if s != nil && s.c == c {
				found = true
				continue
			}
			kept = append(kept, s)
		}
		if !found {
			continue
		}
		a.ws = kept
		if len(a.ws) == 0 && a.udp == nil {
			delete(e.agents, id)
		} else {
			a.online = true // remaining WSS and/or UDP may still be live
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
	if a.hasWS() {
		return true
	}
	if a.udp != nil && time.Since(a.seen) < 45*time.Second {
		return true
	}
	return false
}

func (e *Engine) agentHasUDP(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	e.agentsMu.RLock()
	a := e.agents[nodeID]
	e.agentsMu.RUnlock()
	return a != nil && a.udp != nil
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
		if a.hasWS() {
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

func (e *Engine) writeAgent(nodeID string, streamID uint32, packet []byte) error {
	e.agentsMu.RLock()
	a := e.agents[nodeID]
	e.agentsMu.RUnlock()
	if a == nil {
		return errNoPeer
	}
	// Prefer UDP when the agent punched a public path (profile=udp / both).
	if a.udp != nil && e.Pool != nil {
		path := e.Pool.Next()
		if path != nil {
			_, err := path.Conn.WriteToUDP(packet, a.udp)
			if err == nil {
				e.Stats.PacketsOut.Add(1)
				return nil
			}
		}
	}
	if !a.hasWS() {
		return errNoPeer
	}
	e.agentsMu.RLock()
	slots := a.ws
	n := len(slots)
	e.agentsMu.RUnlock()
	if n == 0 {
		return errNoPeer
	}
	idx := int(streamID) % n
	if streamID == 0 {
		idx = int(a.rr.Add(1)-1) % n
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
