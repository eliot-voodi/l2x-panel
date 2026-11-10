package engine

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// agentLink is one connected tunnel-agent (WSS) on the portal.
type agentLink struct {
	id      string
	ws      *websocket.Conn
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

func (e *Engine) registerAgent(nodeID string, c *websocket.Conn) {
	e.initAgents()
	e.agentsMu.Lock()
	old := e.agents[nodeID]
	e.agents[nodeID] = &agentLink{id: nodeID, ws: c, online: true, seen: time.Now()}
	e.agentsMu.Unlock()
	e.online.Store(true)
	e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	if old != nil && old.ws != nil && old.ws != c {
		_ = old.ws.Close()
	}
}

func (e *Engine) unregisterAgentWS(c *websocket.Conn) {
	e.agentsMu.Lock()
	defer e.agentsMu.Unlock()
	for id, a := range e.agents {
		if a != nil && a.ws == c {
			delete(e.agents, id)
		}
	}
	if len(e.agents) == 0 {
		e.online.Store(false)
	}
}

func (e *Engine) agentOnline(nodeID string) bool {
	e.agentsMu.RLock()
	defer e.agentsMu.RUnlock()
	a := e.agents[nodeID]
	return a != nil && a.online && a.ws != nil
}

func (e *Engine) AgentsStatus() map[string]bool {
	e.agentsMu.RLock()
	defer e.agentsMu.RUnlock()
	out := make(map[string]bool, len(e.agents))
	for id, a := range e.agents {
		out[id] = a != nil && a.online && a.ws != nil
	}
	return out
}

func (e *Engine) writeAgentWS(nodeID string, packet []byte) error {
	e.agentsMu.RLock()
	a := e.agents[nodeID]
	e.agentsMu.RUnlock()
	if a == nil || a.ws == nil {
		return errNoPeer
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := a.ws.WriteMessage(websocket.BinaryMessage, packet)
	if err == nil {
		e.Stats.PacketsOut.Add(1)
	}
	return err
}
