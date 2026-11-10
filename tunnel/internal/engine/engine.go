package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eliot-voodi/l2x-panel/tunnel/internal/crypto"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/pool"
	"github.com/eliot-voodi/l2x-panel/tunnel/internal/proto"
)

type Stats struct {
	BytesIn    atomic.Uint64
	BytesOut   atomic.Uint64
	Streams    atomic.Int64
	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
}

type stream struct {
	id      uint32
	conn    net.Conn
	pathID  uint8
	agentID string // portal: which agent owns this stream
	closed  atomic.Bool
	ready   chan struct{}
	buf     [][]byte
	bufMu   sync.Mutex
}

type Engine struct {
	Role     string // portal | agent
	Token    string
	NodeID   string
	Cipher   crypto.Cipher
	Pool     *pool.Pool
	Peer     *net.UDPAddr
	DefDial  string
	MaxStr   int
	Stats    Stats

	mu      sync.RWMutex
	streams map[uint32]*stream
	nextID  atomic.Uint32
	seq     atomic.Uint32
	online  atomic.Bool
	bufPool sync.Pool

	onAgentHello func(addr *net.UDPAddr)

	// Agent-side single WSS link (HTTPS camouflage).
	wsMu      sync.RWMutex
	wsWriteMu sync.Mutex
	ws        wsConn

	// Portal: many agents keyed by node_id (WSS).
	agentsMu sync.RWMutex
	agents   map[string]*agentLink
}

// wsConn is satisfied by *websocket.Conn (binary messages).
type wsConn interface {
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func New(role string, ciph crypto.Cipher, p *pool.Pool, token, nodeID, defDial string, maxStreams int) *Engine {
	if maxStreams <= 0 {
		maxStreams = 4000
	}
	e := &Engine{
		Role:     role,
		Token:    token,
		NodeID:   nodeID,
		Cipher:   ciph,
		Pool:     p,
		DefDial:  defDial,
		MaxStr:   maxStreams,
		streams:  make(map[uint32]*stream),
		bufPool: sync.Pool{New: func() any {
			b := make([]byte, 2048)
			return &b
		}},
	}
	e.nextID.Store(1)
	return e
}

func (e *Engine) SetPeer(addr *net.UDPAddr) {
	e.mu.Lock()
	e.Peer = addr
	e.mu.Unlock()
	e.online.Store(true)
}

func (e *Engine) GetPeer() *net.UDPAddr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Peer
}

func (e *Engine) Online() bool { return e.online.Load() }

func (e *Engine) Run(ctx context.Context) {
	for _, path := range e.Pool.Paths() {
		path := path
		go e.readLoop(ctx, path)
	}
	go e.keepalive(ctx)
	if e.Role == "agent" {
		go e.helloLoop(ctx)
	}
	<-ctx.Done()
}

func (e *Engine) helloLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			payload := []byte(e.Token + "|" + e.NodeID)
			_ = e.send(proto.Frame{Type: proto.TypeHELLO, Payload: payload}, 0)
		}
	}
}

func (e *Engine) keepalive(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.send(proto.Frame{Type: proto.TypeKA, Payload: []byte("ka")}, 0)
		}
	}
}

func (e *Engine) readLoop(ctx context.Context, path *pool.Path) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = path.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := path.Conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		e.handlePacket(path, addr, buf[:n])
	}
}

func (e *Engine) handlePacket(path *pool.Path, addr *net.UDPAddr, packet []byte) {
	e.Stats.PacketsIn.Add(1)
	_ = path
	e.handleCipherPacket(packet, addr)
}

func (e *Engine) handleCipherPacket(packet []byte, addr *net.UDPAddr) {
	if len(packet) < proto.HeaderSize+e.Cipher.Overhead() {
		return
	}
	hdr := packet[:proto.HeaderSize]
	body := packet[proto.HeaderSize:]
	seq := binary.BigEndian.Uint32(hdr[6:10])
	pathID := hdr[1] & 0x0f // sender path id in low nibble of flags
	nonce := crypto.Nonce12(pathID, seq)
	plain, err := e.Cipher.Open(nil, nonce, body, hdr)
	if err != nil {
		return
	}
	full := append(append([]byte{}, hdr...), plain...)
	binary.BigEndian.PutUint16(full[10:12], uint16(len(plain)))
	fr, err := proto.Decode(full)
	if err != nil {
		return
	}
	e.Stats.BytesIn.Add(uint64(len(plain)))
	e.dispatchFrame(fr, pathID, addr)
}

func (e *Engine) dispatchFrame(fr proto.Frame, pathID uint8, addr *net.UDPAddr) {
	switch fr.Type {
	case proto.TypeHELLO:
		if e.Role == "portal" {
			if addr != nil {
				e.SetPeer(addr)
			} else {
				e.online.Store(true)
				e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
			}
			nodeID, _ := parseHelloPayload(fr.Payload, e.Token)
			if nodeID == "" {
				// legacy: payload may be raw "token|node" already logged
				nodeID = string(fr.Payload)
			}
			_ = e.sendForAgent(nodeID, proto.Frame{Type: proto.TypeHELLOOK, Payload: []byte("ok")}, pathID)
			log.Printf("agent hello via %s node=%s", linkKind(addr), string(fr.Payload))
		}
	case proto.TypeHELLOOK:
		if addr != nil {
			e.SetPeer(addr)
		} else {
			e.online.Store(true)
		}
		log.Printf("portal hello-ok via %s", linkKind(addr))
	case proto.TypeKA:
		if e.Role == "portal" && e.GetPeer() == nil && addr != nil {
			e.SetPeer(addr)
		}
	case proto.TypePUNCH:
		if addr != nil {
			e.SetPeer(addr)
		}
		if fr.Flags&0x80 == 0 {
			_ = e.send(proto.Frame{Type: proto.TypePUNCH, Flags: 0x80, Payload: []byte("pong")}, pathID)
		}
	case proto.TypeOPEN:
		if e.Role == "agent" {
			go e.acceptOpen(fr)
		}
	case proto.TypeOPENACK:
		e.mu.RLock()
		st := e.streams[fr.StreamID]
		e.mu.RUnlock()
		if st != nil && st.ready != nil {
			select {
			case <-st.ready:
			default:
				close(st.ready)
			}
		}
	case proto.TypeDATA:
		e.onData(fr)
	case proto.TypeCLOSE:
		e.closeStream(fr.StreamID, false)
	}
}

func linkKind(addr *net.UDPAddr) string {
	if addr == nil {
		return "wss"
	}
	return addr.String()
}

func (e *Engine) send(fr proto.Frame, pathHint uint8) error {
	return e.sendForAgent("", fr, pathHint)
}

func (e *Engine) sendForAgent(agentID string, fr proto.Frame, pathHint uint8) error {
	if agentID == "" && fr.StreamID != 0 {
		e.mu.RLock()
		if st := e.streams[fr.StreamID]; st != nil {
			agentID = st.agentID
		}
		e.mu.RUnlock()
	}
	peer := e.GetPeer()
	if peer == nil && e.Role == "agent" && e.getWS() == nil {
		return errNoPeer
	}
	if peer == nil && e.Role == "portal" && agentID == "" && e.getWS() == nil {
		// allow if any agent online (control frames)
		if len(e.AgentsStatus()) == 0 {
			return errNoPeer
		}
	}
	return e.sendToAgent(peer, agentID, fr, pathHint)
}

var errNoPeer = errors.New("no peer")

func (e *Engine) sendTo(addr *net.UDPAddr, fr proto.Frame, pathHint uint8) error {
	return e.sendToAgent(addr, "", fr, pathHint)
}

func (e *Engine) sendToAgent(addr *net.UDPAddr, agentID string, fr proto.Frame, pathHint uint8) error {
	seq := e.seq.Add(1)
	fr.Seq = seq
	pathID := uint8(0)
	if e.Pool != nil {
		path := e.Pool.ByID(pathHint)
		if path == nil {
			path = e.Pool.Next()
		}
		if path != nil {
			pathID = path.ID
		}
	}
	fr.Flags = (fr.Flags & 0xf0) | (pathID & 0x0f)
	raw := make([]byte, proto.HeaderSize+len(fr.Payload)+e.Cipher.Overhead()+16)
	n, err := proto.Encode(raw, fr)
	if err != nil {
		return err
	}
	hdr := raw[:proto.HeaderSize]
	plain := raw[proto.HeaderSize:n]
	nonce := crypto.Nonce12(pathID, seq)
	ct := e.Cipher.Seal(nil, nonce, plain, hdr)
	out := append(append([]byte{}, hdr...), ct...)

	// Portal → specific agent WSS
	if e.Role == "portal" && agentID != "" {
		if err := e.writeAgentWS(agentID, out); err != nil {
			return err
		}
		e.Stats.BytesOut.Add(uint64(len(plain)))
		return nil
	}
	// Agent (or legacy single-link portal) WSS
	if e.getWS() != nil {
		if err := e.writeWS(out); err != nil {
			return err
		}
		e.Stats.BytesOut.Add(uint64(len(plain)))
		return nil
	}
	if e.Pool == nil || addr == nil {
		return errNoPeer
	}
	path := e.Pool.ByID(pathID)
	if path == nil {
		path = e.Pool.Next()
	}
	if path == nil {
		return errNoPeer
	}
	_, err = path.Conn.WriteToUDP(out, addr)
	if err == nil {
		e.Stats.PacketsOut.Add(1)
		e.Stats.BytesOut.Add(uint64(len(plain)))
	}
	return err
}

// SendCtrl sends a control frame to the current peer.
func (e *Engine) SendCtrl(typ uint8, payload []byte) error {
	return e.send(proto.Frame{Type: typ, Payload: payload}, 0)
}

func (e *Engine) acceptOpen(fr proto.Frame) {
	target := string(fr.Payload)
	if target == "" {
		target = e.DefDial
	}
	if target == "" {
		_ = e.send(proto.Frame{Type: proto.TypeCLOSE, StreamID: fr.StreamID}, 0)
		return
	}
	// Register immediately so early DATA is buffered before dial completes.
	st := &stream{id: fr.StreamID, pathID: 0, ready: make(chan struct{})}
	e.mu.Lock()
	if len(e.streams) >= e.MaxStr {
		e.mu.Unlock()
		_ = e.send(proto.Frame{Type: proto.TypeCLOSE, StreamID: fr.StreamID}, 0)
		return
	}
	e.streams[fr.StreamID] = st
	e.mu.Unlock()
	e.Stats.Streams.Add(1)

	conn, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		e.closeStream(fr.StreamID, true)
		return
	}
	st.conn = conn
	_ = e.send(proto.Frame{Type: proto.TypeOPENACK, StreamID: fr.StreamID}, 0)
	st.bufMu.Lock()
	pending := st.buf
	st.buf = nil
	st.bufMu.Unlock()
	for _, p := range pending {
		_, _ = conn.Write(p)
	}
	go e.pipeConn(st)
}

func (e *Engine) onData(fr proto.Frame) {
	e.mu.RLock()
	st := e.streams[fr.StreamID]
	e.mu.RUnlock()
	if st == nil || st.closed.Load() {
		return
	}
	if st.conn == nil {
		st.bufMu.Lock()
		if len(st.buf) < 64 {
			cp := make([]byte, len(fr.Payload))
			copy(cp, fr.Payload)
			st.buf = append(st.buf, cp)
		}
		st.bufMu.Unlock()
		return
	}
	_, _ = st.conn.Write(fr.Payload)
}

func (e *Engine) closeStream(id uint32, notify bool) {
	e.mu.Lock()
	st := e.streams[id]
	delete(e.streams, id)
	e.mu.Unlock()
	if st == nil {
		return
	}
	if st.closed.CompareAndSwap(false, true) {
		if st.ready != nil {
			select {
			case <-st.ready:
			default:
				close(st.ready)
			}
		}
		if st.conn != nil {
			_ = st.conn.Close()
		}
		e.Stats.Streams.Add(-1)
		if notify {
			_ = e.send(proto.Frame{Type: proto.TypeCLOSE, StreamID: id}, st.pathID)
		}
	}
}

func (e *Engine) pipeConn(st *stream) {
	buf := make([]byte, 1200)
	for {
		n, err := st.conn.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			_ = e.send(proto.Frame{Type: proto.TypeDATA, StreamID: st.id, Payload: payload}, st.pathID)
		}
		if err != nil {
			e.closeStream(st.id, true)
			return
		}
	}
}

// ServeProxy listens for local TCP and opens tunnel streams to dialTarget on agent.
func (e *Engine) ServeProxy(ctx context.Context, listen, dialTarget string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Printf("proxy listen %s -> agent dial %s", listen, dialTarget)
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
		go e.handleProxyConn(conn, dialTarget)
	}
}

func (e *Engine) handleProxyConn(conn net.Conn, dialTarget string) {
	if !e.Online() {
		_ = conn.Close()
		return
	}
	id := e.nextID.Add(1)
	nPaths := len(e.Pool.Paths())
	if nPaths < 1 {
		nPaths = 1
	}
	st := &stream{
		id: id, conn: conn,
		pathID: uint8(id % uint32(nPaths)),
		ready:  make(chan struct{}),
	}
	e.mu.Lock()
	e.streams[id] = st
	e.mu.Unlock()
	e.Stats.Streams.Add(1)
	if err := e.send(proto.Frame{Type: proto.TypeOPEN, StreamID: id, Payload: []byte(dialTarget)}, st.pathID); err != nil {
		e.closeStream(id, false)
		return
	}
	select {
	case <-st.ready:
	case <-time.After(8 * time.Second):
		log.Printf("stream %d open ack timeout", id)
		e.closeStream(id, true)
		return
	}
	e.pipeConn(st)
}

// AttachConn registers an existing connection as a stream (for tests).
func (e *Engine) AttachConn(conn net.Conn, dialTarget string) {
	e.handleProxyConn(conn, dialTarget)
}

func (e *Engine) CopyStats() (in, out uint64, streams int64, pin, pout uint64) {
	return e.Stats.BytesIn.Load(), e.Stats.BytesOut.Load(), e.Stats.Streams.Load(),
		e.Stats.PacketsIn.Load(), e.Stats.PacketsOut.Load()
}
