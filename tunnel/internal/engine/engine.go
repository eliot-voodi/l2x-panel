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

	// Portal SOCKS UDP ASSOCIATE: DATA frames are relayed as datagrams (not TCP).
	udpMode   bool
	udpPC     net.PacketConn
	udpClient net.Addr
	udpHdr    []byte // ATYP+ADDR+PORT for SOCKS UDP replies
	udpMu     sync.Mutex
}

type Engine struct {
	Role     string // portal | agent
	Token    string
	NodeID   string
	Cipher   crypto.Cipher
	AltCipher crypto.Cipher // portal: accept dpi_lite (null) agents alongside chacha
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

	// Agent-side WSS pool (HTTPS camouflage; parallel links for throughput).
	wsMu    sync.RWMutex
	wsSlots []*wsSlot
	wsRR    atomic.Uint32

	// Portal: many agents keyed by node_id (WSS and/or UDP).
	agentsMu sync.RWMutex
	agents   map[string]*agentLink
	altMu    sync.RWMutex
}

const (
	dataChunkWSS = 32768
	dataChunkUDP = 1200
	tcpBufSize   = 4 << 20 // 4 MiB
)

func New(role string, ciph crypto.Cipher, p *pool.Pool, token, nodeID, defDial string, maxStreams int) *Engine {
	if maxStreams <= 0 {
		maxStreams = 4000
	}
	poolSize := proto.HeaderSize + proto.MaxPayload + 64
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
			b := make([]byte, poolSize)
			return &b
		}},
	}
	e.nextID.Store(1)
	return e
}

// tuneTCP applies NoDelay + larger buffers for bulk throughput.
func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(tcpBufSize)
	_ = tc.SetWriteBuffer(tcpBufSize)
}

// useUDPChunk is true when the tunnel datapath prefers UDP (MTU-safe frames).
func (e *Engine) useUDPChunk(agentID string) bool {
	if e.Role == "portal" {
		return e.agentHasUDP(agentID)
	}
	peer := e.GetPeer()
	return peer != nil && peer.IP != nil && !peer.IP.IsLoopback()
}

func (e *Engine) dataChunkSize(agentID string) int {
	if e.useUDPChunk(agentID) {
		return dataChunkUDP
	}
	return dataChunkWSS
}

// sendDATA fragments payload to path-appropriate DATA frames.
func (e *Engine) sendDATA(st *stream, payload []byte) error {
	if st == nil || len(payload) == 0 {
		return nil
	}
	chunk := e.dataChunkSize(st.agentID)
	if chunk < 1 {
		chunk = dataChunkUDP
	}
	for len(payload) > 0 {
		n := chunk
		if n > len(payload) {
			n = len(payload)
		}
		p := make([]byte, n)
		copy(p, payload[:n])
		if err := e.send(proto.Frame{Type: proto.TypeDATA, StreamID: st.id, Payload: p}, st.pathID); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
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
	// Burst HELLO until the portal ACKs, then slow refresh (KA already runs every 5s).
	// Previously every 2s forever — noisy logs and extra portal work for no gain.
	fast := time.NewTicker(2 * time.Second)
	defer fast.Stop()
	acked := false
	payload := []byte(e.Token + "|" + e.NodeID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			_ = e.send(proto.Frame{Type: proto.TypeHELLO, Payload: payload}, 0)
			if e.online.Load() {
				if !acked {
					acked = true
					fast.Reset(60 * time.Second)
				}
			}
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

func (e *Engine) minOverhead() int {
	oh := e.Cipher.Overhead()
	e.altMu.RLock()
	alt := e.AltCipher
	e.altMu.RUnlock()
	if alt != nil && alt.Overhead() < oh {
		oh = alt.Overhead()
	}
	return oh
}

func (e *Engine) openBody(pathID uint8, seq uint32, body, hdr []byte) ([]byte, crypto.Cipher, error) {
	nonce := crypto.Nonce12(pathID, seq)
	plain, err := e.Cipher.Open(nil, nonce, body, hdr)
	if err == nil {
		return plain, e.Cipher, nil
	}
	e.altMu.RLock()
	alt := e.AltCipher
	e.altMu.RUnlock()
	if alt != nil {
		plain, err = alt.Open(nil, nonce, body, hdr)
		if err == nil {
			return plain, alt, nil
		}
	}
	return nil, nil, err
}

func (e *Engine) handleCipherPacket(packet []byte, addr *net.UDPAddr) {
	if len(packet) < proto.HeaderSize+e.minOverhead() {
		return
	}
	hdr := packet[:proto.HeaderSize]
	body := packet[proto.HeaderSize:]
	seq := binary.BigEndian.Uint32(hdr[6:10])
	pathID := hdr[1] & 0x0f // sender path id in low nibble of flags
	plain, used, err := e.openBody(pathID, seq, body, hdr)
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
	if addr != nil {
		e.touchAgentByUDP(addr)
	}
	e.dispatchFrame(fr, pathID, addr, used)
}

func (e *Engine) dispatchFrame(fr proto.Frame, pathID uint8, addr *net.UDPAddr, used crypto.Cipher) {
	switch fr.Type {
	case proto.TypeHELLO:
		if e.Role == "portal" {
			nodeID, _ := parseHelloPayload(fr.Payload, e.Token)
			if nodeID == "" {
				// legacy: payload may be raw "token|node" already logged
				nodeID = string(fr.Payload)
			}
			if addr != nil {
				e.registerAgentUDP(nodeID, addr, used)
			} else {
				e.online.Store(true)
				e.SetPeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
				e.setAgentCipher(nodeID, used)
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
	if peer == nil && e.Role == "agent" && !e.hasWS() {
		return errNoPeer
	}
	if peer == nil && e.Role == "portal" && agentID == "" && !e.hasWS() {
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
	ciph := e.Cipher
	if e.Role == "portal" && agentID != "" {
		ciph = e.cipherForAgent(agentID)
	}
	need := proto.HeaderSize + len(fr.Payload) + ciph.Overhead()
	bp := e.bufPool.Get().(*[]byte)
	raw := *bp
	if cap(raw) < need {
		raw = make([]byte, need)
	} else {
		raw = raw[:need]
	}
	n, err := proto.Encode(raw, fr)
	if err != nil {
		*bp = raw
		e.bufPool.Put(bp)
		return err
	}
	var hdrCopy [proto.HeaderSize]byte
	copy(hdrCopy[:], raw[:proto.HeaderSize])
	plainLen := n - proto.HeaderSize
	nonce := crypto.Nonce12(pathID, seq)
	ct := ciph.Seal(nil, nonce, raw[proto.HeaderSize:n], hdrCopy[:])
	outNeed := proto.HeaderSize + len(ct)
	if cap(raw) < outNeed {
		raw = make([]byte, outNeed)
	} else {
		raw = raw[:outNeed]
	}
	copy(raw[:proto.HeaderSize], hdrCopy[:])
	copy(raw[proto.HeaderSize:], ct)
	out := raw

	put := func() {
		*bp = raw
		e.bufPool.Put(bp)
	}

	// Portal → specific agent (WSS or UDP)
	if e.Role == "portal" && agentID != "" {
		err = e.writeAgent(agentID, fr.StreamID, out)
		if err == nil {
			e.Stats.BytesOut.Add(uint64(plainLen))
		}
		put()
		return err
	}

	// Prefer real UDP peer when available (profile=udp/both); else WSS pool.
	useUDP := addr != nil && e.Pool != nil && e.useUDPChunk(agentID)
	if useUDP {
		path := e.Pool.ByID(pathID)
		if path == nil {
			path = e.Pool.Next()
		}
		if path != nil {
			_, err = path.Conn.WriteToUDP(out, addr)
			if err == nil {
				e.Stats.PacketsOut.Add(1)
				e.Stats.BytesOut.Add(uint64(plainLen))
				put()
				return nil
			}
		}
	}
	if e.hasWS() {
		err = e.writeWS(fr.StreamID, out)
		if err == nil {
			e.Stats.BytesOut.Add(uint64(plainLen))
		}
		put()
		return err
	}
	put()
	return errNoPeer
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
	network := "tcp"
	if len(target) >= 4 && target[:4] == "udp:" {
		network = "udp"
		target = target[4:]
	}
	// Register immediately so early DATA is buffered before dial completes.
	st := &stream{id: fr.StreamID, pathID: 0, ready: make(chan struct{}), udpMode: network == "udp"}
	e.mu.Lock()
	if len(e.streams) >= e.MaxStr {
		e.mu.Unlock()
		_ = e.send(proto.Frame{Type: proto.TypeCLOSE, StreamID: fr.StreamID}, 0)
		return
	}
	e.streams[fr.StreamID] = st
	e.mu.Unlock()
	e.Stats.Streams.Add(1)

	conn, err := net.DialTimeout(network, target, 8*time.Second)
	if err != nil {
		log.Printf("dial %s %s: %v", network, target, err)
		e.closeStream(fr.StreamID, true)
		return
	}
	if network == "tcp" {
		tuneTCP(conn)
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
	if network == "udp" {
		go e.pipeUDP(st)
	} else {
		go e.pipeConn(st)
	}
}

func (e *Engine) onData(fr proto.Frame) {
	e.mu.RLock()
	st := e.streams[fr.StreamID]
	e.mu.RUnlock()
	if st == nil || st.closed.Load() {
		return
	}
	// Portal UDP ASSOCIATE: wrap payload as SOCKS5 UDP reply to the client.
	if st.udpMode && st.conn == nil && st.udpPC != nil {
		st.udpMu.Lock()
		pc, from, hdr := st.udpPC, st.udpClient, append([]byte(nil), st.udpHdr...)
		st.udpMu.Unlock()
		if pc == nil || from == nil || len(hdr) == 0 {
			return
		}
		pkt := make([]byte, 3+len(hdr)+len(fr.Payload))
		// RSV=0, FRAG=0
		copy(pkt[3:], hdr)
		copy(pkt[3+len(hdr):], fr.Payload)
		_, _ = pc.WriteTo(pkt, from)
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
	buf := make([]byte, dataChunkWSS)
	for {
		n, err := st.conn.Read(buf)
		if n > 0 {
			_ = e.sendDATA(st, buf[:n])
		}
		if err != nil {
			e.closeStream(st.id, true)
			return
		}
	}
}

// pipeUDP reads datagrams from a connected UDP socket and forwards each as one DATA frame.
func (e *Engine) pipeUDP(st *stream) {
	buf := make([]byte, 2048)
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
	tuneTCP(conn)
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
