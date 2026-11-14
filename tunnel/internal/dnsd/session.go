package dnsd

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

var errSessionTableFull = errors.New("session table full")

type session struct {
	id               uint8
	cookie           uint8
	verify           [4]byte
	signature        [sessionInitDataSize]byte
	responseBase64   bool
	uploadMTU        int
	downloadMTU      int
	lastSeen         time.Time
	mu               sync.Mutex
	streams          map[uint16]*stream
	txQueue          []Packet
	pending          map[uint64]*pendingDown
	closed           bool
}

type stream struct {
	id         uint16
	conn       net.Conn
	sendSeq    uint16
	recvExpect uint16
	closed     bool
	mu         sync.Mutex
	// VPN-level fragment reassembly for one in-flight sequence.
	fragSeq   uint16
	fragTotal uint8
	fragParts map[uint8][]byte
	// TCP write reordering (DNS answers arrive out of order).
	reorder map[uint16][]byte
}

type sessionStore struct {
	mu       sync.Mutex
	byID     [256]*session
	bySig    map[[sessionInitDataSize]byte]uint8
	maxSlots int
	timeout  time.Duration
}

func newSessionStore(maxSlots int, timeout time.Duration) *sessionStore {
	if maxSlots <= 0 || maxSlots > 255 {
		maxSlots = 255
	}
	return &sessionStore{
		bySig:    make(map[[sessionInitDataSize]byte]uint8),
		maxSlots: maxSlots,
		timeout:  timeout,
	}
}

func (s *sessionStore) findOrCreate(payload []byte, base64 bool) (*session, bool, error) {
	if len(payload) != sessionInitDataSize {
		return nil, false, errors.New("bad init payload")
	}
	var sig [sessionInitDataSize]byte
	copy(sig[:], payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked(time.Now())

	if id, ok := s.bySig[sig]; ok {
		if sess := s.byID[id]; sess != nil && !sess.closed {
			sess.lastSeen = time.Now()
			return sess, true, nil
		}
	}

	var id uint8
	found := false
	for i := 1; i <= s.maxSlots; i++ {
		cand := uint8(i)
		if s.byID[cand] == nil {
			id = cand
			found = true
			break
		}
	}
	if !found {
		return nil, false, errSessionTableFull
	}

	cookie := randomByte()
	var verify [4]byte
	copy(verify[:], payload[6:10])

	sess := &session{
		id:             id,
		cookie:         cookie,
		verify:         verify,
		signature:      sig,
		responseBase64: base64,
		uploadMTU:      150,
		downloadMTU:    500,
		lastSeen:       time.Now(),
		streams:        make(map[uint16]*stream),
	}
	s.byID[id] = sess
	s.bySig[sig] = id
	return sess, false, nil
}

func (s *sessionStore) get(id uint8, cookie uint8) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byID[id]
	if sess == nil || sess.closed || sess.cookie != cookie {
		return nil, false
	}
	sess.lastSeen = time.Now()
	return sess, true
}

func (s *sessionStore) close(id uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byID[id]
	if sess == nil {
		return
	}
	sess.closeAll()
	delete(s.bySig, sess.signature)
	s.byID[id] = nil
}

func (s *sessionStore) reapLocked(now time.Time) {
	for i := 1; i <= 255; i++ {
		sess := s.byID[uint8(i)]
		if sess == nil {
			continue
		}
		if now.Sub(sess.lastSeen) > s.timeout {
			sess.closeAll()
			delete(s.bySig, sess.signature)
			s.byID[uint8(i)] = nil
		}
	}
}

func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i := 1; i <= 255; i++ {
		if s.byID[uint8(i)] != nil {
			n++
		}
	}
	return n
}

func (sess *session) closeAll() {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.closed = true
	for _, st := range sess.streams {
		st.close()
	}
	sess.streams = map[uint16]*stream{}
	sess.txQueue = nil
	sess.pending = nil
}

func (sess *session) enqueue(p Packet) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.txQueue) >= maxTxQueue {
		// Prefer dropping oldest STREAM_DATA, keep control/SOCKS signals.
		dropped := false
		for i, q := range sess.txQueue {
			if q.PacketType == pktStreamData || q.PacketType == pktStreamResend {
				sess.txQueue = append(sess.txQueue[:i], sess.txQueue[i+1:]...)
				dropped = true
				break
			}
		}
		if !dropped {
			sess.txQueue = sess.txQueue[1:]
		}
	}
	sess.txQueue = append(sess.txQueue, p)
}

func (sess *session) dequeue() (Packet, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.txQueue) == 0 {
		return Packet{}, false
	}
	p := sess.txQueue[0]
	sess.txQueue = sess.txQueue[1:]
	return p, true
}

func (sess *session) getStream(id uint16) (*stream, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	st, ok := sess.streams[id]
	return st, ok
}

func (sess *session) putStream(st *stream) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.streams[st.id] = st
}

func (sess *session) removeStream(id uint16) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if st, ok := sess.streams[id]; ok {
		st.close()
		delete(sess.streams, id)
	}
}

func (st *stream) close() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.closed = true
	if st.conn != nil {
		_ = st.conn.Close()
		st.conn = nil
	}
}

func (st *stream) nextSendSeq() uint16 {
	st.mu.Lock()
	defer st.mu.Unlock()
	seq := st.sendSeq
	st.sendSeq++
	return seq
}

// takeAssembledPayload merges VPN-level fragments for one sequence.
// Returns (payload, ready). ready=false means more fragments are needed.
func (st *stream) takeAssembledPayload(seq uint16, fragID, total uint8, part []byte) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if total <= 1 {
		st.fragParts = nil
		return part, true
	}
	if st.fragParts == nil || st.fragSeq != seq || st.fragTotal != total {
		st.fragSeq = seq
		st.fragTotal = total
		st.fragParts = make(map[uint8][]byte, total)
	}
	st.fragParts[fragID] = append([]byte(nil), part...)
	if len(st.fragParts) < int(total) {
		return nil, false
	}
	out := make([]byte, 0, len(part)*int(total))
	for i := uint8(0); i < total; i++ {
		p, ok := st.fragParts[i]
		if !ok {
			return nil, false
		}
		out = append(out, p...)
	}
	st.fragParts = nil
	return out, true
}

func randomByte() uint8 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	if b[0] == 0 {
		b[0] = 1
	}
	return b[0]
}

func parseSocksTarget(payload []byte) (host string, port uint16, err error) {
	if len(payload) < 3 {
		return "", 0, errors.New("target too short")
	}
	offset := 1
	switch payload[0] {
	case 0x01: // IPv4
		if len(payload) < offset+4+2 {
			return "", 0, errors.New("target too short")
		}
		host = net.IP(payload[offset : offset+4]).String()
		offset += 4
	case 0x03: // domain
		if len(payload) < offset+1 {
			return "", 0, errors.New("target too short")
		}
		n := int(payload[offset])
		offset++
		if n < 1 || len(payload) < offset+n+2 {
			return "", 0, errors.New("bad domain")
		}
		host = string(payload[offset : offset+n])
		offset += n
	case 0x04: // IPv6
		if len(payload) < offset+16+2 {
			return "", 0, errors.New("target too short")
		}
		host = net.IP(payload[offset : offset+16]).String()
		offset += 16
	default:
		return "", 0, errors.New("unsupported atyp")
	}
	port = binary.BigEndian.Uint16(payload[offset : offset+2])
	return host, port, nil
}
