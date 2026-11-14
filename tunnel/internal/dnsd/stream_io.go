package dnsd

import (
	"io"
	"net"
	"time"
)

const (
	minDownlinkChunk = 64
	maxDownlinkChunk = 500
	maxTxQueue       = 1024
	readerIdleWait   = 20 * time.Millisecond
	retransmitAfter  = 400 * time.Millisecond
	maxRetransmits   = 8
	maxReorderBuf    = 64
)

type pendingDown struct {
	pkt      Packet
	lastSent time.Time
	sends    int
}

func clampDownlinkChunk(mtu int) int {
	if mtu < minDownlinkChunk {
		return minDownlinkChunk
	}
	if mtu > maxDownlinkChunk {
		return maxDownlinkChunk
	}
	return mtu
}

func pendKey(streamID, seq uint16) uint64 {
	return uint64(streamID)<<16 | uint64(seq)
}

func (sess *session) startReader(st *stream) {
	go func() {
		chunk := clampDownlinkChunk(sess.downloadMTU)
		buf := make([]byte, chunk)
		for {
			st.mu.Lock()
			conn := st.conn
			closed := st.closed
			st.mu.Unlock()
			if closed || conn == nil {
				return
			}
			for sess.queueLen() > maxTxQueue/2 {
				st.mu.Lock()
				closed = st.closed
				st.mu.Unlock()
				if closed {
					return
				}
				time.Sleep(readerIdleWait)
			}
			_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				sess.enqueueStreamData(st, buf[:n])
			}
			if err == nil {
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if err != io.EOF && err != net.ErrClosed {
				sess.enqueue(Packet{
					SessionID:      sess.id,
					PacketType:     pktStreamRST,
					SessionCookie:  sess.cookie,
					HasStreamID:    true,
					StreamID:       st.id,
					HasSequenceNum: true,
					SequenceNum:    st.nextSendSeq(),
				})
			} else {
				sess.enqueue(Packet{
					SessionID:      sess.id,
					PacketType:     pktStreamCloseWrite,
					SessionCookie:  sess.cookie,
					HasStreamID:    true,
					StreamID:       st.id,
					HasSequenceNum: true,
					SequenceNum:    st.nextSendSeq(),
				})
			}
			sess.removeStream(st.id)
			return
		}
	}()
}

func (sess *session) enqueueStreamData(st *stream, payload []byte) {
	if len(payload) == 0 {
		return
	}
	seq := st.nextSendSeq()
	sess.enqueue(Packet{
		SessionID:       sess.id,
		PacketType:      pktStreamData,
		SessionCookie:   sess.cookie,
		HasStreamID:     true,
		StreamID:        st.id,
		HasSequenceNum:  true,
		SequenceNum:     seq,
		HasFragmentInfo: true,
		FragmentID:      0,
		TotalFragments:  1,
		HasCompression:  true,
		CompressionType: 0,
		Payload:         append([]byte(nil), payload...),
	})
}

func (sess *session) queueLen() int {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return len(sess.txQueue)
}

// dequeueForReply returns the next packet for a DNS TXT answer.
// Prefer fresh queue items; otherwise retransmit unacked downlink.
func (sess *session) dequeueForReply() (Packet, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	now := time.Now()
	if len(sess.txQueue) > 0 {
		p := sess.txQueue[0]
		sess.txQueue = sess.txQueue[1:]
		sess.noteSentLocked(p, now)
		return p, true
	}
	var bestKey uint64
	var best *pendingDown
	for k, it := range sess.pending {
		if it.sends >= maxRetransmits {
			continue
		}
		if now.Sub(it.lastSent) < retransmitAfter {
			continue
		}
		if best == nil || it.lastSent.Before(best.lastSent) {
			best = it
			bestKey = k
		}
	}
	if best == nil {
		return Packet{}, false
	}
	best.lastSent = now
	best.sends++
	_ = bestKey
	cp := best.pkt
	cp.Payload = append([]byte(nil), best.pkt.Payload...)
	return cp, true
}

func (sess *session) noteSentLocked(p Packet, now time.Time) {
	if p.PacketType != pktStreamData && p.PacketType != pktStreamResend {
		return
	}
	if sess.pending == nil {
		sess.pending = make(map[uint64]*pendingDown)
	}
	key := pendKey(p.StreamID, p.SequenceNum)
	if old, ok := sess.pending[key]; ok {
		old.lastSent = now
		old.sends++
		old.pkt = p
		return
	}
	sess.pending[key] = &pendingDown{pkt: p, lastSent: now, sends: 1}
}

func (sess *session) ackDownlink(streamID, seq uint16) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.pending == nil {
		return
	}
	delete(sess.pending, pendKey(streamID, seq))
}

func (sess *session) nackDownlink(streamID, seq uint16) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.pending == nil {
		return
	}
	key := pendKey(streamID, seq)
	it, ok := sess.pending[key]
	if !ok {
		return
	}
	cp := it.pkt
	cp.PacketType = pktStreamResend
	cp.Payload = append([]byte(nil), it.pkt.Payload...)
	sess.txQueue = append([]Packet{cp}, sess.txQueue...)
	it.lastSent = time.Time{} // eligible immediately on next empty poll
}

// acceptOrdered buffers out-of-order upload payloads and returns the contiguous
// prefix that can be written to the TCP conn (DNS answers are often reordered).
func (st *stream) acceptOrdered(seq uint16, payload []byte) [][]byte {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reorder == nil {
		st.reorder = make(map[uint16][]byte)
	}
	// Already delivered (duplicate / late resend).
	if seqAhead(st.recvExpect, seq) {
		return nil
	}
	st.reorder[seq] = append([]byte(nil), payload...)
	if len(st.reorder) > maxReorderBuf {
		for s := range st.reorder {
			if s == st.recvExpect || seqAhead(st.recvExpect, s) {
				continue
			}
			if uint16(s-st.recvExpect) > uint16(maxReorderBuf/2) {
				delete(st.reorder, s)
			}
		}
	}
	var out [][]byte
	for {
		p, ok := st.reorder[st.recvExpect]
		if !ok {
			break
		}
		out = append(out, p)
		delete(st.reorder, st.recvExpect)
		st.recvExpect++
	}
	return out
}

// seqAhead reports whether got was already consumed (got < expect with wrap).
func seqAhead(expect, got uint16) bool {
	return uint16(expect-got) < 0x8000 && got != expect
}
