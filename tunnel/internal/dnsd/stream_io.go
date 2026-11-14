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
)

func clampDownlinkChunk(mtu int) int {
	if mtu < minDownlinkChunk {
		return minDownlinkChunk
	}
	if mtu > maxDownlinkChunk {
		return maxDownlinkChunk
	}
	return mtu
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
			// Backpressure: don't read faster than the client can poll TXT answers.
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
				// Idle upstream — keep polling the socket.
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
