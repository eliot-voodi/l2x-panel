package dnsd

import "testing"

func TestClampDownlinkChunk(t *testing.T) {
	if got := clampDownlinkChunk(0); got != minDownlinkChunk {
		t.Fatalf("got %d", got)
	}
	if got := clampDownlinkChunk(1200); got != maxDownlinkChunk {
		t.Fatalf("got %d", got)
	}
	if got := clampDownlinkChunk(300); got != 300 {
		t.Fatalf("got %d", got)
	}
}

func TestFragmentAssemble(t *testing.T) {
	st := &stream{}
	if _, ready := st.takeAssembledPayload(1, 0, 1, []byte("abc")); !ready {
		t.Fatal("single fragment should be ready")
	}
	if _, ready := st.takeAssembledPayload(2, 0, 2, []byte("aa")); ready {
		t.Fatal("partial should wait")
	}
	out, ready := st.takeAssembledPayload(2, 1, 2, []byte("bb"))
	if !ready || string(out) != "aabb" {
		t.Fatalf("got ready=%v out=%q", ready, out)
	}
}

func TestAcceptOrderedReorders(t *testing.T) {
	st := &stream{recvExpect: 1}
	if got := st.acceptOrdered(2, []byte("b")); len(got) != 0 {
		t.Fatalf("future-only should buffer, got %d", len(got))
	}
	got := st.acceptOrdered(1, []byte("a"))
	if len(got) != 2 || string(got[0]) != "a" || string(got[1]) != "b" {
		t.Fatalf("got %#v", got)
	}
	if st.recvExpect != 3 {
		t.Fatalf("expect %d", st.recvExpect)
	}
	if got := st.acceptOrdered(1, []byte("a")); len(got) != 0 {
		t.Fatalf("dup should drop")
	}
}

// Official MasterDnsVPN: SOCKS5_SYN uses control seq 0, but STREAM_DATA also
// starts at sndNxt=0. recvExpect must be 0 after SYN or the first ClientHello
// chunk is treated as already delivered and TLS breaks.
func TestAcceptOrderedOfficialSocksDataStartsAtZero(t *testing.T) {
	st := &stream{recvExpect: 0}
	got := st.acceptOrdered(0, []byte("CH"))
	if len(got) != 1 || string(got[0]) != "CH" {
		t.Fatalf("first data seq=0 must be written, got %#v", got)
	}
	if st.recvExpect != 1 {
		t.Fatalf("expect 1 after seq 0, got %d", st.recvExpect)
	}
	// Old bug: recvExpect := synSeq+1 with synSeq==0 dropped ClientHello.
	broken := &stream{recvExpect: 1}
	if got := broken.acceptOrdered(0, []byte("CH")); len(got) != 0 {
		t.Fatalf("syn+1 expect wrongly accepts seq 0: %#v", got)
	}
}

func TestSeqAhead(t *testing.T) {
	if !seqAhead(5, 3) {
		t.Fatal("3 already delivered when expect 5")
	}
	if seqAhead(5, 5) {
		t.Fatal("current is not ahead")
	}
	if seqAhead(5, 6) {
		t.Fatal("future is not ahead")
	}
}
