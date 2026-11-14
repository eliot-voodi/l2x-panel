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
