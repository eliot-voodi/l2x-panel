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
