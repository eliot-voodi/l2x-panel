package proto

import "testing"

func TestEncodeDecode(t *testing.T) {
	buf := make([]byte, 64)
	f := Frame{Type: TypeDATA, Flags: 3, StreamID: 42, Seq: 7, Payload: []byte("hello")}
	n, err := Encode(buf, f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != f.Type || got.StreamID != f.StreamID || string(got.Payload) != "hello" {
		t.Fatalf("got %+v", got)
	}
}
