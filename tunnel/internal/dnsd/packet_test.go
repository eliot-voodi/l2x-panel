package dnsd

import (
	"bytes"
	"testing"
)

func TestBase36RoundTrip(t *testing.T) {
	samples := [][]byte{
		{},
		{1},
		{1, 2, 3},
		bytes.Repeat([]byte{0xab}, 20),
		bytes.Repeat([]byte{0xff}, 70),
	}
	for _, s := range samples {
		enc := encodeBase36(s)
		dec, err := decodeBase36(enc)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(s, dec) {
			t.Fatalf("mismatch len=%d", len(s))
		}
	}
}

func TestPacketRoundTrip(t *testing.T) {
	raw, err := BuildRaw(BuildOptions{
		SessionID:      7,
		PacketType:     pktSocks5Connected,
		SessionCookie:  9,
		StreamID:       42,
		SequenceNum:    3,
		Payload:        []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.SessionID != 7 || p.SessionCookie != 9 || p.StreamID != 42 || p.SequenceNum != 3 {
		t.Fatalf("bad parse: %+v", p)
	}
	if !bytes.Equal(p.Payload, []byte{1, 2, 3}) {
		t.Fatalf("payload mismatch")
	}
}

func TestCodecChaChaRoundTrip(t *testing.T) {
	c, err := NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello-dns-tunnel")
	enc, err := c.EncryptAndEncode(plain)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := c.DecodeAndDecrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	// EncryptAndEncode encrypts the VPN frame; here we round-trip raw bytes through codec only.
	if !bytes.Equal(plain, dec) {
		t.Fatalf("codec mismatch %q vs %q", plain, dec)
	}
}

func TestHeaderCheck(t *testing.T) {
	raw, err := BuildRaw(BuildOptions{PacketType: pktSessionInit, Payload: make([]byte, 10)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePacket(raw); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff // corrupt — may be payload
	// Corrupt check byte (last header byte before payload)
	p, err := ParsePacket(raw[:4]) // too short for init with payload but header ok
	_ = p
	_ = err
}
