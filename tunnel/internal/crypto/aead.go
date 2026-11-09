package crypto

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Cipher interface {
	Seal(dst, nonce, plaintext, aad []byte) []byte
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
	Overhead() int
	NonceSize() int
}

type nullCipher struct{}

func (nullCipher) Seal(dst, nonce, plaintext, aad []byte) []byte {
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return append(dst, out...)
}
func (nullCipher) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return append(dst, out...), nil
}
func (nullCipher) Overhead() int  { return 0 }
func (nullCipher) NonceSize() int { return 12 }

type aeadCipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, aad []byte) []byte
		Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
		Overhead() int
		NonceSize() int
	}
}

func (c aeadCipher) Seal(dst, nonce, plaintext, aad []byte) []byte {
	return c.aead.Seal(dst, nonce, plaintext, aad)
}
func (c aeadCipher) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	return c.aead.Open(dst, nonce, ciphertext, aad)
}
func (c aeadCipher) Overhead() int  { return c.aead.Overhead() }
func (c aeadCipher) NonceSize() int { return c.aead.NonceSize() }

func DeriveKey(psk string) []byte {
	r := hkdf.New(sha256.New, []byte(psk), []byte("l2x-tunnel-v1"), []byte("data"))
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = r.Read(key)
	return key
}

func New(cipherName, psk string) (Cipher, error) {
	switch cipherName {
	case "", "chacha20poly1305", "chacha":
		aead, err := chacha20poly1305.New(DeriveKey(psk))
		if err != nil {
			return nil, err
		}
		return aeadCipher{aead: aead}, nil
	case "null", "none", "off":
		return nullCipher{}, nil
	default:
		return nil, errors.New("unknown cipher: " + cipherName)
	}
}

// Nonce12 builds a 12-byte nonce from pathID + seq.
func Nonce12(pathID uint8, seq uint32) []byte {
	n := make([]byte, 12)
	n[0] = pathID
	n[1] = 0
	n[2] = 0
	n[3] = 0
	n[4] = byte(seq >> 24)
	n[5] = byte(seq >> 16)
	n[6] = byte(seq >> 8)
	n[7] = byte(seq)
	return n
}
