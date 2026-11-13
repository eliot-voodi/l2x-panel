package dnsd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

var (
	errInvalidCodecMethod = errors.New("invalid encryption method")
	errInvalidCiphertext  = errors.New("invalid ciphertext")
)

const (
	chachaNonceSize = 16
	aesNonceSize    = 12
)

// Codec encrypts/decrypts VPN frames and maps them to/from DNS-safe base36.
type Codec struct {
	method int
	key    []byte
}

func NewCodec(method int, rawKey string) (*Codec, error) {
	if method < 0 || method > 5 {
		return nil, errInvalidCodecMethod
	}
	return &Codec{method: method, key: deriveKey(method, rawKey)}, nil
}

func (c *Codec) EncryptAndEncode(data []byte) ([]byte, error) {
	if c.method == 0 {
		return encodeBase36(data), nil
	}
	enc, err := c.encrypt(data)
	if err != nil {
		return nil, err
	}
	return encodeBase36(enc), nil
}

func (c *Codec) DecodeAndDecrypt(data []byte) ([]byte, error) {
	decoded, err := decodeBase36(data)
	if err != nil {
		return nil, err
	}
	if c.method == 0 {
		return decoded, nil
	}
	return c.decrypt(decoded)
}

func (c *Codec) DecodeStringAndDecrypt(s string) ([]byte, error) {
	decoded, err := decodeBase36String(s)
	if err != nil {
		return nil, err
	}
	if c.method == 0 {
		return decoded, nil
	}
	return c.decrypt(decoded)
}

func (c *Codec) encrypt(data []byte) ([]byte, error) {
	switch c.method {
	case 1:
		return xorCrypto(nil, data, c.key), nil
	case 2:
		return chachaEncrypt(data, c.key)
	case 3, 4, 5:
		aead, err := newAESGCM(c.key)
		if err != nil {
			return nil, err
		}
		return aesEncrypt(aead, data)
	default:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
}

func (c *Codec) decrypt(data []byte) ([]byte, error) {
	switch c.method {
	case 1:
		return xorCrypto(nil, data, c.key), nil
	case 2:
		return chachaDecrypt(data, c.key)
	case 3, 4, 5:
		aead, err := newAESGCM(c.key)
		if err != nil {
			return nil, err
		}
		return aesDecrypt(aead, data)
	default:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
}

func xorCrypto(dst, data, key []byte) []byte {
	if len(data) == 0 || len(key) == 0 {
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	if cap(dst) < len(data) {
		dst = make([]byte, len(data))
	} else {
		dst = dst[:len(data)]
	}
	keyLen := len(key)
	for i := 0; i < len(data); i++ {
		dst[i] = data[i] ^ key[i%keyLen]
	}
	return dst
}

func chachaEncrypt(data, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, chachaNonceSize+len(data))
	nonce := out[:chachaNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce[4:])
	if err != nil {
		return nil, err
	}
	stream.SetCounter(binary.LittleEndian.Uint32(nonce[:4]))
	stream.XORKeyStream(out[chachaNonceSize:], data)
	return out, nil
}

func chachaDecrypt(data, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) <= chachaNonceSize {
		return nil, errInvalidCiphertext
	}
	nonce := data[:chachaNonceSize]
	ct := data[chachaNonceSize:]
	out := make([]byte, len(ct))
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce[4:])
	if err != nil {
		return nil, err
	}
	stream.SetCounter(binary.LittleEndian.Uint32(nonce[:4]))
	stream.XORKeyStream(out, ct)
	return out, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	return cipher.NewGCM(block)
}

func aesEncrypt(aead cipher.AEAD, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return []byte{}, nil
	}
	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, src, nil), nil
}

func aesDecrypt(aead cipher.AEAD, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	if len(src) <= aesNonceSize {
		return nil, errInvalidCiphertext
	}
	nonce, ct := src[:aesNonceSize], src[aesNonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errInvalidCiphertext
	}
	return pt, nil
}

func deriveKey(method int, rawKey string) []byte {
	bKey := []byte(rawKey)
	switch method {
	case 2, 5:
		sum := sha256.Sum256(bKey)
		return sum[:]
	case 3:
		sum := md5.Sum(bKey)
		return sum[:]
	default:
		n := requiredKeyLen(method)
		key := make([]byte, n)
		copy(key, bKey)
		return key
	}
}

func requiredKeyLen(method int) int {
	switch method {
	case 2, 5:
		return 32
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}
