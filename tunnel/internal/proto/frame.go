package proto

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize = 12
	MaxPayload = 1400
)

const (
	TypeDATA    uint8 = 1
	TypeOPEN    uint8 = 2
	TypeCLOSE   uint8 = 3
	TypeKA      uint8 = 4
	TypePUNCH   uint8 = 5
	TypeHELLO   uint8 = 6
	TypeHELLOOK uint8 = 7
)

const Version uint8 = 1

var (
	ErrShort   = errors.New("frame too short")
	ErrVersion = errors.New("bad version")
)

// Frame layout (12 bytes):
//
//	[0]   ver<<4 | type
//	[1]   flags
//	[2:6] streamID uint32 BE
//	[6:10] seq uint32 BE
//	[10:12] length uint16 BE
//	[12:] payload
type Frame struct {
	Type     uint8
	Flags    uint8
	StreamID uint32
	Seq      uint32
	Payload  []byte
}

func Encode(dst []byte, f Frame) (int, error) {
	n := HeaderSize + len(f.Payload)
	if len(dst) < n {
		return 0, errors.New("buffer too small")
	}
	dst[0] = (Version << 4) | (f.Type & 0x0f)
	dst[1] = f.Flags
	binary.BigEndian.PutUint32(dst[2:6], f.StreamID)
	binary.BigEndian.PutUint32(dst[6:10], f.Seq)
	binary.BigEndian.PutUint16(dst[10:12], uint16(len(f.Payload)))
	copy(dst[HeaderSize:], f.Payload)
	return n, nil
}

func Decode(src []byte) (Frame, error) {
	if len(src) < HeaderSize {
		return Frame{}, ErrShort
	}
	ver := src[0] >> 4
	if ver != Version {
		return Frame{}, ErrVersion
	}
	ln := int(binary.BigEndian.Uint16(src[10:12]))
	if len(src) < HeaderSize+ln {
		return Frame{}, ErrShort
	}
	payload := make([]byte, ln)
	copy(payload, src[HeaderSize:HeaderSize+ln])
	return Frame{
		Type:     src[0] & 0x0f,
		Flags:    src[1],
		StreamID: binary.BigEndian.Uint32(src[2:6]),
		Seq:      binary.BigEndian.Uint32(src[6:10]),
		Payload:  payload,
	}, nil
}
