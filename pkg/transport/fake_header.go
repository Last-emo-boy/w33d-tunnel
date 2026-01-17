package transport

import (
	"encoding/binary"
	"math/rand"
	"time"
)

// FakeHeaderType defines the type of fake header to prepend.
type FakeHeaderType int

const (
	FakeHeaderNone FakeHeaderType = iota
	FakeHeaderRTP
	FakeHeaderDTLS
	FakeHeaderDNS
)

// RTP Header Constants
const (
	rtpHeaderSize = 12
	rtpVersion    = 2
)

// AddFakeHeader prepends a fake header to the packet.
func AddFakeHeader(payload []byte, headerType FakeHeaderType) []byte {
	switch headerType {
	case FakeHeaderRTP:
		return addRTPHeader(payload)
	default:
		return payload
	}
}

// RemoveFakeHeader strips the fake header from the packet.
func RemoveFakeHeader(packet []byte, headerType FakeHeaderType) []byte {
	switch headerType {
	case FakeHeaderRTP:
		if len(packet) < rtpHeaderSize {
			return packet // Too short, maybe not ours?
		}
		// Basic validation could go here
		return packet[rtpHeaderSize:]
	default:
		return packet
	}
}

func addRTPHeader(payload []byte) []byte {
	buf := make([]byte, rtpHeaderSize+len(payload))
	
	// RTP Header Format:
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V=2|P|X|  CC   |M|     PT      |       Sequence Number         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                           Timestamp                           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Synchronization Source (SSRC) identifier            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Byte 0: V=2 (10), P=0, X=0, CC=0 -> 10000000 -> 0x80
	buf[0] = 0x80
	
	// Byte 1: M=0, PT=96 (Dynamic) -> 01100000 -> 0x60
	// We can randomize PT slightly to look like different codecs (96-127)
	buf[1] = 0x60 | (byte(rand.Intn(32)) & 0x7F) // Mask M bit just in case

	// Sequence Number (Random or incrementing? Random is safer for stateless)
	binary.BigEndian.PutUint16(buf[2:4], uint16(rand.Intn(65535)))
	
	// Timestamp (Current timeish)
	binary.BigEndian.PutUint32(buf[4:8], uint32(time.Now().UnixNano()/1000))
	
	// SSRC (Random ID)
	binary.BigEndian.PutUint32(buf[8:12], rand.Uint32())
	
	copy(buf[12:], payload)
	return buf
}
