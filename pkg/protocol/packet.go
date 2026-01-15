package protocol

import (
	"encoding/binary"
	"errors"
	"w33d-tunnel/pkg/crypto"
)

const (
	FlagUnreliable = 1 << 5 // New flag for unreliable datagrams (e.g. UDP Associate)
)

// Header represents the plaintext header of a data packet.
type Header struct {
	Flags      uint8
	Reserved   uint8
	PayloadLen uint16
	SeqNumber  uint32 // ARQ Sequence Number
	AckNumber  uint32 // Present if FlagAck is set
}

// DataPacket represents a decrypted data packet.
type DataPacket struct {
	Header  Header
	Payload []byte
}

// MarshalHeader serializes the header.
func (h *Header) Marshal() []byte {
	size := 8 // 1+1+2+4
	if h.Flags&FlagAck != 0 {
		size += 4
	}
	buf := make([]byte, size)
	buf[0] = h.Flags
	buf[1] = h.Reserved
	binary.BigEndian.PutUint16(buf[2:4], h.PayloadLen)
	binary.BigEndian.PutUint32(buf[4:8], h.SeqNumber)
	if h.Flags&FlagAck != 0 {
		binary.BigEndian.PutUint32(buf[8:12], h.AckNumber)
	}
	return buf
}

// UnmarshalHeader deserializes the header.
func UnmarshalHeader(data []byte) (Header, int, error) {
	if len(data) < 8 {
		return Header{}, 0, errors.New("header too short")
	}
	h := Header{
		Flags:      data[0],
		Reserved:   data[1],
		PayloadLen: binary.BigEndian.Uint16(data[2:4]),
		SeqNumber:  binary.BigEndian.Uint32(data[4:8]),
	}
	size := 8
	if h.Flags&FlagAck != 0 {
		if len(data) < 12 {
			return Header{}, 0, errors.New("header too short for ACK")
		}
		h.AckNumber = binary.BigEndian.Uint32(data[8:12])
		size += 4
	}
	return h, size, nil
}

// BuildDataPacket constructs an encrypted data packet.
// It takes the key, nonce, header info, and payload.
// It pads the packet to a random length if requested (not implemented here, just simple padding).
func BuildDataPacket(key, nonce []byte, header Header, payload []byte) ([]byte, error) {
	// 1. Marshal Header
	headerBytes := header.Marshal()

	// 2. Concatenate Header + Payload
	// Note: Padding should be added here if we want to hide length.
	// For now, let's implement simple padding to 4-byte alignment or random.
	// RFC says: "Padding: Variable bytes... implicitly indicated... Payload Length field is useful"
	// So we can append random bytes.

	plaintext := make([]byte, len(headerBytes)+len(payload))
	copy(plaintext, headerBytes)
	copy(plaintext[len(headerBytes):], payload)

	// Add padding (optional). Let's pad to multiple of 16 for now or random.
	// For this implementation, I'll skip complex padding logic for simplicity unless required.
	// The RFC says "Pad... to random length".
	// Let's add 0-15 bytes of random padding.
	padLen := crypto.RandomBytes(1)[0] % 16
	padding := crypto.RandomBytes(int(padLen))
	plaintext = append(plaintext, padding...)

	// 3. Encrypt
	// Additional Data: The RFC doesn't explicitly mention AAD for data packets,
	// usually the header is encrypted. "All header fields... are encrypted".
	// So AAD can be nil or maybe the implicit sequence number if we want to bind it.
	// But the sequence is in the Nonce.
	// We'll use nil AAD.
	ciphertext, err := crypto.Encrypt(key, nonce, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// BuildDataPacketWithSeq constructs an encrypted data packet with explicit sequence prefix.
// It also obfuscates the sequence number if headerKey is provided.
func BuildDataPacketWithSeq(key, nonce []byte, header Header, payload []byte, seq uint64, headerKey []byte) ([]byte, error) {
	ciphertext, err := BuildDataPacket(key, nonce, header, payload)
	if err != nil {
		return nil, err
	}

	// Prepend Seq (8 bytes)
	buf := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(buf[0:8], seq)
	copy(buf[8:], ciphertext)

	// Obfuscate Header (Seq)
	if len(headerKey) > 0 {
		mask := make([]byte, 8)
		if len(ciphertext) >= 16 {
			mask = crypto.GenerateHeaderMask(headerKey, ciphertext[:16])
		} else {
			mask = crypto.GenerateHeaderMask(headerKey, make([]byte, 16))
		}

		for i := 0; i < 8; i++ {
			buf[i] ^= mask[i]
		}
	}

	return buf, nil
}

// ParseDataPacket decrypts and parses a data packet.
func ParseDataPacket(key, nonce, ciphertext []byte) (*DataPacket, error) {
	plaintext, err := crypto.Decrypt(key, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	header, headerSize, err := UnmarshalHeader(plaintext)
	if err != nil {
		return nil, err
	}

	if len(plaintext) < headerSize+int(header.PayloadLen) {
		return nil, errors.New("packet too short for payload")
	}

	payload := plaintext[headerSize : headerSize+int(header.PayloadLen)]
	// Remaining bytes are padding, ignored.

	return &DataPacket{
		Header:  header,
		Payload: payload,
	}, nil
}
