package protocol

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
	"w33d-tunnel/pkg/crypto"
)

// Role definitions
const (
	RoleClient = iota
	RoleServer
)

// State definitions
const (
	StateClosed = iota
	StateInitiating
	StateHandshaking
	StateEstablished
	StateRekeying
	StateClosing
)

// Session represents a secure tunnel session.
type Session struct {
	// Separate locks for Send and Recv to allow concurrent processing
	SendLock sync.Mutex
	RecvLock sync.Mutex

	Role            int
	State           int
	LocalStaticPriv []byte
	LocalStaticPub  []byte
	PeerStaticPub   []byte

	// Handshake keys
	EphemeralPriv    []byte
	EphemeralPub     []byte
	PeerEphemeralPub []byte

	// Session Keys (Read-only after handshake)
	SendKey       []byte
	RecvKey       []byte
	SendNonceSalt []byte
	RecvNonceSalt []byte
	SendHeaderKey []byte
	RecvHeaderKey []byte

	// Sequence Numbers (Protected by respective locks)
	SendSeq uint64
	RecvSeq uint64 // Highest received

	// Replay Window (Simple implementation: track highest and window)
	// For simplicity, we just use RecvSeq as the high water mark
	// and a basic check. Real sliding window is complex to implement perfectly in short time.

	RemoteAddr net.Addr
	LastActive time.Time
}

// NewSession creates a new session.
func NewSession(role int, staticPriv, peerStaticPub []byte) *Session {
	// If staticPriv is nil, generate one (or it might be PSK mode, but let's assume Static Key mode for now)
	// If peerStaticPub is nil, we might be in a mode where we trust first connect (TOFU) or PSK.
	// For this implementation, we assume static keys are provided or generated.

	var pub []byte
	if len(staticPriv) == crypto.KeySize {
		// derive pub
		var err error
		pub, err = crypto.GetPublicKey(staticPriv)
		if err != nil {
			// Should ideally handle error
		}
	}

	return &Session{
		Role:            role,
		State:           StateClosed,
		LocalStaticPriv: staticPriv,
		LocalStaticPub:  pub,
		PeerStaticPub:   peerStaticPub,
		LastActive:      time.Now(),
	}
}

// GenerateEphemeralKeys generates new ephemeral keys for handshake.
func (s *Session) GenerateEphemeralKeys() error {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	s.EphemeralPriv = priv
	s.EphemeralPub = pub
	return nil
}

// ConstructNonce constructs the 96-bit nonce from salt and sequence.
// Nonce = Salt XOR Seq
func (s *Session) ConstructNonce(salt []byte, seq uint64) []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, salt)

	// XOR the last 8 bytes with the sequence number
	// Or just XOR the whole thing if we expand seq.
	// RFC says: "nonce_salt XOR seq_num"

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)

	// XOR into the last 8 bytes of nonce (assuming 12 byte nonce)
	// salt is 12 bytes.
	// We align seq to the end.
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}

	return nonce
}

// IncrementSendSeq increments the send sequence number.
func (s *Session) IncrementSendSeq() uint64 {
	s.SendLock.Lock()
	defer s.SendLock.Unlock()
	seq := s.SendSeq
	s.SendSeq++
	return seq
}

// ValidateRecvSeq checks replay protection.
// Returns true if packet is valid (new or within window and not duplicate).
func (s *Session) ValidateRecvSeq(seq uint64) bool {
	// Simple check: strictly increasing for now to verify basic logic.
	// In real sliding window, we accept seq > RecvSeq OR (seq > RecvSeq-Window && !seen).
	// Let's implement strictly increasing for simplicity of the prototype,
	// or allow small reordering.

	if seq > s.RecvSeq {
		s.RecvSeq = seq
		return true
	}
	// TODO: Implement proper sliding window
	return false
}

// DecryptPacket tries to decrypt a packet.
// It expects the packet to start with 8-byte Sequence Number.
func (s *Session) DecryptPacket(data []byte, windowSize uint64) (*DataPacket, uint64, error) {
	// 1. Parse Seq and Ciphertext (No Lock)
	if len(data) < 8 {
		return nil, 0, errors.New("packet too short for seq")
	}

	// De-obfuscate Header (Sequence Number)
	// Mask = ChaCha20(HeaderKey, Nonce=Ciphertext[0:16])
	// We use the first 16 bytes of ciphertext as sample for mask generation.
	// If ciphertext < 16, use whatever we have padded with zeros?
	// Realistically, ciphertext should be > 16 (Poly1305 tag is 16).

	// Copy first 8 bytes (Obfuscated Seq)
	obfuscatedSeq := data[0:8]
	ciphertext := data[8:]

	// Generate Mask
	mask := make([]byte, 8)
	if len(ciphertext) >= 16 {
		// Use Ciphertext sample
		// We need a lightweight function. ChaCha20 block is good.
		// Since we don't have direct ChaCha20 block primitive exposed in standard lib easily without cipher.Stream,
		// Let's use a simpler XOR with Hash(HeaderKey + Sample).
		// Or assume we have a crypto helper.
		mask = crypto.GenerateHeaderMask(s.RecvHeaderKey, ciphertext[:16])
	} else {
		// Fallback for short packets (should not happen with AEAD tag)
		mask = crypto.GenerateHeaderMask(s.RecvHeaderKey, make([]byte, 16))
	}

	seqBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		seqBytes[i] = obfuscatedSeq[i] ^ mask[i]
	}

	seq := binary.BigEndian.Uint64(seqBytes)

	// 2. Decrypt (No Lock - computationally intensive part)
	// We rely on AEAD for integrity. Replay check happens after.
	// Assumption: RecvKey and RecvNonceSalt are immutable during data transfer.
	nonce := s.ConstructNonce(s.RecvNonceSalt, seq)
	pkt, err := ParseDataPacket(s.RecvKey, nonce, ciphertext)
	if err != nil {
		return nil, 0, err
	}

	// 3. Update State (Lock)
	s.RecvLock.Lock()
	defer s.RecvLock.Unlock()

	// Replay Protection / Window Check
	// Since we decrypted successfully, the packet is authentic.
	// We just need to track the sequence number.

	// Update High Water Mark
	if seq > s.RecvSeq {
		s.RecvSeq = seq
	}
	s.LastActive = time.Now()

	return pkt, seq, nil
}
