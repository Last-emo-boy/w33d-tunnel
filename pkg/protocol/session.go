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
	
	// Sliding Window for Replay Protection
	// Window size 1024.
	// We use a []uint64 bitmap. 1024 bits = 16 * 64-bit integers.
	RecvWindow [16]uint64 

	RemoteAddr net.Addr
	LastActive time.Time
	
	// Tenant Info
	Token string
	// Traffic Stats
	BytesRead    uint64
	BytesWritten uint64
	StatsLock    sync.Mutex
}

// AddStats updates traffic usage safely.
func (s *Session) AddStats(read, written uint64) {
	s.StatsLock.Lock()
	defer s.StatsLock.Unlock()
	s.BytesRead += read
	s.BytesWritten += written
}

// GetAndResetStats returns current stats and resets them.
func (s *Session) GetAndResetStats() (uint64, uint64) {
	s.StatsLock.Lock()
	defer s.StatsLock.Unlock()
	r, w := s.BytesRead, s.BytesWritten
	s.BytesRead = 0
	s.BytesWritten = 0
	return r, w
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

// ValidateRecvSeq checks replay protection using a sliding window.
// Returns true if packet is valid (new or within window and not duplicate).
func (s *Session) ValidateRecvSeq(seq uint64) bool {
	// 1. New highest sequence number
	if seq > s.RecvSeq {
		// Shift window
		diff := seq - s.RecvSeq
		if diff >= 1024 {
			// Jump too big, reset window (all previous invalid)
			for i := 0; i < 16; i++ {
				s.RecvWindow[i] = 0
			}
		} else {
			// Shift window left by diff
			// Implementing bit shift on array of uint64 is tricky.
			// Simplified approach:
			// Just calculate the index for the NEW seq, and everything else is relative.
			// Actually, typical implementation:
			// RecvSeq is the Right Edge of the window.
			// When RecvSeq moves right, we clear the bits that fell off?
			// 
			// Optimization:
			// We only need to check if `seq` is in [RecvSeq - 1023, RecvSeq].
			// If seq > RecvSeq, it is valid. We update RecvSeq.
			// But we need to mark it as seen.
			
			// Let's do the shifting.
			shift := uint64(diff)
			
			// Shift the whole array left by `shift` bits.
			// Since 1024 is small, we can just loop.
			// Or simplified:
			// We don't shift. We just use modulo?
			// No, modulo doesn't handle the "moving window" naturally for replay check.
			// 
			// Let's implement the shift.
			// Move bits from lower indices to higher?
			// Window: [Oldest ... Newest]
			// If we shift "left" (Newest moves), we are actually shifting in 0s at the new position.
			// 
			// Let's use the standard "IPSec" style window.
			// RecvSeq is the highest seen.
			// We track `seq` relative to RecvSeq.
			
			// First, handle the shift logic by clearing old bits?
			// Actually, we just need to shift the bitmap.
			// Doing a 1024-bit shift is expensive.
			// 
			// Alternative: Ring Buffer.
			// Index = seq % 1024.
			// But we need to handle "wrapping" and clearing old values.
			// 
			// Let's stick to the shift, but optimize.
			// If diff > 64, we shift whole uint64s.
			
			// Shift Logic:
			// We want to shift LEFT by `diff`.
			// `RecvWindow` represents [RecvSeq-1023 ... RecvSeq] ?
			// Let's say bit 0 is RecvSeq. Bit 1 is RecvSeq-1.
			// If RecvSeq increases by 1, Bit 0 becomes Bit 1.
			// So we shift LEFT (<<).
			
			wordsShift := shift / 64
			bitsShift := shift % 64
			
			if wordsShift > 0 {
				for i := 15; i >= int(wordsShift); i-- {
					s.RecvWindow[i] = s.RecvWindow[i-int(wordsShift)]
				}
				for i := 0; i < int(wordsShift); i++ {
					s.RecvWindow[i] = 0
				}
			}
			
			if bitsShift > 0 {
				carry := uint64(0)
				for i := 0; i < 16; i++ {
					newCarry := s.RecvWindow[i] >> (64 - bitsShift)
					s.RecvWindow[i] = (s.RecvWindow[i] << bitsShift) | carry
					carry = newCarry
				}
			}
		}
		
		s.RecvSeq = seq
		// Mark current (Bit 0)
		s.RecvWindow[0] |= 1
		return true
	}

	// 2. Old packet
	if seq <= s.RecvSeq {
		diff := s.RecvSeq - seq
		if diff >= 1024 {
			return false // Too old
		}
		
		// Check bit
		wordIdx := diff / 64
		bitIdx := diff % 64
		
		mask := uint64(1) << bitIdx
		if (s.RecvWindow[wordIdx] & mask) != 0 {
			return false // Replay
		}
		
		// Mark seen
		s.RecvWindow[wordIdx] |= mask
		return true
	}

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
	
	if !s.ValidateRecvSeq(seq) {
		// Decrypted fine but replay. Drop.
		// However, we already spent CPU decrypting. This is acceptable to prevent DoS on State.
		return nil, seq, errors.New("replay detected")
	}

	s.LastActive = time.Now()

	return pkt, seq, nil
}
