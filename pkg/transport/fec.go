package transport

import (
	"encoding/binary"
	"errors"
	"sync"
	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/protocol"

	"github.com/klauspost/reedsolomon"
)

const (
	FECDataShards   = 10
	FECParityShards = 3
	FECBlockSize    = FECDataShards + FECParityShards
)

// FECEncoder handles Forward Error Correction encoding.
type FECEncoder struct {
	enc          reedsolomon.Encoder
	shards       [][]byte
	shardCount   int
	maxShardSize int
	mutex        sync.Mutex
}

func NewFECEncoder() (*FECEncoder, error) {
	enc, err := reedsolomon.New(FECDataShards, FECParityShards)
	if err != nil {
		return nil, err
	}
	return &FECEncoder{
		enc:    enc,
		shards: make([][]byte, FECBlockSize),
	}, nil
}

// Encode adds a data packet to the block. If block is full, returns parity packets.
// Input packet is NOT modified.
func (e *FECEncoder) Encode(packet []byte) ([][]byte, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Add packet to current block
	// We must make a copy because we might pad it later
	pktCopy := GetBuffer2K() // Use Pool
	if len(packet) > cap(pktCopy) {
		// Should not happen with current MTU config (1350)
		// But if it does, allocate new
		pktCopy = make([]byte, len(packet))
	} else {
		pktCopy = pktCopy[:len(packet)]
	}
	copy(pktCopy, packet)
	
	e.shards[e.shardCount] = pktCopy
	if len(pktCopy) > e.maxShardSize {
		e.maxShardSize = len(pktCopy)
	}
	e.shardCount++

	// Check if block is full (DataShards reached)
	if e.shardCount == FECDataShards {
		return e.flush()
	}
	
	return nil, nil
}

func (e *FECEncoder) flush() ([][]byte, error) {
	// 1. Pad all shards to maxShardSize
	for i := 0; i < FECDataShards; i++ {
		shard := e.shards[i]
		if len(shard) < e.maxShardSize {
			padding := make([]byte, e.maxShardSize-len(shard))
			// Simple zero padding is fine for RS
			e.shards[i] = append(shard, padding...)
		}
	}
	
	// 2. Allocate parity shards
	for i := FECDataShards; i < FECBlockSize; i++ {
		e.shards[i] = make([]byte, e.maxShardSize)
	}
	
	// 3. Encode
	if err := e.enc.Encode(e.shards); err != nil {
		e.reset()
		return nil, err
	}
	
	// 4. Extract Parity
	parity := make([][]byte, FECParityShards)
	for i := 0; i < FECParityShards; i++ {
		// Copy parity data
		// Use Pool?
		// Parity shards are created by RS inside e.shards.
		// We need to return them.
		// The caller will use them and then discard.
		// We can't easily pool the *slice of slices* return value, but we can pool the data.
		
		src := e.shards[FECDataShards+i]
		p := GetBuffer2K()
		if len(src) > cap(p) {
			p = make([]byte, len(src))
		} else {
			p = p[:len(src)]
		}
		copy(p, src)
		parity[i] = p
	}
	
	e.reset()
	return parity, nil
}

func (e *FECEncoder) reset() {
	// Return buffers to pool
	for i := 0; i < e.shardCount; i++ {
		if e.shards[i] != nil {
			PutBuffer2K(e.shards[i])
			e.shards[i] = nil
		}
	}
	// Also clear parity slots if they were allocated
	for i := FECDataShards; i < FECBlockSize; i++ {
		e.shards[i] = nil
	}
	
	e.shardCount = 0
	e.maxShardSize = 0
}

// FECDecoder handles Forward Error Correction decoding/recovery.
type FECDecoder struct {
	dec           reedsolomon.Encoder // Same interface
	blockShards   [][]byte
	blockPresent  []bool
	blockCount    int
	mutex         sync.Mutex
	
	// State tracking
	currentGroup uint64
}

func NewFECDecoder() (*FECDecoder, error) {
	dec, err := reedsolomon.New(FECDataShards, FECParityShards)
	if err != nil {
		return nil, err
	}
	return &FECDecoder{
		dec:          dec,
		blockShards:  make([][]byte, FECBlockSize),
		blockPresent: make([]bool, FECBlockSize),
	}, nil
}

// HandlePacket processes a packet.
// If it's a Data packet, returns it immediately.
// If it's a Parity packet, buffers it and tries to recover lost data packets.
// Returns recovered packets if any.
// 
// Note: This requires packets to carry FEC Group information.
func (d *FECDecoder) HandlePacket(packet []byte, header protocol.Header) ([][]byte, error) {
	// Payload Wrapper: [Group(8)][Index(1)][Content]
	if len(packet) < 9 {
		return nil, errors.New("packet too short for FEC wrapper")
	}
	
	group := binary.BigEndian.Uint64(packet[0:8])
	index := int(packet[8])
	
	isParity := (header.Flags & protocol.FlagFEC) != 0
	
	// Reset if new group
	if group > d.currentGroup {
		// New group started. Old group is abandoned (incomplete).
		// Ideally we should have recovered already.
		d.reset(group)
	} else if group < d.currentGroup {
		// Old packet. Ignore.
		return nil, nil
	}
	
	// Current Group
	if isParity {
		// Parity packet logic
		// Index 10, 11, 12...
		// In wrapper, index is already correct (10+).
		
		if index < FECDataShards {
			// Invalid parity index
			return nil, nil
		}
		
		// Store Parity
		// We store the WHOLE wrapper or just Content?
		// Reconstruct needs same-sized shards.
		// If we store Wrapper, we recover Wrapper.
		// That's what we want!
		
		slot := index
		if slot >= FECBlockSize { return nil, nil }
		
		if !d.blockPresent[slot] {
			// Store Copy
			c := make([]byte, len(packet))
			copy(c, packet)
			d.blockShards[slot] = c
			d.blockPresent[slot] = true
			d.blockCount++
		}
		
	} else {
		// Data Packet
		// Index 0..9
		
		if index >= FECDataShards {
			return nil, nil
		}
		
		if !d.blockPresent[index] {
			// Store Copy
			c := make([]byte, len(packet))
			copy(c, packet)
			d.blockShards[index] = c
			d.blockPresent[index] = true
			d.blockCount++
		}
		
		// Return immediately (No delay!)
		// Caller handles unwrapping.
	}
	
	// Check for Recovery
	// We need 10 shards.
	if d.blockCount >= FECDataShards {
		// Do we have holes in Data?
		hasHoles := false
		for i := 0; i < FECDataShards; i++ {
			if !d.blockPresent[i] {
				hasHoles = true
				break
			}
		}
		
		if hasHoles {
			// Recover!
			// Reconstruct requires all shards to be same size.
			// We assume parity shards were padded to max size.
			// We might need to pad our received data shards to match parity size?
			// Let's check max size in buffer.
			maxSize := 0
			for i := 0; i < FECBlockSize; i++ {
				if d.blockPresent[i] && len(d.blockShards[i]) > maxSize {
					maxSize = len(d.blockShards[i])
				}
			}
			
			// Pad existing
			for i := 0; i < FECBlockSize; i++ {
				if d.blockPresent[i] && len(d.blockShards[i]) < maxSize {
					// Pad (copy to new slice)
					newBuf := make([]byte, maxSize)
					copy(newBuf, d.blockShards[i])
					d.blockShards[i] = newBuf
				} else if !d.blockPresent[i] {
					d.blockShards[i] = nil // Ensure nil
				}
			}
			
			// Reconstruct
			if err := d.dec.Reconstruct(d.blockShards); err != nil {
				logger.Debug("FEC Reconstruct failed: %v", err)
				return nil, nil // Return nothing (can't recover)
			}
			
			// Collect Recovered Packets
			var recovered [][]byte
			for i := 0; i < FECDataShards; i++ {
				if !d.blockPresent[i] {
					// This was recovered!
					// We need to strip padding?
					// Packet length is lost if we just zero-pad.
					// Protocol should handle trailing zeros?
					// Smart Padding already aligns to buckets.
					// So it should be fine?
					// Wait, if we padded to MaxShardSize which is > BucketSize?
					// Yes.
					// But our protocol parser ignores trailing bytes after PayloadLen.
					// So extra zeros are fine!
					
					recPkt := d.blockShards[i]
					recovered = append(recovered, recPkt)
					
					// Mark as present
					d.blockPresent[i] = true
					d.blockCount++
				}
			}
			
			if len(recovered) > 0 {
				logger.Debug("FEC Recovered %d packets in group %d", len(recovered), group)
			}
			return recovered, nil
		}
	}
	
	return nil, nil
}

func (d *FECDecoder) reset(group uint64) {
	d.currentGroup = group
	d.blockCount = 0
	for i := 0; i < FECBlockSize; i++ {
		d.blockShards[i] = nil
		d.blockPresent[i] = false
	}
}
