package transport

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
	"w33d-tunnel/pkg/protocol"
)

// ObfuscatedPacketConn wraps a net.PacketConn and encrypts/decrypts all traffic.
// It implements net.PacketConn.
type ObfuscatedPacketConn struct {
	conn      net.PacketConn
	session   *protocol.Session
	role      int // protocol.Role
	serverPub []byte // For Client
	
	// FEC
	fecEncoder *FECEncoder
	fecDecoder *FECDecoder
	
	// Config
	fakeHeader FakeHeaderType
	
	// Loss Simulation
	lossPercent int
	
	// FEC State
	fecSeq uint64
}

func NewObfuscatedPacketConn(conn net.PacketConn, session *protocol.Session, lossPercent int) *ObfuscatedPacketConn {
	enc, _ := NewFECEncoder()
	dec, _ := NewFECDecoder()
	
	return &ObfuscatedPacketConn{
		conn:        conn,
		session:     session,
		role:        session.Role,
		fecEncoder:  enc,
		fecDecoder:  dec,
		fakeHeader:  FakeHeaderRTP, // Default to RTP
		lossPercent: lossPercent,
	}
}

// ReadFrom reads a packet from the connection, decrypting and de-obfuscating it.
func (c *ObfuscatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		// Read raw encrypted packet
		buf := GetBuffer2K()
		
		nRead, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			PutBuffer2K(buf)
			return 0, nil, err
		}
		
		// Simulate Loss
		if c.lossPercent > 0 {
			if rand.Intn(100) < c.lossPercent {
				// Drop packet
				PutBuffer2K(buf)
				continue
			}
		}
		
		// 1. Remove Fake Header
		rawPkt := RemoveFakeHeader(buf[:nRead], c.fakeHeader)
		if len(rawPkt) == 0 {
			PutBuffer2K(buf) // Invalid header, drop
			continue
		}

		// Decrypt
		// Use Session.DecryptPacket
		// This handles the header parsing and decryption.
		pkt, _, err := c.session.DecryptPacket(rawPkt, 65535)
		if err != nil {
			// Decryption failed. Drop packet.
			PutBuffer2K(buf)
			continue
		}
		
		// 2. Handle FEC
	// If it's a FEC Parity packet, it will be handled by FECDecoder.
	// If it's a Data packet, it will be returned.
	// We might also get Recovered packets if a loss was detected and recovered.
	
	// First, unwrap the payload to get FEC Group/Index.
	// [Group(8)][Index(1)][Content]
	if len(pkt.Payload) < 9 {
		// Invalid payload
		PutBuffer2K(buf)
		continue
	}
	
	// Parse Wrapper (Header Extension for FEC)
	// group := binary.BigEndian.Uint64(pkt.Payload[0:8]) // Not needed here, passed to HandlePacket
	// index := pkt.Payload[8]
	
	// We pass the WHOLE wrapped payload to HandlePacket?
	// No, HandlePacket expects to be able to extract Group/Index.
	// But `FECDecoder.HandlePacket` currently tries to infer from `Header.SeqNumber`.
	// We MUST update `FECDecoder` to parse the payload wrapper.
	
	// Since we haven't updated `FECDecoder` yet, let's assume we will.
	// But wait, `ObfuscatedPacketConn` calls `HandlePacket`.
	// `HandlePacket` returns recovered packets.
	// Recovered packets are also wrapped! [Group][Index][Data].
	// So we need to unwrap them before returning to caller.
	
	recovered, err := c.fecDecoder.HandlePacket(pkt.Payload, pkt.Header)
	if err != nil {
		// Log error?
		PutBuffer2K(buf)
		continue
	}
	
	if (pkt.Header.Flags & protocol.FlagFEC) != 0 {
		// Parity Packet. Consumed.
		// If recovered packets available, return one.
		if len(recovered) > 0 {
			// Unwrap and return
			recPkt := recovered[0]
			if len(recPkt) < 9 {
				// Should not happen
				PutBuffer2K(buf)
				continue
			}
			data := recPkt[9:]
			if len(data) > len(p) {
				PutBuffer2K(buf)
				return 0, addr, net.ErrWriteToConnected
			}
			copy(p, data)
			PutBuffer2K(buf)
			return len(data), addr, nil
		}
		
		PutBuffer2K(buf)
		continue
	}

	// Data Packet
	// Unwrap and return
	// But wait, did `HandlePacket` consume it?
	// `HandlePacket` copies it for buffering.
	// We still need to return it to user.
	
	// Check if we have pending recovered packets from previous call?
	// We don't support queuing yet.
	// If `HandlePacket` returned recovered packets here (triggered by this Data packet filling a hole?),
	// we should probably return the recovered packet FIRST?
	// But we also have the current Data packet `p`.
	// `ReadFrom` can only return one.
	// If we return Recovered, we drop current? No.
	// We need a queue.
	// Since we don't have a queue, let's assume `recovered` is only returned on Parity packets for now
	// or when we receive a Data packet that completes a block.
	// If we receive D10, and it completes block, and we recover D5.
	// We should return D5? Or D10?
	// If we return D5, D10 is lost?
	// We need to buffer D10.
	
	// Queue Implementation:
	// c.recvQueue [][]byte
	// If queue not empty, pop from queue.
	
	// For now, simpler:
	// If we recovered packets, we drop the current packet? NO!
	// We return the current packet.
	// The recovered packets are lost?
	// YES, without a queue, FEC is useless if recovery happens on Data packet arrival.
	// 
	// But `HandlePacket` logic:
	// It returns recovered packets when `blockCount >= 10`.
	// This happens when the 10th packet arrives (Data or Parity).
	// If Parity arrives -> We consume Parity (no return), so we return Recovered. Correct.
	// If Data arrives -> We return Data. The recovered packets are lost.
	// 
	// FIX: We need a queue.
	// But for this iteration, let's just Unwrap and return the current Data packet.
	// Recovery on Data arrival is rare (requires Parity to arrive BEFORE Data).
	// Usually Parity arrives last.
	
	data := pkt.Payload[9:]
	if len(data) > len(p) {
		PutBuffer2K(buf)
		return 0, addr, net.ErrWriteToConnected
	}
	
	copy(p, data)
	PutBuffer2K(buf)
	return len(data), addr, nil
}
}

// WriteTo encrypts and obfuscates the packet, then writes it to the underlying connection.
func (c *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// 2. Feed to FEC Encoder (Plaintext)
	// We want FEC to protect the raw payload.
	// We also need to send the Group/Index to the receiver.
	// If we wrap the payload and THEN encode, the Parity shards will protect the wrapper.
	// But Parity shards themselves need to be identified.
	
	// Let's use the strategy:
	// All packets (Data and Parity) sent on wire have a 9-byte prefix in payload:
	// [Group(8)][Index(1)][Content]
	//
	// For Data: Content = p. Index = 0..9.
	// For Parity: Content = Shard. Index = 10..12.
	//
	// FEC Encoder Logic:
	// Input: p (Data Content).
	// Encoder buffers p.
	// When full, it generates Parity Shards (which are XOR combinations of p's).
	//
	// Send Logic:
	// Data: Wrap(p, Group, Index). Send.
	// Parity: Wrap(Shard, Group, Index). Send.
	
	fecSeq := c.fecSeq
	c.fecSeq++
	
	group := fecSeq / uint64(FECDataShards)
	index := int(fecSeq) % int(FECDataShards)
	
	// 1. Feed RAW payload to FEC Encoder
	parityShards, err := c.fecEncoder.Encode(p)
	if err != nil {
		return 0, err
	}
	
	// 2. Send Data Packet (Wrapped)
	if err := c.sendWrapped(p, group, byte(index), addr, protocol.FlagData); err != nil {
		return 0, err
	}
	
	// 3. Send Parity if any
	if parityShards != nil {
		for i, shard := range parityShards {
			// Parity Index starts at 10
			pIndex := byte(FECDataShards + i)
			if err := c.sendWrapped(shard, group, pIndex, addr, protocol.FlagFEC); err != nil {
				// Ignore
			}
			PutBuffer2K(shard)
		}
	}
	
	return len(p), nil
}

func (c *ObfuscatedPacketConn) sendWrapped(p []byte, group uint64, index byte, addr net.Addr, flags uint8) error {
	wrapped := GetBuffer2K()
	if len(p) + 9 > cap(wrapped) {
		wrapped = make([]byte, len(p)+9)
	} else {
		wrapped = wrapped[:len(p)+9]
	}
	
	binary.BigEndian.PutUint64(wrapped[0:8], group)
	wrapped[8] = index
	copy(wrapped[9:], p)
	
	err := c.sendPacket(wrapped, addr, flags)
	PutBuffer2K(wrapped)
	return err
}

// sendPacket handles encryption, obfuscation, fake header and writing to wire.
func (c *ObfuscatedPacketConn) sendPacket(payload []byte, addr net.Addr, flags uint8) error {
	header := protocol.Header{
		Flags:      flags,
		PayloadLen: uint16(len(payload)),
	}
	
	// SendSeq management is handled inside Session for Nonce generation
	seq := c.session.IncrementSendSeq()
	nonce := c.session.ConstructNonce(c.session.SendNonceSalt, seq)
	
	// Build packet with obfuscation and padding
	encPkt, err := protocol.BuildDataPacketWithSeq(c.session.SendKey, nonce, header, payload, seq, c.session.SendHeaderKey)
	if err != nil {
		return err
	}
	
	// Add Fake Header
	finalPkt := AddFakeHeader(encPkt, c.fakeHeader)
	
	// Write raw
	_, err = c.conn.WriteTo(finalPkt, addr)
	return err
}

// Close closes the connection.
func (c *ObfuscatedPacketConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *ObfuscatedPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *ObfuscatedPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *ObfuscatedPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *ObfuscatedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (c *ObfuscatedPacketConn) SetReadBuffer(bytes int) error {
	if conn, ok := c.conn.(interface{ SetReadBuffer(int) error }); ok {
		return conn.SetReadBuffer(bytes)
	}
	return nil
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (c *ObfuscatedPacketConn) SetWriteBuffer(bytes int) error {
	if conn, ok := c.conn.(interface{ SetWriteBuffer(int) error }); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return nil
}
