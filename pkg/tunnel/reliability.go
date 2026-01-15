package tunnel

import (
	"errors"
	"sync"
	"time"
	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/protocol"
)

const (
	// WindowSize limits the number of unacknowledged packets.
	WindowSize = 4096
	// MinResendInterval is the minimum time before retransmission.
	MinResendInterval = 10 * time.Millisecond
)

// PendingPacket represents a packet waiting for ACK.
type PendingPacket struct {
	Header    protocol.Header
	Payload   []byte
	FirstSent time.Time
	LastSent  time.Time
	Retries   int
}

// ReliableSession adds ARQ (Automatic Repeat Request) to a session.
type ReliableSession struct {
	Session *protocol.Session

	// Send Side
	sendLock sync.Mutex
	nextSeq  uint32 // Next ARQ Seq to assign
	sendBuf  map[uint32]*PendingPacket
	minAck   uint32 // The oldest unacknowledged seq (for window)

	// Recv Side
	recvLock sync.Mutex
	nextRecv uint32 // Next expected ARQ Seq
	recvBuf  map[uint32]*protocol.DataPacket

	// Config
	ResendInterval time.Duration
	MaxRetries     int

	// RTT Estimation
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration
}

// NewReliableSession creates a new reliable session wrapper.
func NewReliableSession(sess *protocol.Session) *ReliableSession {
	return &ReliableSession{
		Session:        sess,
		nextSeq:        1,
		sendBuf:        make(map[uint32]*PendingPacket),
		nextRecv:       1,
		recvBuf:        make(map[uint32]*protocol.DataPacket),
		ResendInterval: MinResendInterval,
		MaxRetries:     0, // Infinite
		rto:            100 * time.Millisecond,
	}
}

// SendData queues data and returns the packet bytes to send (encrypted).
func (rs *ReliableSession) SendData(payload []byte) ([]byte, error) {
	return rs.sendDataInternal(payload, false)
}

// SendUnreliableData sends data without ARQ/ordering guarantees.
func (rs *ReliableSession) SendUnreliableData(payload []byte) ([]byte, error) {
	return rs.sendDataInternal(payload, true)
}

func (rs *ReliableSession) sendDataInternal(payload []byte, unreliable bool) ([]byte, error) {
	rs.sendLock.Lock()
	defer rs.sendLock.Unlock()

	// Flow Control (Skip for unreliable? Maybe still limit to avoid flooding)
	// For now, unreliable packets also count towards send window to keep simple sequence space.
	// But we don't need to retransmit them.
	// Wait, if we use the same sequence space, we MUST store them in sendBuf to handle ACKs correctly?
	// If we skip storing, the receiver will ACK a sequence we don't have. That's fine (cumulative ack).
	// But if we skip sequence number, we break ordering for reliable packets?
	// We MUST assign a sequence number to Unreliable packets to keep encryption nonce sync/unique.
	// So we increment nextSeq.
	
	if len(rs.sendBuf) >= WindowSize {
		return nil, errors.New("send window full")
	}

	seq := rs.nextSeq
	rs.nextSeq++

	header := protocol.Header{
		Flags:      protocol.FlagData,
		PayloadLen: uint16(len(payload)),
		SeqNumber:  seq,
	}
	
	if unreliable {
		header.Flags |= protocol.FlagUnreliable
	}

	// Piggyback ACK
	ackSeq := rs.GetNextRecv() - 1
	if ackSeq > 0 {
		header.Flags |= protocol.FlagAck
		header.AckNumber = ackSeq
	}

	// Store for retransmission ONLY if reliable
	if !unreliable {
		rs.sendBuf[seq] = &PendingPacket{
			Header:    header,
			Payload:   payload,
			FirstSent: time.Now(),
			LastSent:  time.Now(),
		}
	} else {
		// For unreliable, we don't retransmit.
		// But we consumed a sequence number.
		// If we don't put it in sendBuf, handleAck might be confused?
		// handleAck removes seq <= ackSeq. If it's not in map, no problem.
		// BUT, if we send 1(Rel), 2(Unrel), 3(Rel).
		// Receiver gets 1, 2, 3. Sends Ack 3.
		// Sender gets Ack 3. Removes 1 and 3.
		// What about 2? It wasn't in map.
		// That works fine.
		
		// One issue: If 2 is lost. Receiver gets 1, 3.
		// Receiver sends Ack 1. Then buffers 3.
		// Sender resends 3? No, sender sees 3 is unacked.
		// Receiver waiting for 2?
		// If 2 is unreliable, receiver should NOT wait for it.
		// So Receiver logic needs change to skip 2.
	}

	return rs.buildPacket(header, payload)
}

func (rs *ReliableSession) GetNextRecv() uint32 {
	rs.recvLock.Lock()
	defer rs.recvLock.Unlock()
	return rs.nextRecv
}

func (rs *ReliableSession) buildPacket(header protocol.Header, payload []byte) ([]byte, error) {
	// Lock Session for Nonce generation
	// Note: Session has its own locks.
	nonceSeq := rs.Session.IncrementSendSeq()
	nonce := rs.Session.ConstructNonce(rs.Session.SendNonceSalt, nonceSeq)

	return protocol.BuildDataPacketWithSeq(rs.Session.SendKey, nonce, header, payload, nonceSeq, rs.Session.SendHeaderKey)
}

// HandlePacket processes a received decrypted packet.
// Returns:
// 1. orderedPayloads: A list of data payloads that are now in-order and ready to process.
// 2. ackPacket: An ACK packet to send back immediately (if any).
// 3. error
func (rs *ReliableSession) HandlePacket(pkt *protocol.DataPacket) ([][]byte, []byte, error) {
	var ackBytes []byte
	var orderedPayloads [][]byte

	// 1. Process ACK if present
	if pkt.Header.Flags&protocol.FlagAck != 0 {
		rs.handleAck(pkt.Header.AckNumber)
	}

	// 2. Process Data if present
	if pkt.Header.Flags&protocol.FlagData != 0 {
		// Update Recv State and get ordered data
		orderedPayloads = rs.handleData(pkt)

		// Generate Cumulative ACK
		// We ALWAYS send ACK, even if it's a duplicate or out of order.
		// We tell the sender: "I am expecting nextRecv".
		// So we ACK (nextRecv - 1).
		ackSeq := rs.nextRecv - 1
		if ackSeq > 0 {
			ackHeader := protocol.Header{
				Flags:     protocol.FlagAck,
				SeqNumber: 0,
				AckNumber: ackSeq,
			}

			// logger.Debug("Sending Cumulative ACK for %d", ackSeq)

			var err error
			ackBytes, err = rs.buildPacket(ackHeader, nil)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return orderedPayloads, ackBytes, nil
}

func (rs *ReliableSession) handleAck(ackSeq uint32) {
	rs.sendLock.Lock()
	defer rs.sendLock.Unlock()

	// RTT Sample
	if pkt, ok := rs.sendBuf[ackSeq]; ok {
		if pkt.Retries == 0 {
			rtt := time.Since(pkt.FirstSent)
			rs.updateRTT(rtt)
		}
	}

	// Cumulative ACK: Remove all <= ackSeq
	for seq := range rs.sendBuf {
		if seq <= ackSeq {
			delete(rs.sendBuf, seq)
		}
	}
}

func (rs *ReliableSession) updateRTT(rtt time.Duration) {
	if rs.srtt == 0 {
		rs.srtt = rtt
		rs.rttvar = rtt / 2
	} else {
		alpha := 0.125
		beta := 0.25

		diff := rs.srtt - rtt
		if diff < 0 {
			diff = -diff
		}

		rs.rttvar = time.Duration((1-beta)*float64(rs.rttvar) + beta*float64(diff))
		rs.srtt = time.Duration((1-alpha)*float64(rs.srtt) + alpha*float64(rtt))
	}

	rs.rto = rs.srtt + 4*rs.rttvar
	if rs.rto < 10*time.Millisecond {
		rs.rto = 10 * time.Millisecond
	}
	if rs.rto > 2*time.Second {
		rs.rto = 2 * time.Second
	}
}

func (rs *ReliableSession) handleData(pkt *protocol.DataPacket) [][]byte {
	rs.recvLock.Lock()
	defer rs.recvLock.Unlock()

	seq := pkt.Header.SeqNumber

	if seq < rs.nextRecv {
		// Old duplicate, already acked (and we sent ack again above)
		return nil
	}

	// If exactly what we expected
	if seq == rs.nextRecv {
		var payloads [][]byte
		
		// If unreliable, just append. If reliable, append.
		// Wait, if it's unreliable, we still consume the sequence number.
		// So nextRecv++ is correct.
		
		if pkt.Header.Flags&protocol.FlagUnreliable == 0 || pkt.Payload != nil {
             // Only return payload if it's not empty? 
             // Unreliable packets might be empty (just gap fillers?)
             // No, they carry data.
			payloads = append(payloads, pkt.Payload)
		}
		
		rs.nextRecv++

		// Check buffer for subsequent packets
		for {
			if nextPkt, ok := rs.recvBuf[rs.nextRecv]; ok {
				// We found the next packet.
				// Is it reliable or unreliable?
				// It doesn't matter, it's the next one.
				if nextPkt.Payload != nil {
					payloads = append(payloads, nextPkt.Payload)
				}
				delete(rs.recvBuf, rs.nextRecv)
				rs.nextRecv++
			} else {
				break
			}
		}
		return payloads
	}

	// Out of order (future packet)
	// If it's Unreliable, can we deliver it immediately?
	// If we do, we break the "orderedPayloads" contract?
	// But "orderedPayloads" implies reliable stream.
	// If the user wants Unreliable, they probably handle reordering.
	// BUT, we are multiplexing streams.
	// If we return it now, the caller gets it.
	// If the caller is a SOCKS5 UDP handler, it's fine.
	// If the caller is a TCP stream, it's bad?
	// The caller (main.go) dispatches based on StreamID.
	// UDP streams will use CmdUDP. TCP streams use CmdData.
	// So if we return it out-of-order, main.go will process CmdUDP out-of-order. That is CORRECT for UDP.
	// What if we return CmdData out-of-order? That would break TCP.
	// So: Only return immediately if FlagUnreliable is set.
	
	if pkt.Header.Flags&protocol.FlagUnreliable != 0 {
		// It's unreliable. We can return it immediately.
		// BUT we must NOT increment nextRecv, because we are skipping the gap.
		// AND we must NOT return it again when the gap is filled.
		// So we just return it.
		// Problem: The caller expects a list of payloads.
		// If we return it, the caller processes it.
		// Later, when the gap fills, nextRecv increments.
		// Will we process this packet again?
		// We didn't add it to recvBuf. So no.
		// But wait, if we don't add to recvBuf, and don't increment nextRecv,
		// how does nextRecv ever pass this number?
		// Ah! If it's Unreliable, we assume it's "consumed" regarding the gap?
		// No. The sender used a sequence number.
		// If packet 2 is unreliable and we receive it before 1.
		// We process 2.
		// Receiver state: nextRecv=1.
		// Later 1 arrives. nextRecv becomes 2.
		// Then we look for 2? We don't have it (processed).
		// So nextRecv stops at 2.
		// Sender sends 3. Receiver gets 3. Buffers 3.
		// Deadlock?
		
		// Solution: We need to mark '2' as "seen" or "skipped" in the sequence stream so nextRecv can skip it.
		// But we can't increment nextRecv yet because 1 is missing.
		// We could add a "tombstone" or "placeholder" in recvBuf?
		// Or just store it in recvBuf marked as "Processed"?
		// If we store it, we can return it NOW, and when nextRecv reaches it, we skip returning it again.
		
		// Let's modify DataPacket to have a "Processed" field? No, it's protocol struct.
		// We can wrap it in recvBuf.
		
		// Alternative: Unreliable packets do NOT consume Sequence Number?
		// Then we can't use the same nonce/replay logic.
		// Replay logic relies on Sequence.
		
		// Let's go with "Process immediately + Tombstone".
		
		var payloads [][]byte
		payloads = append(payloads, pkt.Payload)
		
		// Buffer a placeholder to fill the sequence gap later
		rs.recvBuf[seq] = &protocol.DataPacket{Header: pkt.Header, Payload: nil} // Nil payload = already processed
		
		return payloads
	}

	// Buffer it (Reliable or Future Unreliable that we didn't want to process? No, always process Unrel immediately)
	if _, exists := rs.recvBuf[seq]; !exists {
		// logger.Debug("Buffered out-of-order packet %d (expecting %d)", seq, rs.nextRecv)
		rs.recvBuf[seq] = pkt
	}
	
	return nil
}

// CheckRetransmits checks for timed-out packets and returns them for retransmission.
// This should be called periodically.
func (rs *ReliableSession) CheckRetransmits() ([][]byte, error) {
	rs.sendLock.Lock()
	defer rs.sendLock.Unlock()

	var packets [][]byte
	now := time.Now()

	for _, item := range rs.sendBuf {
		// Exponential Backoff: RTO * 2^Retries
		interval := rs.rto * time.Duration(1<<item.Retries)
		if interval > 2*time.Second {
			interval = 2 * time.Second
		}

		if now.Sub(item.LastSent) > interval {
			if rs.MaxRetries > 0 && item.Retries >= rs.MaxRetries {
				logger.Error("Packet %d max retries reached. Dropping.", item.Header.SeqNumber)
				delete(rs.sendBuf, item.Header.SeqNumber)
				continue
			}

			// Retransmit
			// Note: We MUST use a NEW Nonce/EncryptionSeq, but same Header.SeqNumber
			item.Retries++
			item.LastSent = now

			pkt, err := rs.buildPacket(item.Header, item.Payload)
			if err == nil {
				packets = append(packets, pkt)
			}
		}
	}

	return packets, nil
}
