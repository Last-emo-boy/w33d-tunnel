package transport

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
	"w33d-tunnel/pkg/protocol"
)

// SessionManager manages sessions mapped by remote address.
type SessionManager struct {
	serverPriv []byte
	sessions   map[string]*protocol.Session
	lock       sync.RWMutex
	stopChan   chan struct{}
}

func NewSessionManager(serverPriv []byte) *SessionManager {
	sm := &SessionManager{
		serverPriv: serverPriv,
		sessions:   make(map[string]*protocol.Session),
		stopChan:   make(chan struct{}),
	}
	go sm.cleanupLoop()
	return sm
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.lock.Lock()
			now := time.Now()
			for k, s := range sm.sessions {
				// If inactive for 5 minutes, cleanup
				if now.Sub(s.LastActive) > 5*time.Minute {
					delete(sm.sessions, k)
				}
			}
			sm.lock.Unlock()
		}
	}
}

func (sm *SessionManager) GetSession(addr net.Addr) *protocol.Session {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	return sm.sessions[addr.String()]
}

func (sm *SessionManager) CreateSession(addr net.Addr) *protocol.Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	
	// Check again
	if sess, ok := sm.sessions[addr.String()]; ok {
		return sess
	}
	
	// Create new server session (Client Key unknown yet, will be set during Handshake)
	sess := protocol.NewSession(protocol.RoleServer, sm.serverPriv, nil)
	sess.RemoteAddr = addr
	
	// Initialize FEC
	enc, _ := NewFECEncoder()
	dec, _ := NewFECDecoder()
	sess.FECEncoder = enc
	sess.FECDecoder = dec
	
	sm.sessions[addr.String()] = sess
	return sess
}

// ServerObfuscatedPacketConn wraps a UDP listener and handles multiplexing for multiple clients.
// It intercepts Handshake packets and decrypts Data packets using the correct session.
type ServerObfuscatedPacketConn struct {
conn    *net.UDPConn
	manager *SessionManager
	lossPercent int
}

func NewServerObfuscatedPacketConn(conn *net.UDPConn, serverPriv []byte, lossPercent int) *ServerObfuscatedPacketConn {
	return &ServerObfuscatedPacketConn{
		conn:        conn,
		manager:     NewSessionManager(serverPriv),
		lossPercent: lossPercent,
	}
}

func (s *ServerObfuscatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		// Read raw UDP
		buf := GetBuffer2K()
		
		nRead, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			PutBuffer2K(buf)
			return 0, nil, err
		}
		
		// Simulate Loss
		if s.lossPercent > 0 {
			if rand.Intn(100) < s.lossPercent {
				// Drop packet
				PutBuffer2K(buf)
				continue
			}
		}
		
		// 1. Remove Fake Header
		// We don't know the type yet? Or assume same as Client?
		// For now assume RTP.
		rawPkt := RemoveFakeHeader(buf[:nRead], FakeHeaderRTP)
		if len(rawPkt) == 0 {
			PutBuffer2K(buf)
			continue
		}

		// Check Session
		// Note: RemoteAddr is still the UDP source.
		// But packet content is stripped.
		
		sess := s.manager.GetSession(addr)
		
		// If no session, it MUST be a Handshake Initiation or we drop it.
		if sess == nil || sess.State == protocol.StateClosed {
			if sess == nil {
				sess = s.manager.CreateSession(addr)
			}
			
			// Try to process as Handshake
			resp, err := sess.ProcessHandshakeInitiation(rawPkt)
			if err == nil {
				// Handshake Success! Send Response.
				// We must ADD Fake Header to response too.
				finalResp := AddFakeHeader(resp, FakeHeaderRTP)
				
				s.conn.WriteToUDP(finalResp, addr)
				PutBuffer2K(buf)
				continue
			} else {
				PutBuffer2K(buf)
				continue
			}
		}
		
	// Session Established. Decrypt.
		pkt, _, err := sess.DecryptPacket(rawPkt, 65535)
		if err != nil {
			// Decrypt failed. Drop.
			PutBuffer2K(buf)
			continue
		}
		
		s.manager.AddStats(sess, uint64(len(rawPkt)), uint64(len(pkt.Payload)))

		// 2. Handle FEC
		// If it's a FEC Parity packet, it will be handled by FECDecoder.
		// If it's a Data packet, it will be returned.
		// We might also get Recovered packets if a loss was detected and recovered.
		
		// Unwrap the payload to get FEC Group/Index.
		// [Group(8)][Index(1)][Content]
		if len(pkt.Payload) < 9 {
			// Invalid payload
			PutBuffer2K(buf)
			continue
		}
		
		recovered, err := sess.FECDecoder.HandlePacket(pkt.Payload, pkt.Header)
		if err != nil {
			PutBuffer2K(buf)
			continue
		}
		
		if (pkt.Header.Flags & protocol.FlagFEC) != 0 {
			// Parity Packet. Consumed.
			// If recovered packets available, return one.
			// TODO: Handle multiple recovered packets (need queue).
			// For now, return the first one.
			if len(recovered) > 0 {
				recPkt := recovered[0]
				if len(recPkt) < 9 {
					PutBuffer2K(buf)
					continue
				}
				data := recPkt[9:]
				if len(data) > len(p) {
					PutBuffer2K(buf)
					return 0, addr, errors.New("buffer too small")
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
		// We assume that HandlePacket processed it (stored for potential recovery)
		// but we still need to deliver it immediately.
		
		realPayload := pkt.Payload[9:]
	
		// Copy payload (QUIC packet) to p
		if len(realPayload) > len(p) {
			PutBuffer2K(buf)
			return 0, addr, errors.New("buffer too small")
		}
		copy(p, realPayload)
		PutBuffer2K(buf)
		return len(realPayload), addr, nil
	}
}

func (s *ServerObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// ... (Existing logic needs to check session to account for bytes written)
	// WriteTo is called by QUIC.
	// We need to find the session.
	sess := s.manager.GetSession(addr)
	if sess == nil {
		return 0, errors.New("no session")
	}
	
	return s.writeToInternal(p, addr, sess)
}

func (s *ServerObfuscatedPacketConn) writeToInternal(p []byte, addr net.Addr, sess *protocol.Session) (n int, err error) {
	// Use FEC Encoder
	
	fecSeq := sess.FECSeq
	sess.FECSeq++
	
	group := fecSeq / uint64(FECDataShards)
	index := int(fecSeq) % int(FECDataShards)
	
	// 1. Feed RAW payload to FEC Encoder
	parityShards, err := sess.FECEncoder.Encode(p)
	if err != nil {
		return 0, err
	}
	
	// 2. Send Data Packet (Wrapped)
	if err := s.sendWrapped(p, group, byte(index), addr, protocol.FlagData, sess); err != nil {
		return 0, err
	}
	
	// 3. Send Parity if any
	if parityShards != nil {
		for i, shard := range parityShards {
			// Parity Index starts at 10
			pIndex := byte(FECDataShards + i)
			if err := s.sendWrapped(shard, group, pIndex, addr, protocol.FlagFEC, sess); err != nil {
				// Ignore
			}
			PutBuffer2K(shard)
		}
	}
	
	return len(p), nil
}

func (s *ServerObfuscatedPacketConn) sendWrapped(p []byte, group uint64, index byte, addr net.Addr, flags uint8, sess *protocol.Session) error {
	wrapped := GetBuffer2K()
	if len(p) + 9 > cap(wrapped) {
		wrapped = make([]byte, len(p)+9)
	} else {
		wrapped = wrapped[:len(p)+9]
	}
	
	binary.BigEndian.PutUint64(wrapped[0:8], group)
	wrapped[8] = index
	copy(wrapped[9:], p)
	
	// Encrypt Packet
	seq := sess.IncrementSendSeq()
	encrypted, err := sess.EncryptPacket(wrapped, seq)
	if err != nil {
		PutBuffer2K(wrapped)
		return err
	}
	PutBuffer2K(wrapped) // Done with plaintext wrapper
	
	// Add Fake Header
	finalPkt := AddFakeHeader(encrypted, FakeHeaderRTP)
	
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		n, err := s.conn.WriteToUDP(finalPkt, udpAddr)
		if err == nil {
			s.manager.AddStats(sess, 0, uint64(n)) // Account wire bytes
		}
		return err
	}
	return net.ErrWriteToConnected
}

// AddStats helper
func (sm *SessionManager) AddStats(sess *protocol.Session, read, written uint64) {
	if sess.Token != "" {
		sess.AddStats(read, written)
	}
}

// GetSessionStats returns aggregated stats per token
func (s *ServerObfuscatedPacketConn) GetSessionStats() []map[string]interface{} {
	return s.manager.GetStats()
}

func (sm *SessionManager) GetStats() []map[string]interface{} {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	
	var results []map[string]interface{}
	for _, sess := range sm.sessions {
		if sess.Token == "" { continue }
		r, w := sess.GetAndResetStats()
		if r > 0 || w > 0 {
			results = append(results, map[string]interface{}{
				"token": sess.Token,
				"read":  r,
				"write": w,
			})
		}
	}
	return results
}

func (s *ServerObfuscatedPacketConn) Close() error {
	return s.conn.Close()
}

func (s *ServerObfuscatedPacketConn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *ServerObfuscatedPacketConn) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *ServerObfuscatedPacketConn) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

func (s *ServerObfuscatedPacketConn) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (s *ServerObfuscatedPacketConn) SetReadBuffer(bytes int) error {
	return s.conn.SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (s *ServerObfuscatedPacketConn) SetWriteBuffer(bytes int) error {
	return s.conn.SetWriteBuffer(bytes)
}
