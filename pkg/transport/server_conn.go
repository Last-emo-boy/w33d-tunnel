package transport

import (
	"errors"
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
}

func NewSessionManager(serverPriv []byte) *SessionManager {
	return &SessionManager{
		serverPriv: serverPriv,
		sessions:   make(map[string]*protocol.Session),
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
	sm.sessions[addr.String()] = sess
	return sess
}

// ServerObfuscatedPacketConn wraps a UDP listener and handles multiplexing for multiple clients.
// It intercepts Handshake packets and decrypts Data packets using the correct session.
type ServerObfuscatedPacketConn struct {
	conn    *net.UDPConn
	manager *SessionManager
}

func NewServerObfuscatedPacketConn(conn *net.UDPConn, serverPriv []byte) *ServerObfuscatedPacketConn {
	return &ServerObfuscatedPacketConn{
		conn:    conn,
		manager: NewSessionManager(serverPriv),
	}
}

func (s *ServerObfuscatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read raw UDP
	buf := make([]byte, 2048)
	nRead, addr, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	
	// Check Session
	sess := s.manager.GetSession(addr)
	
	// If no session, it MUST be a Handshake Initiation or we drop it.
	if sess == nil || sess.State == protocol.StateClosed {
		if sess == nil {
			sess = s.manager.CreateSession(addr)
		}
		
		// Try to process as Handshake
		resp, err := sess.ProcessHandshakeInitiation(buf[:nRead])
		if err == nil {
			// Handshake Success! Send Response.
			// Do NOT return packet to QUIC yet.
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				s.conn.WriteToUDP(resp, udpAddr)
			}
			
			// We consumed the packet. QUIC doesn't see it.
			// We need to loop to get the next packet.
			// But ReadFrom must block.
			return s.ReadFrom(p)
		} else {
			// Handshake failed? Maybe it's a data packet for a session we forgot?
			// Or just garbage. Drop.
			// logger.Debug("Handshake failed from %s: %v", addr, err)
			return s.ReadFrom(p)
		}
	}
	
	// Session Established. Decrypt.
	pkt, _, err := sess.DecryptPacket(buf[:nRead], 65535)
	if err != nil {
		// Decrypt failed. Drop.
		// Log a warning if needed, but not too verbose
		// logger.Warn("Decrypt failed from %s: %v", addr, err)
		return s.ReadFrom(p)
	}
	
	// Copy payload (QUIC packet) to p
	if len(pkt.Payload) > len(p) {
		return 0, addr, errors.New("buffer too small")
	}
	copy(p, pkt.Payload)
	return len(pkt.Payload), addr, nil
}

func (s *ServerObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Find Session
	sess := s.manager.GetSession(addr)
	if sess == nil {
		// We are trying to write to an unknown address?
		// QUIC might be responding to a new client?
		// But we should have created session in ReadFrom.
		return 0, errors.New("session not found for write")
	}
	
	// Encrypt
	header := protocol.Header{
		Flags:      protocol.FlagData,
		PayloadLen: uint16(len(p)),
	}
	
	seq := sess.IncrementSendSeq()
	nonce := sess.ConstructNonce(sess.SendNonceSalt, seq)
	
	encPkt, err := protocol.BuildDataPacketWithSeq(sess.SendKey, nonce, header, p, seq, sess.SendHeaderKey)
	if err != nil {
		return 0, err
	}
	
	_, err = s.conn.WriteTo(encPkt, addr)
	if err != nil {
		return 0, err
	}
	
	return len(p), nil
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
