package tunnel

import (
	"net"
	"sync"
	"w33d-tunnel/pkg/protocol"
)

// StreamMap manages mapping between StreamID and net.Conn
type StreamMap struct {
	sync.RWMutex
	conns    map[uint32]net.Conn
	udpConns map[uint32]*SocksUDPWrapper // Separate map for UDP listeners
	nextID   uint32
}

func NewStreamMap() *StreamMap {
	return &StreamMap{
		conns:    make(map[uint32]net.Conn),
		udpConns: make(map[uint32]*SocksUDPWrapper),
		nextID:   1, // 0 reserved?
	}
}

func (m *StreamMap) Add(id uint32, conn net.Conn) {
	m.Lock()
	defer m.Unlock()
	m.conns[id] = conn
}

func (m *StreamMap) AddUDP(id uint32, wrapper *SocksUDPWrapper) {
	m.Lock()
	defer m.Unlock()
	m.udpConns[id] = wrapper
}

func (m *StreamMap) Get(id uint32) (net.Conn, bool) {
	m.RLock()
	defer m.RUnlock()
	conn, ok := m.conns[id]
	return conn, ok
}

func (m *StreamMap) GetUDP(id uint32) (*SocksUDPWrapper, bool) {
	m.RLock()
	defer m.RUnlock()
	wrapper, ok := m.udpConns[id]
	return wrapper, ok
}

func (m *StreamMap) Remove(id uint32) {
	m.Lock()
	defer m.Unlock()
	delete(m.conns, id)
}

func (m *StreamMap) RemoveUDP(id uint32) {
	m.Lock()
	defer m.Unlock()
	delete(m.udpConns, id)
}

func (m *StreamMap) NextID() uint32 {
	m.Lock()
	defer m.Unlock()
	id := m.nextID
	m.nextID++
	return id
}

// SendFrame encapsulates sending a frame over the tunnel using ARQ.
func SendFrame(sess *ReliableSession, frame *Frame) ([]byte, error) {
	return sess.SendData(frame.Marshal())
}

// BuildTunnelPacket is a helper to build encrypted packet from frame.
// Deprecated: Use SendFrame with ReliableSession
func BuildTunnelPacket(sess *protocol.Session, frame *Frame) ([]byte, error) {
	payload := frame.Marshal()
	header := protocol.Header{
		Flags:      protocol.FlagData,
		PayloadLen: uint16(len(payload)),
	}

	// sess.Lock()
	seq := sess.IncrementSendSeq()
	nonce := sess.ConstructNonce(sess.SendNonceSalt, seq)
	// sess.Unlock()

	return protocol.BuildDataPacketWithSeq(sess.SendKey, nonce, header, payload, seq, sess.SendHeaderKey)
}
