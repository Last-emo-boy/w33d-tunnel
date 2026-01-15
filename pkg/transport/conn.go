package transport

import (
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
}

func NewObfuscatedPacketConn(conn net.PacketConn, session *protocol.Session) *ObfuscatedPacketConn {
	return &ObfuscatedPacketConn{
		conn:    conn,
		session: session,
		role:    session.Role,
	}
}

// ReadFrom reads a packet from the connection, decrypting and de-obfuscating it.
func (c *ObfuscatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read raw encrypted packet
	buf := make([]byte, 2048) // MTU + Overhead
	nRead, addr, err := c.conn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	// Decrypt
	// Note: We reuse ParseDataPacket logic but without the Header/Frame structure?
	// Wait, QUIC expects its own packet format.
	// We are encapsulating the WHOLE QUIC packet as the "Payload" of our custom protocol.
	// So: [Header][Encrypted QUIC Packet][Padding][Tag]
	
	// Use Session.DecryptPacket
	// This handles the header parsing and decryption.
	pkt, _, err := c.session.DecryptPacket(buf[:nRead], 65535)
	if err != nil {
		// Decryption failed. Drop packet.
		// Return 0, nil? Or error?
		// If we return error, QUIC might close connection.
		// Better to just drop it silently (return 0, nil, nil is invalid?)
		// We should loop until we get a valid packet?
		// But ReadFrom must block.
		// Let's recursively call ReadFrom?
		// Stack overflow risk.
		// Iterative loop.
		return c.ReadFrom(p) // Simple tail recursion (Go doesn't optimize, but depth is low usually)
	}

	// pkt.Payload contains the decrypted QUIC packet.
	if len(pkt.Payload) > len(p) {
		return 0, addr, net.ErrWriteToConnected
	}
	
	copy(p, pkt.Payload)
	return len(pkt.Payload), addr, nil
}

// WriteTo encrypts and obfuscates the packet, then writes it to the underlying connection.
func (c *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Encrypt
	// p is the QUIC packet.
	// We wrap it in our protocol.Header
	
	header := protocol.Header{
		Flags:      protocol.FlagData, // Mark as Data
		PayloadLen: uint16(len(p)),
	}
	
	// SendSeq management is handled inside Session for Nonce generation
	seq := c.session.IncrementSendSeq()
	nonce := c.session.ConstructNonce(c.session.SendNonceSalt, seq)
	
	// Build packet with obfuscation and padding
	// Note: BuildDataPacketWithSeq adds random padding (0-128 bytes) automatically now.
	encPkt, err := protocol.BuildDataPacketWithSeq(c.session.SendKey, nonce, header, p, seq, c.session.SendHeaderKey)
	if err != nil {
		return 0, err
	}
	
	// Write raw
	_, err = c.conn.WriteTo(encPkt, addr)
	if err != nil {
		return 0, err
	}
	
	// Return len(p) so QUIC thinks it wrote that many bytes
	return len(p), nil
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
