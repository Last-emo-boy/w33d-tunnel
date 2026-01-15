package transport

import (
	"context"
	"errors"
	"net"
	"time"
	"w33d-tunnel/pkg/crypto"
	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/protocol"

	quic "github.com/quic-go/quic-go"
)

// ClientDialer handles the UDP Handshake and then upgrades to QUIC.
type ClientDialer struct {
	ServerAddr *net.UDPAddr
	ServerPub  []byte
}

func NewClientDialer(serverAddr string, serverPub []byte) (*ClientDialer, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	return &ClientDialer{
		ServerAddr: addr,
		ServerPub:  serverPub,
	}, nil
}

func (d *ClientDialer) Dial(ctx context.Context) (any, error) {
	// 1. Listen UDP (Unconnected) to allow WriteTo
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	// 2. Perform Handshake
	priv, _, _ := crypto.GenerateKeyPair()
	sess := protocol.NewSession(protocol.RoleClient, priv, d.ServerPub)
	
	initPacket, err := sess.CreateHandshakeInitiation()
	if err != nil {
		conn.Close()
		return nil, err
	}
	
	if _, err := conn.WriteToUDP(initPacket, d.ServerAddr); err != nil {
		conn.Close()
		return nil, err
	}
	
	// Read Response
	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		conn.Close()
		return nil, errors.New("handshake timeout")
	}
	
	if err := sess.ProcessHandshakeResponse(buf[:n]); err != nil {
		conn.Close()
		return nil, err
	}
	
	conn.SetReadDeadline(time.Time{})
	logger.Info("Handshake Successful. Upgrading to QUIC...")
	
	// 3. Wrap in ObfuscatedConn
	obfsConn := NewObfuscatedPacketConn(conn, sess)
	
	// 4. Dial QUIC
	tlsConfig := crypto.GenerateTLSConfig()
	tlsConfig.InsecureSkipVerify = true // Trust the Outer Layer security
	tlsConfig.NextProtos = []string{"w33d-tunnel"}
	
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	
	return quic.Dial(ctx, obfsConn, d.ServerAddr, tlsConfig, quicConfig)
}
