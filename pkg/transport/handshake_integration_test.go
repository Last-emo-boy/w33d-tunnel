package transport

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"w33d-tunnel/pkg/crypto"
	"w33d-tunnel/pkg/protocol"
)

type readResult struct {
	payload []byte
	addr    net.Addr
	err     error
}

func startServerReadOnce(conn *ServerObfuscatedPacketConn) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			ch <- readResult{err: err}
			return
		}
		ch <- readResult{
			payload: append([]byte(nil), buf[:n]...),
			addr:    addr,
		}
	}()
	return ch
}

func waitMetricAtLeast(t *testing.T, conn *ServerObfuscatedPacketConn, key string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m := conn.GetMetrics()
		if m[key] >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("metric %s did not reach %d, got %d", key, want, conn.GetMetrics()[key])
}

func newHandshakeServer(t *testing.T, tokens map[string]QuotaInfo) (*ServerObfuscatedPacketConn, *net.UDPAddr, []byte, func()) {
	t.Helper()

	serverPriv, serverPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate server keypair failed: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp failed: %v", err)
	}

	conn := NewServerObfuscatedPacketConn(udpConn, serverPriv, 0)
	conn.UpdateValidTokens(tokens)

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = conn.Close()
			close(conn.manager.stopChan)
		})
	}
	t.Cleanup(cleanup)

	addr := conn.LocalAddr().(*net.UDPAddr)
	return conn, addr, serverPub, cleanup
}

func newHandshakeClient(t *testing.T, serverPub []byte, token string) (*net.UDPConn, *protocol.Session) {
	t.Helper()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp failed: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	clientPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate client keypair failed: %v", err)
	}

	sess := protocol.NewSession(protocol.RoleClient, clientPriv, serverPub)
	sess.Token = token
	return clientConn, sess
}

func doClientHandshake(t *testing.T, clientConn *net.UDPConn, sess *protocol.Session, serverAddr *net.UDPAddr) {
	t.Helper()

	initPkt, err := sess.CreateHandshakeInitiation()
	if err != nil {
		t.Fatalf("create handshake initiation failed: %v", err)
	}

	if _, err := clientConn.WriteToUDP(AddFakeHeader(initPkt, FakeHeaderRTP), serverAddr); err != nil {
		t.Fatalf("send initiation failed: %v", err)
	}

	respBuf := make([]byte, 4096)
	if err := clientConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	n, _, err := clientConn.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read handshake response failed: %v", err)
	}
	rawResp := RemoveFakeHeader(respBuf[:n], FakeHeaderRTP)
	if len(rawResp) == 0 {
		t.Fatal("invalid handshake response header")
	}
	if err := sess.ProcessHandshakeResponse(rawResp); err != nil {
		t.Fatalf("process handshake response failed: %v", err)
	}
}

func TestHandshakeIntegrationSuccess(t *testing.T) {
	serverConn, serverAddr, serverPub, _ := newHandshakeServer(t, map[string]QuotaInfo{
		"ok-token": {
			QuotaBytes: 1024 * 1024,
			UsedBytes:  0,
			MaxIPs:     1,
		},
	})

	readCh := startServerReadOnce(serverConn)
	clientConn, sess := newHandshakeClient(t, serverPub, "ok-token")
	doClientHandshake(t, clientConn, sess, serverAddr)

	payload := []byte("handshake-data-ok")
	wrapped := make([]byte, 9+len(payload))
	copy(wrapped[9:], payload)
	seq := sess.IncrementSendSeq()
	encrypted, err := sess.EncryptPacket(wrapped, seq)
	if err != nil {
		t.Fatalf("encrypt data packet failed: %v", err)
	}
	if _, err := clientConn.WriteToUDP(AddFakeHeader(encrypted, FakeHeaderRTP), serverAddr); err != nil {
		t.Fatalf("send encrypted data failed: %v", err)
	}

	select {
	case res := <-readCh:
		if res.err != nil {
			t.Fatalf("server read failed: %v", res.err)
		}
		if !bytes.Equal(res.payload, payload) {
			t.Fatalf("unexpected payload: got %q want %q", res.payload, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not return decrypted payload in time")
	}

	waitMetricAtLeast(t, serverConn, "sessions_established_total", 1)
	metrics := serverConn.GetMetrics()
	if metrics["handshake_reject_invalid_total"] != 0 {
		t.Fatalf("unexpected invalid reject counter: %d", metrics["handshake_reject_invalid_total"])
	}
}

func TestHandshakeIntegrationRejectsInvalidToken(t *testing.T) {
	serverConn, serverAddr, serverPub, cleanup := newHandshakeServer(t, map[string]QuotaInfo{
		"known-token": {
			QuotaBytes: 1024 * 1024,
		},
	})

	readCh := startServerReadOnce(serverConn)
	clientConn, sess := newHandshakeClient(t, serverPub, "bad-token")

	initPkt, err := sess.CreateHandshakeInitiation()
	if err != nil {
		t.Fatalf("create handshake initiation failed: %v", err)
	}
	if _, err := clientConn.WriteToUDP(AddFakeHeader(initPkt, FakeHeaderRTP), serverAddr); err != nil {
		t.Fatalf("send initiation failed: %v", err)
	}

	respBuf := make([]byte, 4096)
	if err := clientConn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	if _, _, err := clientConn.ReadFromUDP(respBuf); err == nil {
		t.Fatal("expected timeout because invalid token should not receive handshake response")
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected timeout error, got %v", err)
		}
	}

	waitMetricAtLeast(t, serverConn, "handshake_reject_invalid_total", 1)
	metrics := serverConn.GetMetrics()
	if metrics["sessions_established_total"] != 0 {
		t.Fatalf("expected no established sessions, got %d", metrics["sessions_established_total"])
	}

	cleanup()
	select {
	case <-readCh:
	case <-time.After(1 * time.Second):
		t.Fatal("server reader did not stop after close")
	}
}
