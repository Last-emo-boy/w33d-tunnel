package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func buildServerDatagram(flowID uint32, sourceAddr string, payload []byte) []byte {
	addrBytes := []byte(sourceAddr)
	data := make([]byte, 5+len(addrBytes)+len(payload))
	binary.BigEndian.PutUint32(data[0:4], flowID)
	data[4] = byte(len(addrBytes))
	copy(data[5:], addrBytes)
	copy(data[5+len(addrBytes):], payload)
	return data
}

func extractSocksPayload(pkt []byte) ([]byte, error) {
	// SOCKS5 UDP Header:
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
	if len(pkt) < 4 {
		return nil, fmt.Errorf("packet too short")
	}
	if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		return nil, fmt.Errorf("invalid socks header")
	}

	pos := 4
	switch pkt[3] {
	case 1: // IPv4
		if len(pkt) < pos+4+2 {
			return nil, fmt.Errorf("invalid ipv4 packet")
		}
		pos += 4 + 2
	case 3: // Domain
		if len(pkt) < pos+1 {
			return nil, fmt.Errorf("invalid domain packet")
		}
		l := int(pkt[pos])
		pos++
		if len(pkt) < pos+l+2 {
			return nil, fmt.Errorf("invalid domain length")
		}
		pos += l + 2
	case 4: // IPv6
		if len(pkt) < pos+16+2 {
			return nil, fmt.Errorf("invalid ipv6 packet")
		}
		pos += 16 + 2
	default:
		return nil, fmt.Errorf("unsupported atyp")
	}

	return pkt[pos:], nil
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp failed: %v", err)
	}
	return conn
}

func readAndAssertPayload(t *testing.T, conn *net.UDPConn, expected []byte) {
	t.Helper()
	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read udp failed: %v", err)
	}
	payload, err := extractSocksPayload(buf[:n])
	if err != nil {
		t.Fatalf("extract payload failed: %v", err)
	}
	if !bytes.Equal(payload, expected) {
		t.Fatalf("expected payload %q, got %q", expected, payload)
	}
}

func TestRouteDatagramIsolationAcrossFlows(t *testing.T) {
	c := NewClient(Config{})

	serverSideFlow1 := mustListenUDP(t)
	defer serverSideFlow1.Close()
	serverSideFlow2 := mustListenUDP(t)
	defer serverSideFlow2.Close()

	clientEndpoint1 := mustListenUDP(t)
	defer clientEndpoint1.Close()
	clientEndpoint2 := mustListenUDP(t)
	defer clientEndpoint2.Close()

	flow1 := uint32(1001)
	flow2 := uint32(1002)

	c.udpFlows.Store(flow1, serverSideFlow1)
	c.udpFlows.Store(flow2, serverSideFlow2)
	c.udpAddrs.Store(flow1, clientEndpoint1.LocalAddr())
	c.udpAddrs.Store(flow2, clientEndpoint2.LocalAddr())

	sharedSource := "8.8.8.8:53"
	payload1 := []byte("flow-1-data")
	payload2 := []byte("flow-2-data")

	for i := 0; i < 10; i++ {
		if err := c.routeDatagram(buildServerDatagram(flow1, sharedSource, payload1)); err != nil {
			t.Fatalf("route flow1 failed: %v", err)
		}
		if err := c.routeDatagram(buildServerDatagram(flow2, sharedSource, payload2)); err != nil {
			t.Fatalf("route flow2 failed: %v", err)
		}
	}

	for i := 0; i < 10; i++ {
		readAndAssertPayload(t, clientEndpoint1, payload1)
		readAndAssertPayload(t, clientEndpoint2, payload2)
	}
}
