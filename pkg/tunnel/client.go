package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// HandleSOCKS5 starts a SOCKS5 server on localAddr and forwards to tunnel.
func StartSOCKS5(localAddr string, sess *ReliableSession, tunnelConn *net.UDPConn, sm *StreamMap) error {
	l, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 Proxy listening on %s", localAddr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Println("SOCKS5 Accept error:", err)
				continue
			}
			go handleSocksConnection(conn, sess, tunnelConn, sm)
		}
	}()

	return nil
}

func handleSocksConnection(conn net.Conn, sess *ReliableSession, tunnelConn *net.UDPConn, sm *StreamMap) {
	defer conn.Close()

	// SOCKS5 Handshake
	// 1. Version identifier/method selection
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return // Not SOCKS5
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	// Reply: No Auth (0x00)
	conn.Write([]byte{5, 0})

	// 2. Request details
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	
	cmd := buf[1]
	
	// Address
	var targetAddr string
	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		ip := net.IP(buf[:4]).String()
		targetAddr = ip
	case 3: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetAddr = string(domainBuf)
	case 4: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		ip := net.IP(buf[:16]).String()
		targetAddr = fmt.Sprintf("[%s]", ip)
	default:
		return
	}

	// Port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", targetAddr, port)

	// Assign Stream ID
	streamID := sm.NextID()
	sm.Add(streamID, conn)
	defer sm.Remove(streamID)
	
	if cmd == 1 { // CONNECT
		// Send Connect Frame
		frame := &Frame{
			StreamID: streamID,
			Cmd:      CmdConnect,
			Data:     []byte(target),
		}

		pkt, err := SendFrame(sess, frame)
		if err != nil {
			log.Println("Build Connect Packet fail:", err)
			return
		}
		tunnelConn.Write(pkt)
		
		conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // Success, BIND 0.0.0.0:0
		
		// Forward Data Loop (Local -> Tunnel)
		fwdBuf := make([]byte, 4096)
		for {
			n, err := conn.Read(fwdBuf)
			if err != nil {
				break
			}
			
			dataFrame := &Frame{
				StreamID: streamID,
				Cmd:      CmdData,
				Data:     fwdBuf[:n],
			}
			pkt, err := SendFrame(sess, dataFrame)
			if err != nil {
				break
			}
			tunnelConn.Write(pkt)
		}
	} else if cmd == 3 { // UDP ASSOCIATE
		handleUDPAssociate(conn, sess, tunnelConn, sm, streamID, target)
	}
	
	// Send Close
	closeFrame := &Frame{StreamID: streamID, Cmd: CmdClose}
	if pkt, err := SendFrame(sess, closeFrame); err == nil {
		tunnelConn.Write(pkt)
	}
}

func handleUDPAssociate(conn net.Conn, sess *ReliableSession, tunnelConn *net.UDPConn, sm *StreamMap, streamID uint32, target string) {
	// 1. Setup UDP Listener
	// Bind to random port
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	defer udpConn.Close()
	
	// Get assigned port
	_, portStr, _ := net.SplitHostPort(udpConn.LocalAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	
	// 2. Reply to SOCKS5 Client with BND.ADDR/PORT
	// BND.ADDR = 0.0.0.0 (or local IP), PORT = assigned port
	resp := []byte{5, 0, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port & 0xff)}
	conn.Write(resp)
	
	// 3. Keep TCP connection alive (if client closes, we close UDP)
	// We also need to forward packets.
	
	// Let's create a wrapper.
	
	wrapper := &SocksUDPWrapper{
		Listener: udpConn,
	}
	
	// Overwrite the TCP conn in SM with UDP wrapper?
	// No, TCP conn must stay open.
	// We need TWO entries? Or separate map?
	// Reuse StreamID?
	// The Tunnel Frame comes with StreamID.
	// If we use same StreamID for UDP, we conflict with TCP control stream.
	// But SOCKS5 UDP is associated with the TCP stream.
	// If we use the same ID, when main loop gets CmdUDP, it looks up StreamID.
	// It gets the TCP connection.
	// That's wrong. We want the UDP listener.
	// So we need a NEW StreamID for UDP?
	// OR we change StreamMap to support distinct types?
	// OR `HandlePacket` checks Cmd. If CmdUDP, it uses a different map?
	
	// Simpler: The SOCKS5 protocol associates UDP with TCP.
	// But over the tunnel, we can just use the same StreamID if we handle CmdUDP differently.
	// In `client/main.go`, the handler:
	/*
		switch frame.Cmd {
		case tunnel.CmdData:
			conn, ok := sm.Get(frame.StreamID) ...
		case tunnel.CmdUDP:
			// Handle UDP
		}
	*/
	// We need to store the UDP wrapper somewhere accessible by StreamID.
	// Let's add `GetUDP(id)` to StreamMap or a global map.
	// Let's extend StreamMap.
	
	sm.AddUDP(streamID, wrapper)
	defer sm.RemoveUDP(streamID)
	
	// UDP Forwarding Loop
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			
			// Parse SOCKS5 UDP Header
			// [RSV 2][FRAG 1][ATYP 1][DST...][DATA]
			if n < 10 {
				continue
			}
			
			// Store Client Address
			wrapper.SetClientAddr(addr)
			
			// We just wrap the whole payload in CmdUDP frame
			// But wait, the Server needs to know where to send.
			// The SOCKS5 UDP header contains the destination.
			// So we send the whole SOCKS5 UDP packet as payload.
			// The Server will parse it.
			
			frame := &Frame{
				StreamID: streamID,
				Cmd:      CmdUDP,
				Data:     buf[:n],
			}
			
			// Send Unreliable
			pkt, err := sess.SendUnreliableData(frame.Marshal())
			if err == nil {
				tunnelConn.Write(pkt)
			}
		}
	}()
	
	// Block on TCP read (Keepalive)
	dummy := make([]byte, 1)
	for {
		_, err := conn.Read(dummy)
		if err != nil {
			break
		}
	}
}

type SocksUDPWrapper struct {
	Listener   *net.UDPConn
	ClientAddr *net.UDPAddr // Last seen client address
	Lock       sync.Mutex // To protect addr
}

func (w *SocksUDPWrapper) Write(b []byte) (int, error) {
	w.Lock.Lock()
	addr := w.ClientAddr
	w.Lock.Unlock()
	
	if addr == nil {
		return 0, nil // Drop if we don't know where to send
	}
	return w.Listener.WriteToUDP(b, addr)
}

func (w *SocksUDPWrapper) SetClientAddr(addr *net.UDPAddr) {
	w.Lock.Lock()
	w.ClientAddr = addr
	w.Lock.Unlock()
}
