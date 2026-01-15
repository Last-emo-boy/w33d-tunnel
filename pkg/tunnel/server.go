package tunnel

import (
	"fmt"
	"net"
	"time"
	"w33d-tunnel/pkg/logger"
)

// HandleServerFrame processes incoming frames on the server side.
func HandleServerFrame(sess *ReliableSession, conn *net.UDPConn, frame *Frame, sm *StreamMap, remoteAddr net.Addr) {
	switch frame.Cmd {
	case CmdConnect:
		target := string(frame.Data)
		// Dial Target
		logger.Debug("Proxy connecting to %s for Stream %d", target, frame.StreamID)
		targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			logger.Error("Dial failed to %s: %v", target, err)
			// Send ConnectFail?
			// For now just ignore or close.
			closeFrame := &Frame{StreamID: frame.StreamID, Cmd: CmdClose}
			sendFrameToAddr(sess, conn, closeFrame, remoteAddr)
			return
		}
		logger.Debug("Connected to %s for Stream %d", target, frame.StreamID)

		sm.Add(frame.StreamID, targetConn)

		// Start Reader from Target -> Tunnel
		go func() {
			defer func() {
				sm.Remove(frame.StreamID)
				targetConn.Close()
				closeFrame := &Frame{StreamID: frame.StreamID, Cmd: CmdClose}
				sendFrameToAddr(sess, conn, closeFrame, remoteAddr)
			}()

			buf := make([]byte, 4096)
			for {
				n, err := targetConn.Read(buf)
				if err != nil {
					break
				}

				dataFrame := &Frame{
					StreamID: frame.StreamID,
					Cmd:      CmdData,
					Data:     buf[:n],
				}

				// Retry loop for flow control
				for {
					if err := sendFrameToAddr(sess, conn, dataFrame, remoteAddr); err != nil {
						// Simple check: is it window full?
						// For now, assume any error from SendFrame might be recoverable if we wait,
						// unless it's a fatal session error.
						// But SendFrame mainly errors on Window Full.
						// TODO: Check error type strictly.
						time.Sleep(1 * time.Millisecond)
						continue
					}
					break
				}
			}
		}()

	case CmdData:
		targetConn, ok := sm.Get(frame.StreamID)
		if ok {
			targetConn.Write(frame.Data)
		} else {
			// Stream closed or not found
		}

	case CmdClose:
		targetConn, ok := sm.Get(frame.StreamID)
		if ok {
			targetConn.Close()
			sm.Remove(frame.StreamID)
		}
		// Also check UDP
		if _, ok := sm.GetUDP(frame.StreamID); ok {
			sm.RemoveUDP(frame.StreamID)
		}

	case CmdUDP:
		// Payload: SOCKS5 UDP Packet [RSV][FRAG][ATYP][DST][DATA]
		// We need to parse destination and send UDP packet.
		// SOCKS5 UDP is stateless (datagrams).
		// But we need to receive replies.
		// So we need a UDP socket.
		// Should we create one UDP socket per StreamID? Yes.
		// And we reuse it for subsequent packets from same StreamID.
		
		wrapper, ok := sm.GetUDP(frame.StreamID)
		if !ok {
			// Create new UDP socket for this stream
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return
			}
			
			wrapper = &SocksUDPWrapper{
				Listener: udpConn,
			}
			sm.AddUDP(frame.StreamID, wrapper)
			
			// Start Reader for Replies
			go func() {
				defer func() {
					sm.RemoveUDP(frame.StreamID)
					udpConn.Close()
				}()
				
				buf := make([]byte, 65535)
				for {
					n, rAddr, err := udpConn.ReadFromUDP(buf)
					if err != nil {
						break
					}
					
					// We need to wrap it back in SOCKS5 UDP Header?
					// Yes, Client expects SOCKS5 header.
					// [RSV][FRAG][ATYP][SRC][DATA]
					
					// Construct header based on rAddr
					header := make([]byte, 0, 262)
					header = append(header, 0, 0, 0) // RSV, FRAG
					
					ip4 := rAddr.IP.To4()
					if ip4 != nil {
						header = append(header, 1) // ATYP IPv4
						header = append(header, ip4...)
					} else {
						header = append(header, 4) // ATYP IPv6
						header = append(header, rAddr.IP...)
					}
					
					port := rAddr.Port
					header = append(header, byte(port>>8), byte(port&0xff))
					
					payload := append(header, buf[:n]...)
					
					respFrame := &Frame{
						StreamID: frame.StreamID,
						Cmd:      CmdUDP,
						Data:     payload,
					}
					
			// Send Unreliable
			pkt, err := sess.SendUnreliableData(respFrame.Marshal())
			if err == nil {
				conn.WriteTo(pkt, remoteAddr)
			}
		}
	}()
}

// Parse Header from Frame Data
data := frame.Data
		if len(data) < 4 {
			return
		}
		
		// Skip RSV(2), FRAG(1)
		atyp := data[3]
		var dstAddr *net.UDPAddr
		var payload []byte
		
		offset := 4
		switch atyp {
		case 1: // IPv4
			if len(data) < offset+4+2 { return }
			ip := net.IP(data[offset : offset+4])
			offset += 4
			port := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			dstAddr = &net.UDPAddr{IP: ip, Port: port}
			payload = data[offset:]
		case 3: // Domain
			if len(data) < offset+1 { return }
			addrLen := int(data[offset])
			offset++
			if len(data) < offset+addrLen+2 { return }
			domain := string(data[offset : offset+addrLen])
			offset += addrLen
			port := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			
			// Resolve Domain
			resolved, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", domain, port))
			if err != nil {
				return
			}
			dstAddr = resolved
			payload = data[offset:]
		case 4: // IPv6
			if len(data) < offset+16+2 { return }
			ip := net.IP(data[offset : offset+16])
			offset += 16
			port := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			dstAddr = &net.UDPAddr{IP: ip, Port: port}
			payload = data[offset:]
		default:
			return
		}
		
		// Send to Destination
		wrapper.Listener.WriteToUDP(payload, dstAddr)
	}
}

func sendFrameToAddr(sess *ReliableSession, conn *net.UDPConn, frame *Frame, addr net.Addr) error {
	pkt, err := SendFrame(sess, frame)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(pkt, addr)
	return err
}
