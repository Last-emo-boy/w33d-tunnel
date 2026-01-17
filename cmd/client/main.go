package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/transport"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/proxy"
)

// Global Variables for System Proxy Cleanup
var globalProxyEnabled bool

type QUICConnection interface {
	OpenStreamSync(context.Context) (*quic.Stream, error)
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CloseWithError(quic.ApplicationErrorCode, string) error
}

func main() {
	serverAddr := flag.String("server", "", "Server address (Optional if using subscription)")
	serverPubStr := flag.String("pubkey", "", "Server Static Public Key (Optional if using subscription)")
	socksAddr := flag.String("socks", ":1080", "SOCKS5 Listen Address")
	globalProxy := flag.Bool("global", false, "Enable Global System Proxy (Windows Only)")
	verbose := flag.Bool("v", false, "Verbose logging")
	simLoss := flag.Int("sim-loss", 0, "Simulate Packet Loss % (0-100)")
	token := flag.String("token", "", "User Token for Authentication (or Subscription URL)")
	subURL := flag.String("subscribe", "", "Subscription URL (e.g. http://cloud.w33d.xyz/api/subscribe?token=...)")
	
	flag.Parse()
	
	if *verbose {
		logger.SetLevel(logger.LevelDebug)
	}
	
	// Handle Subscription
	if *subURL != "" {
		// Fetch config from Subscription URL
		// For simplicity, we just pick the first node.
		// Subscription returns JSON: { "nodes": [ { "addr": "...", "pub_key": "..." } ] }
		
		logger.Info("Fetching subscription from %s", *subURL)
		resp, err := http.Get(*subURL)
		if err != nil {
			logger.Error("Failed to fetch subscription: %v", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		var config struct {
			Nodes []struct {
				Addr   string `json:"addr"`
				PubKey string `json:"pub_key"`
			} `json:"nodes"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
			logger.Error("Failed to parse subscription: %v", err)
			os.Exit(1)
		}
		
		if len(config.Nodes) == 0 {
			logger.Error("No nodes available in subscription")
			os.Exit(1)
		}
		
			// Pick first valid node
		var selectedNode *struct {
			Addr   string `json:"addr"`
			PubKey string `json:"pub_key"`
		}

		for _, n := range config.Nodes {
			// Validate PubKey
			if _, err := hex.DecodeString(n.PubKey); err == nil && len(n.PubKey) > 0 {
				selectedNode = &n
				break
			} else {
				logger.Warn("Skipping node with invalid pubkey: %s", n.Addr)
			}
		}

		if selectedNode == nil {
			logger.Error("No valid nodes found in subscription")
			os.Exit(1)
		}
		
		*serverAddr = selectedNode.Addr
		*serverPubStr = selectedNode.PubKey
		
		logger.Info("Selected Node: %s (Pub: %s...)", selectedNode.Addr, selectedNode.PubKey[:8])

	// Extract token from URL if not provided?
		// Usually token is part of URL query `?token=...`
		// We need to pass this token to the handshake too?
		// Yes, handshake requires token.
		// If user provided `-subscribe http://.../api/subscribe?token=XYZ`, we should extract XYZ.
		if *token == "" {
			u, _ := http.NewRequest("GET", *subURL, nil)
			q := u.URL.Query()
			*token = q.Get("token")
		}
	}
	
	if *serverAddr == "" || *serverPubStr == "" {
		logger.Error("Please provide --server/--pubkey OR --subscribe")
		flag.Usage()
		os.Exit(1)
	}
	
	_, err := hex.DecodeString(*serverPubStr)
	if err != nil {
		logger.Error("Invalid public key hex")
		os.Exit(1)
	}

	if *simLoss > 0 {
		logger.Info("Packet Loss Simulation Enabled: %d%%", *simLoss)
	}

	// 1. Initialize Client Dialer (Handles Handshake + Obfuscation)
	dialer, err := transport.NewClientDialer(*serverAddr, *serverPubStr, *simLoss, *token)
	if err != nil {
		logger.Error("Failed to create dialer: %v", err)
		os.Exit(1)
	}

	// 2. Dial QUIC Session (Multiplexed Connection)
	logger.Info("Connecting to server via QUIC...")
	q, err := dialer.Dial(context.Background())
	if err != nil {
		logger.Error("QUIC Dial failed: %v", err)
		os.Exit(1)
	}
	quicSess := q.(QUICConnection)
	logger.Info("QUIC Session Established!")

	// 3. Start SOCKS5 Server
	// We handle incoming TCP connections and open new QUIC streams for them.
	
	// Start Datagram Receiver
	go handleDatagrams(quicSess)
	
	// Start HTTP Proxy for Global Mode
	if *globalProxy {
		go startHTTPProxy(":1081", *socksAddr)
		time.Sleep(500 * time.Millisecond)
		logger.Info("Enabling Global System Proxy...")
		if err := enableSystemProxy(*socksAddr); err != nil {
			logger.Error("Failed to set system proxy: %v", err)
		} else {
			globalProxyEnabled = true
			defer disableSystemProxy()
			
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-c
				disableSystemProxy()
				os.Exit(0)
			}()
		}
	}

	startSOCKS5Server(*socksAddr, quicSess)
}

func startSOCKS5Server(addr string, s any) {
	sess := s.(QUICConnection)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("SOCKS5 Listen failed: %v", err)
		os.Exit(1)
	}
	logger.Info("SOCKS5 Proxy listening on %s", addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Error("Accept error: %v", err)
			continue
		}

		go handleSocksConnection(conn, sess)
	}
}

func handleSocksConnection(conn net.Conn, s any) {
	sess := s.(QUICConnection)
	defer conn.Close()

	// Perform SOCKS5 Handshake locally
	// ... (Simplified SOCKS5 Logic) ...
	// 1. Auth Negotiation
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }
	if buf[0] != 5 { return }
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil { return }
	conn.Write([]byte{5, 0}) // No Auth

	// 2. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	cmd := buf[1]
	
	if cmd == 3 { // UDP ASSOCIATE
		// SOCKS5 UDP Associate Logic
		// 1. Client asks to associate UDP
		// 2. We reply with the address/port we are listening on (for UDP)
		// 3. Client sends UDP packets to that address with header
		// 4. We encap and send via QUIC Datagram
		
		// For simplicity, let's bind a new UDP socket for this client?
		// Or share one?
		// SOCKS5 standard: "The server binds to a port... and sends BND.PORT to client"
		
		udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer udpListener.Close()
		
		lAddr := udpListener.LocalAddr().(*net.UDPAddr)
		
		// Reply Success (BND.ADDR = 127.0.0.1, BND.PORT = assigned)
		// IP
		resp := []byte{5, 0, 0, 1, 127, 0, 0, 1}
		// Port
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(lAddr.Port))
		resp = append(resp, portBuf...)
		
		conn.Write(resp)
		
		// Start UDP Relay Loop
		// We need to keep the TCP connection open (Heartbeat)
		// If TCP closes, we close UDP.
		
		go handleUDPRelay(udpListener, sess)
		
		// Block on TCP until closed
		io.Copy(io.Discard, conn)
		return
	}
	
	if cmd != 1 { // Only CONNECT supported (and now UDP ASSOCIATE)
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // Cmd unsupported
		return
	}

	// Parse Address
	var target string
	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
		target = net.IP(buf[:4]).String()
	case 3: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil { return }
		dLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dLen]); err != nil { return }
		target = string(buf[:dLen])
	case 4: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil { return }
		target = fmt.Sprintf("[%s]", net.IP(buf[:16]).String())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }
	port := int(buf[0])<<8 | int(buf[1])
	targetAddr := fmt.Sprintf("%s:%d", target, port)

	// 3. Open QUIC Stream
	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		logger.Error("Failed to open QUIC stream: %v", err)
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // Server Error
		return
	}
	defer stream.Close()

	// 4. Send Target Address to Server
	// Protocol: [Len(1)][TargetString]
	// Note: Simple framing.
	// Write Target
	if len(targetAddr) > 255 {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	
	// Send Metadata
	// Note: We are writing to the QUIC stream now.
	// The ObfuscatedPacketConn below encrypts everything.
	// Inside the stream, it's cleartext (TLS encrypted by QUIC).
	// So we can just send raw bytes.
	// But Server needs to know what to connect to.
	// Let's send target length + target.
	
	// Wait, we need to handle the case where we write the target, then pipe data.
	// Server reads target, then pipes.
	
	meta := append([]byte{byte(len(targetAddr))}, []byte(targetAddr)...)
	if _, err := stream.Write(meta); err != nil {
		return
	}

	// 5. Reply Success to Client
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	// 6. Pipe Data
	// Fix: quic.Stream is a struct pointer now
	go func() {
		io.Copy(stream, conn)
		stream.Close()
	}()
	io.Copy(conn, stream)
}

// UDP Relay Map: TargetAddr -> ClientUDPConn (for responses)
// Simple approach: When we receive Datagram from QUIC, we parse "TargetAddr".
// But Wait! The Server sends back Datagrams. The "TargetAddr" in response is "Who sent this".
// We need to route it back to the correct Local UDP Listener.
// 
// Issue: Multiple UDP ASSOCIATE sessions might be active.
// QUIC Datagrams are global to the session.
// We need a way to demultiplex.
// 
// Protocol for QUIC Datagrams (Client <-> Server):
// [AddrLen][TargetAddr/SourceAddr][Data]
// 
// Client -> Server: TargetAddr is where we want to send.
// Server -> Client: SourceAddr is who replied.
// 
// Client needs to know WHICH local UDP listener expects this packet.
// SOCKS5 UDP packets contain a header with the Target Address.
// 
// Actually, SOCKS5 UDP relay works like this:
// App -> [SOCKS Header][Data] -> Client UDP Listener.
// Client strips SOCKS Header, Encaps -> QUIC -> Server.
// Server -> Target.
// Target -> Server.
// Server -> [AddrLen][SourceAddr][Data] -> QUIC -> Client.
// Client reconstructs SOCKS Header -> Client UDP Listener -> App.
// 
// Problem: If App A sends to Target T, and App B sends to Target T.
// Server replies come back. Client sees Source T.
// Does it belong to App A or App B?
// SOCKS5 UDP requires strictly 1-to-1?
// Actually, SOCKS5 UDP Associate binds a port. The App sends packets to it.
// The SOCKS5 header tells where to go.
// The Relay sends back packets with SOCKS5 header telling where it came from.
// 
// So, we need to map SourceAddr back to... wait.
// The Client UDP Listener is unique per TCP Control Connection.
// BUT, multiple UDP Listeners share the SAME QUIC Session.
// When QUIC receives a datagram, how do we know which UDP Listener to give it to?
// 
// We don't.
// Unless we add a "Session ID" or "Flow ID" to the Datagram.
// Or we broadcast to all listeners? (Bad performance/security)
// 
// Solution: Use "Flow ID" in Datagram?
// Or simplify: Just use the Source Address map.
// If multiple Apps talk to same Target, SOCKS5 usually handles this by different local ports.
// But Server sees same "Client IP".
// 
// Let's implement a global UDP NAT table in Client.
// Map: SourceAddr (String) -> *net.UDPConn (The listener that sent to it?)
// 
// Wait, UDP is connectionless.
// App A -> Listener A -> QUIC -> Server -> Target T.
// Target T -> Server -> QUIC -> Listener A?
// 
// If App B -> Listener B -> QUIC -> Server -> Target T.
// Server sees packet from Client IP.
// Server replies to Client IP.
// Client receives.
// 
// How does Client know if it's for Listener A or B?
// It doesn't, unless we use different ports on Server side?
// Server uses `DialUDP` (random port) for each flow?
// In my server implementation, I use `DialUDP` for each packet (very inefficient) or flow.
// If Server uses different source ports for different outgoing flows, then SourceAddr is unique!
// 
// So:
// App A -> Target T (Server uses Port P1 to talk to T).
// App B -> Target T (Server uses Port P2 to talk to T).
// Reply from T:P1 -> Server -> Client. Client sees Source T:P1.
// Reply from T:P2 -> Server -> Client. Client sees Source T:P2.
// 
// So Client just needs to map "Remote Source Addr" -> "Local Listener".
// But Listener A sent to T.
// Listener B sent to T.
// We need to record "Who talked to T?"
// 
// Map: string(TargetAddr) -> *net.UDPConn (Listener)
// If A and B both talk to T, we have a collision.
// 
// Correct Solution: We need a unique ID for each UDP Associate session.
// We prepend this ID to the Datagram.
// [SessionID(4)][AddrLen][Addr][Data]
// 
// Let's implement this "Flow ID".
// 
// Modified Protocol:
// [FlowID(4)][AddrLen][Addr][Data]

var udpFlows sync.Map // Map[uint32]*net.UDPConn
var udpClientAddrs sync.Map // Map[uint32]net.Addr

func handleUDPRelay(l *net.UDPConn, sess QUICConnection) {
	// Generate Flow ID
	flowID := rand.Uint32()
	udpFlows.Store(flowID, l)
	defer udpFlows.Delete(flowID)
	defer udpClientAddrs.Delete(flowID)
	
	buf := make([]byte, 2048)
	for {
		l.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, addr, err := l.ReadFromUDP(buf)
		if err != nil {
			return
		}
		
		// Update Client Address
		udpClientAddrs.Store(flowID, addr)
		
		// Parse SOCKS5 UDP Header
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		// +----+------+------+----------+----------+----------+
		
		if n < 4 { continue }
		// Skip RSV(2)
		// FRAG(1) should be 0. We don't support frag.
		if buf[2] != 0 { continue }
		
		atyp := buf[3]
		var target string
		pos := 4
		
		switch atyp {
		case 1: // IPv4
			if n < pos+4+2 { continue }
			target = fmt.Sprintf("%s:%d", net.IP(buf[pos:pos+4]), binary.BigEndian.Uint16(buf[pos+4:pos+6]))
			pos += 6
		case 3: // Domain
			if n < pos+1 { continue }
			dLen := int(buf[pos])
			pos++
			if n < pos+dLen+2 { continue }
			target = fmt.Sprintf("%s:%d", string(buf[pos:pos+dLen]), binary.BigEndian.Uint16(buf[pos+dLen:pos+dLen+2]))
			pos += dLen + 2
		case 4: // IPv6
			if n < pos+16+2 { continue }
			target = fmt.Sprintf("[%s]:%d", net.IP(buf[pos:pos+16]), binary.BigEndian.Uint16(buf[pos+16:pos+16+2]))
			pos += 18
		default:
			continue
		}
		
		payload := buf[pos:n]
		
		// Encapsulate for QUIC
		// [FlowID(4)][AddrLen][Addr][Data]
		
		// Serialize
		targetBytes := []byte(target)
		addrLen := len(targetBytes)
		
		// 4 + 1 + addrLen + len(payload)
		pkt := make([]byte, 5+addrLen+len(payload))
		binary.BigEndian.PutUint32(pkt[0:4], flowID)
		pkt[4] = byte(addrLen)
		copy(pkt[5:], targetBytes)
		copy(pkt[5+addrLen:], payload)
		
		sess.SendDatagram(pkt)
	}
}

func handleDatagrams(sess QUICConnection) {
	for {
		data, err := sess.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		
		// Parse [FlowID(4)][AddrLen][Addr][Data]
		if len(data) < 5 { continue }
		
		flowID := binary.BigEndian.Uint32(data[0:4])
		addrLen := int(data[4])
		if len(data) < 5+addrLen { continue }
		
		sourceAddr := string(data[5 : 5+addrLen])
		payload := data[5+addrLen:]
		
		// Find Listener
		val, ok := udpFlows.Load(flowID)
		if !ok { continue }
		l := val.(*net.UDPConn)
		
		// Reconstruct SOCKS5 Header
		// We need to parse SourceAddr back to SOCKS5 bytes
		// To be compliant, we should parse IP/Port.
		// For simplicity, let's assume IPv4 or Domain?
		// SOCKS5 allows Domain.
		
		// Let's parse sourceAddr string back to host/port
		host, portStr, err := net.SplitHostPort(sourceAddr)
		if err != nil { continue }
		port, _ := strconv.Atoi(portStr)
		
		// Build Header
		var header []byte
		header = append(header, 0, 0, 0) // RSV, FRAG
		
		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, 1)
			header = append(header, ip4...)
		} else if ip != nil {
			header = append(header, 4)
			header = append(header, ip...)
		} else {
			// Domain
			header = append(header, 3)
			header = append(header, byte(len(host)))
			header = append(header, []byte(host)...)
		}
		
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		header = append(header, portBytes...)
		
		// Write to Listener
		// Note: WriteToUDP requires an address.
		// But SOCKS5 UDP Associate is weird. The client sends TO us. We send FROM us?
		// No, we use `WriteToUDP` to send TO the Client's address.
		// But wait, `l` is `ListenUDP`. We don't know Client's address!
		// `ReadFromUDP` gave us the Client address.
		// We need to store it in `handleUDPRelay`.
		
		// Fix: We need to store client address in `handleUDPRelay`.
		// But here we are in `handleDatagrams`.
		// We can use `l.WriteToUDP(payload, lastClientAddr)`.
		// But `l` doesn't know `lastClientAddr`.
		
		// For now, let's assume `handleUDPRelay` loop is the only one WRITING to `sess`.
		// We need to send packet BACK to `l`.
		// 
		// Actually, `l` is a *net.UDPConn.
		// We can't access its "last read addr" easily without storing it.
		// 
		// Hack for Prototype:
		// We can store `lastClientAddr` in a separate map keyed by flowID?
		// Or wrap `*net.UDPConn` in a struct that holds the address.
		
		// Let's just wrap the payload and send it to the channel?
		// No, `handleUDPRelay` is blocked on `ReadFromUDP`. It can't select on channel.
		// 
		// So we must use `l.WriteToUDP` here.
		// But we need the address.
		// 
		// Let's fetch address from `udpFlows`.
		// Change `udpFlows` to store a struct `UDPFlow`.
		
		// For now, let's just log and drop to fix compilation, then refactor.
		// Wait, user wants D implemented.
		
		// Refactor Step:
		// We need to store the Client Address associated with this FlowID.
		// But we only know it AFTER the first packet arrives in `handleUDPRelay`.
		// 
		// Let's use a `sync.Map` for `flowID -> clientAddr`.
		// `handleUDPRelay` writes to it.
		// `handleDatagrams` reads from it.
		
		clientAddrVal, ok := udpClientAddrs.Load(flowID)
		if !ok {
			continue // Don't know where to send back yet
		}
		clientAddr := clientAddrVal.(net.Addr)
		
		// Send [SOCKS Header][Payload]
		fullPkt := append(header, payload...)
		l.WriteTo(fullPkt, clientAddr)
	}
}

func startHTTPProxy(httpAddr string, socksAddr string) {
	if strings.HasPrefix(socksAddr, ":") {
		socksAddr = "127.0.0.1" + socksAddr
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		logger.Error("HTTP Proxy Error: %v", err)
		return
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// Handle HTTPS (CONNECT)
			destConn, err := dialer.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			hijacker, ok := w.(http.Hijacker)
			if !ok { return }
			clientConn, _, err := hijacker.Hijack()
			if err != nil { return }
			go transfer(destConn, clientConn)
			go transfer(clientConn, destConn)
		} else {
			// Handle HTTP (Standard)
			// Create a custom transport that uses the SOCKS5 dialer
			transport := &http.Transport{
				Dial: dialer.Dial,
				// Disable Keep-Alives to prevent "connection reset" confusion for now
				DisableKeepAlives: true, 
			}
			client := &http.Client{
				Transport: transport,
				// Don't follow redirects automatically, return them to client
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			
			// We need to request the absolute URL
			r.RequestURI = ""
			
			// If URL is relative (which happens in transparent proxying sometimes), fix it
			if r.URL.Scheme == "" {
				r.URL.Scheme = "http"
			}
			if r.URL.Host == "" {
				r.URL.Host = r.Host
			}

			resp, err := client.Do(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer resp.Body.Close()
			
			// Copy Headers
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}
	})
	http.ListenAndServe(httpAddr, handler)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func enableSystemProxy(addr string) error {
	proxyServer := "127.0.0.1:1081"
	cmdStr := fmt.Sprintf(`
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regKey -Name ProxyEnable -Value 1
Set-ItemProperty -Path $regKey -Name ProxyServer -Value "%s"
`, proxyServer)
	return exec.Command("powershell", "-Command", cmdStr).Run()
}

func disableSystemProxy() error {
	cmdStr := `
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regKey -Name ProxyEnable -Value 0
`
	return exec.Command("powershell", "-Command", cmdStr).Run()
}
