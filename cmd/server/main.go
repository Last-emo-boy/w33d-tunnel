package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"w33d-tunnel/pkg/crypto"
	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/transport"
	"net/http"
	"bytes"
	"encoding/json"

	quic "github.com/quic-go/quic-go"
)

var (
	port    = flag.Int("port", 8080, "Listen port")
	keyHex  = flag.String("key", "", "Server Private Key (Hex). If empty, generates random.")
	verbose = flag.Bool("v", false, "Verbose logging")
	simLoss = flag.Int("sim-loss", 0, "Simulate Packet Loss % (0-100)")
	managerAddr = flag.String("manager", "http://127.0.0.1:3000", "Manager Address")
	nodeID      = flag.String("node-id", "node-1", "Node ID")
	advertised  = flag.String("advertised-addr", "", "Advertised Address (host:port) for clients to connect. If empty, uses 127.0.0.1:port")
)

func startPingServer(port int) {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow CORS for frontend
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})
	logger.Info("Ping Server started on :%d", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func registerToManager(pub []byte) {
	// Construct Payload
	// We need our public address. For now, assume localhost or config.
	// Addr should be "host:port" reachable by client.
	
	addr := *advertised
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", *port)
	}

	payload := map[string]string{
		"id":      *nodeID,
		"name":    *nodeID,
		"addr":    addr, // Use configured address
		"pub_key": hex.EncodeToString(pub),
	}
	
	jsonData, _ := json.Marshal(payload)
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	// Initial
	http.Post(*managerAddr+"/api/register_node", "application/json", bytes.NewBuffer(jsonData))
	
	for range ticker.C {
		http.Post(*managerAddr+"/api/register_node", "application/json", bytes.NewBuffer(jsonData))
	}
}

func runTrafficReporter(conn *transport.ServerObfuscatedPacketConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// Get Stats from SessionManager
		// We need to access conn.SessionManager
		// But it is private.
		// Let's rely on `conn.GetSessionStats()` which we will add.
		
		stats := conn.GetSessionStats()
		if len(stats) == 0 {
			continue
		}
		
		// Post to Manager
		// Payload: { "node_id": "...", "stats": [ { "token": "...", "read": 123, "write": 456 } ] }
		payload := map[string]interface{}{
			"node_id": *nodeID,
			"stats":   stats,
		}
		
		jsonData, _ := json.Marshal(payload)
		resp, err := http.Post(*managerAddr+"/api/report", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			logger.Error("Failed to report stats: %v", err)
			continue
		}
		resp.Body.Close()
	}
}

type QUICConnection interface {
	AcceptStream(context.Context) (*quic.Stream, error)
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	RemoteAddr() net.Addr
}

func main() {
	flag.Parse()
	
	if *verbose {
		logger.SetLevel(logger.LevelDebug)
	}
	
	// Server Static Key
	var priv []byte
	var err error
	
	if *keyHex != "" {
		priv, err = hex.DecodeString(*keyHex)
		if err != nil {
			logger.Error("Invalid Private Key: %v", err)
			os.Exit(1)
		}
	} else {
		priv, _, err = crypto.GenerateKeyPair()
		if err != nil {
			logger.Error("Failed to generate keys: %v", err)
			os.Exit(1)
		}
	}
	
	// Derive Public Key
	pub, _ := crypto.GetPublicKey(priv)
	
	// Print Server Info
	printServerInfo(pub)
	
	// 1. Listen UDP
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		logger.Error("Resolve UDP failed: %v", err)
		os.Exit(1)
	}
	
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Error("Listen UDP failed: %v", err)
		os.Exit(1)
	}
	
	// Start Traffic Reporter
	// Ideally this should communicate with Manager.
	// For now, we just print stats to stdout/logger, or write to a file.
	// We need access to the SessionManager.
	// But SessionManager is inside ServerObfuscatedPacketConn.
	// We need to expose it or pass a callback.
	
	// Let's modify NewServerObfuscatedPacketConn to return SessionManager?
	// Or just use the instance.
	
	logger.Info("Server Started on port %d", *port)
	if *simLoss > 0 {
		logger.Warn("Packet Loss Simulation Enabled: %d%%", *simLoss)
	}
	
	// ServerObfuscatedPacketConn
	serverConn := transport.NewServerObfuscatedPacketConn(udpConn, priv, *simLoss)
	
	// Start Ping Endpoint
	go startPingServer(8090) // Hardcoded for now
	
	// Register to Manager
	go registerToManager(pub)
	
	// Start Reporter
	go runTrafficReporter(serverConn)

	// TLS Config for QUIC (Inner Layer)
	// We can generate self-signed certs because we trust the Outer Layer authentication.
	// Or use the keys we already have.
	tlsConfig := crypto.GenerateTLSConfig()
	tlsConfig.NextProtos = []string{"w33d-tunnel"}
	
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		HandshakeIdleTimeout: 15 * time.Second,
		EnableDatagrams: true,
	}

	listener, err := quic.Listen(serverConn, tlsConfig, quicConfig)
	if err != nil {
		logger.Error("QUIC Listen failed: %v", err)
		os.Exit(1)
	}

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logger.Error("Accept error: %v", err)
			continue
		}
		
		go handleQUICSession(conn)
	}
}

func handleQUICSession(c any) {
	conn := c.(QUICConnection)
	logger.Info("New QUIC Connection from %s", conn.RemoteAddr())
	
	// StreamMap is now implicit (QUIC Streams)
	// We just accept streams and datagrams.
	
	// Handle Datagrams in background
	go handleDatagrams(conn)
	
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logger.Debug("AcceptStream error: %v", err)
			return
		}
		
		go handleStream(stream)
	}
}

type UDPNatSession struct {
	Conn       *net.UDPConn
	LastActive time.Time
}

var (
	natTable sync.Map // map[uint32]*UDPNatSession
)

func handleDatagrams(conn QUICConnection) {
	// Cleanup Loop for NAT Table (Local to this connection? No, flowID is random globally?)
	// FlowID is 4 bytes. Collisions possible globally?
	// The protocol says "FlowID". Client generates it.
	// If multiple clients use same FlowID?
	// The `natTable` should be per-QUIC-Connection ideally.
	// But `handleUDPProxy` was global function.
	// Let's make `natTable` local to `handleDatagrams` (per client session).
	
	localNatTable := make(map[uint32]*UDPNatSession)
	var natMutex sync.Mutex
	
	// Cleanup Routine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				natMutex.Lock()
				now := time.Now()
				for id, sess := range localNatTable {
					if now.Sub(sess.LastActive) > 60*time.Second {
						sess.Conn.Close()
						delete(localNatTable, id)
					}
				}
				natMutex.Unlock()
			}
		}
	}()

	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			logger.Debug("ReceiveDatagram error: %v", err)
			// Close all NAT sessions
			natMutex.Lock()
			for _, sess := range localNatTable {
				sess.Conn.Close()
			}
			natMutex.Unlock()
			return
		}
		
		// Handle UDP Packet
		// Protocol: [FlowID(4)][AddrLen][Addr][Data]
		if len(data) < 5 {
			continue
		}
		
		flowID := binary.BigEndian.Uint32(data[0:4])
		addrLen := int(data[4])
		if len(data) < 5+addrLen {
			continue
		}
		
		targetAddr := string(data[5 : 5+addrLen])
		payload := data[5+addrLen:]
		
		natMutex.Lock()
		sess, exists := localNatTable[flowID]
		if !exists {
			// Resolve
			uAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				natMutex.Unlock()
				continue
			}
			
			// Dial
			c, err := net.DialUDP("udp", nil, uAddr)
			if err != nil {
				natMutex.Unlock()
				continue
			}
			
			sess = &UDPNatSession{
				Conn:       c,
				LastActive: time.Now(),
			}
			localNatTable[flowID] = sess
			
			// Start Reader for this Flow
			go func(id uint32, c *net.UDPConn, target string) {
				buf := make([]byte, 2048)
				for {
					c.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, _, err := c.ReadFromUDP(buf)
					if err != nil {
						// Error or Timeout, close and remove
						natMutex.Lock()
						if s, ok := localNatTable[id]; ok && s.Conn == c {
							delete(localNatTable, id)
						}
						natMutex.Unlock()
						c.Close()
						return
					}
					
					// Update Activity
					natMutex.Lock()
					if s, ok := localNatTable[id]; ok {
						s.LastActive = time.Now()
					}
					natMutex.Unlock()
					
					// Send back
					// Format: [FlowID(4)][AddrLen][Addr][Data]
					flowIDBytes := make([]byte, 4)
					binary.BigEndian.PutUint32(flowIDBytes, id)
					
					respMeta := append(flowIDBytes, byte(len(target)))
					respMeta = append(respMeta, []byte(target)...)
					resp := append(respMeta, buf[:n]...)
					
					conn.SendDatagram(resp)
				}
			}(flowID, c, targetAddr)
		}
		sess.LastActive = time.Now()
		natMutex.Unlock()
		
		// Write to Target
		sess.Conn.Write(payload)
	}
}

// Simple UDP Proxy (One-off for prototype, needs NAT table for real perf)
// func handleUDPProxy... REMOVED

func handleStream(stream *quic.Stream) {
	// Protocol: [Len(1)][TargetString]
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stream, buf); err != nil {
		stream.Close()
		return
	}
	addrLen := int(buf[0])
	
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		stream.Close()
		return
	}
	targetAddr := string(addrBuf)
	
	logger.Debug("Proxying to %s", targetAddr)
	
	// Connect to Target
	// Use default dialer with timeout and KeepAlive
	d := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	targetConn, err := d.Dial("tcp", targetAddr)
	if err != nil {
		logger.Error("Failed to connect to target %s: %v", targetAddr, err)
		stream.Close()
		return
	}
	
	// Pipe
	go func() {
		defer targetConn.Close()
		io.Copy(targetConn, stream)
	}()
	io.Copy(stream, targetConn)
	stream.Close()
}

// ... (Helper structs like ServerObfuscatedPacketConn need implementation)
// For brevity in this step, I will implement them in pkg/transport/server_conn.go next.

func printServerInfo(pub []byte) {
	fmt.Println("--- Server Information ---")
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Printf("  IPv4: %s\n", ipnet.IP.String())
			}
		}
	}
	fmt.Printf("  Static Public Key: %s\n", hex.EncodeToString(pub))
	fmt.Println("--------------------------")
}
