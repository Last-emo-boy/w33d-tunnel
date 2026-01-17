package client

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"w33d-tunnel/pkg/logger"
	"w33d-tunnel/pkg/transport"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/proxy"
)

type QUICConnection interface {
	OpenStreamSync(context.Context) (*quic.Stream, error)
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CloseWithError(quic.ApplicationErrorCode, string) error
}

type Config struct {
	ServerAddr   string
	ServerPubStr string
	SocksAddr    string
	GlobalProxy  bool
	Verbose      bool
	SimLoss      int
	Token        string
	SubURL       string
}

type Client struct {
	cfg        Config
	stats      Stats
	udpFlows   sync.Map
	udpAddrs   sync.Map
	ctx        context.Context
	cancel     context.CancelFunc
	quicSess   QUICConnection
	socksL     net.Listener
	httpL      net.Listener
}

type Stats struct {
	BytesTx uint64
	BytesRx uint64
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg: cfg,
	}
}

func (c *Client) GetStats() Stats {
	return Stats{
		BytesTx: atomic.LoadUint64(&c.stats.BytesTx),
		BytesRx: atomic.LoadUint64(&c.stats.BytesRx),
	}
}

func (c *Client) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	
	// Logger setup (handled by caller)

	// Handle Subscription
	if c.cfg.SubURL != "" {
		logger.Info("Fetching subscription from %s", c.cfg.SubURL)
		
		req, _ := http.NewRequestWithContext(c.ctx, "GET", c.cfg.SubURL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("Failed to fetch subscription: %v", err)
			return err
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
			return err
		}

		if len(config.Nodes) == 0 {
			logger.Error("No nodes available in subscription")
			return fmt.Errorf("no nodes available")
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
			return fmt.Errorf("no valid nodes")
		}

		c.cfg.ServerAddr = selectedNode.Addr
		c.cfg.ServerPubStr = selectedNode.PubKey

		logger.Info("Selected Node: %s (Pub: %s...)", selectedNode.Addr, selectedNode.PubKey[:8])

		// Extract token from URL if not provided
		if c.cfg.Token == "" {
			u, _ := http.NewRequest("GET", c.cfg.SubURL, nil)
			q := u.URL.Query()
			c.cfg.Token = q.Get("token")
		}
	}

	if c.cfg.ServerAddr == "" || c.cfg.ServerPubStr == "" {
		return fmt.Errorf("server address/pubkey or subscription URL required")
	}

	// 1. Initialize Client Dialer
	dialer, err := transport.NewClientDialer(c.cfg.ServerAddr, c.cfg.ServerPubStr, c.cfg.SimLoss, c.cfg.Token)
	if err != nil {
		return err
	}

	// 2. Dial QUIC Session
	logger.Info("Connecting to server via QUIC...")
	q, err := dialer.Dial(c.ctx)
	if err != nil {
		return err
	}
	c.quicSess = q.(QUICConnection)
	logger.Info("QUIC Session Established!")

	// 3. Start Handlers
	go c.handleDatagrams()
	go c.startSOCKS5Server()

	// Start HTTP Proxy for Global Mode
	if c.cfg.GlobalProxy {
		go c.startHTTPProxy(":1081", c.cfg.SocksAddr)
		time.Sleep(500 * time.Millisecond)
		logger.Info("Enabling Global System Proxy...")
		if err := enableSystemProxy(c.cfg.SocksAddr); err != nil {
			logger.Error("Failed to set system proxy: %v", err)
		} else {
			// Clean up on exit
			go func() {
				<-c.ctx.Done()
				disableSystemProxy()
			}()
		}
	}
	
	// Wait for context cancellation
	<-c.ctx.Done()
	
	// Cleanup
	if c.quicSess != nil {
		c.quicSess.CloseWithError(0, "client stopped")
	}
	if c.socksL != nil {
		c.socksL.Close()
	}
	
	logger.Info("Client Stopped.")
	return nil
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Client) startSOCKS5Server() {
	l, err := net.Listen("tcp", c.cfg.SocksAddr)
	if err != nil {
		logger.Error("SOCKS5 Listen failed: %v", err)
		c.Stop()
		return
	}
	c.socksL = l
	logger.Info("SOCKS5 Proxy listening on %s", c.cfg.SocksAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			// Check if closed
			select {
			case <-c.ctx.Done():
				return
			default:
				logger.Error("Accept error: %v", err)
				continue
			}
		}

		go c.handleSocksConnection(conn)
	}
}

func (c *Client) handleSocksConnection(conn net.Conn) {
	defer conn.Close()
	
	// Wrap conn to count stats? 
	// Or count in transfer.
	
	// Handshake
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }
	if buf[0] != 5 { return }
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil { return }
	conn.Write([]byte{5, 0})

	if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	cmd := buf[1]

	if cmd == 3 {
		// UDP Associate
		udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer udpListener.Close()

		lAddr := udpListener.LocalAddr().(*net.UDPAddr)
		resp := []byte{5, 0, 0, 1, 127, 0, 0, 1}
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(lAddr.Port))
		resp = append(resp, portBuf...)

		conn.Write(resp)

		go c.handleUDPRelay(udpListener)
		io.Copy(io.Discard, conn) // Keep TCP open
		return
	}

	if cmd != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect
	var target string
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
		target = net.IP(buf[:4]).String()
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil { return }
		dLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dLen]); err != nil { return }
		target = string(buf[:dLen])
	case 4:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil { return }
		target = fmt.Sprintf("[%s]", net.IP(buf[:16]).String())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }
	port := int(buf[0])<<8 | int(buf[1])
	targetAddr := fmt.Sprintf("%s:%d", target, port)

	stream, err := c.quicSess.OpenStreamSync(context.Background())
	if err != nil {
		logger.Error("Failed to open QUIC stream: %v", err)
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	if len(targetAddr) > 255 {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	meta := append([]byte{byte(len(targetAddr))}, []byte(targetAddr)...)
	if _, err := stream.Write(meta); err != nil {
		return
	}

	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	go c.transfer(stream, conn, &c.stats.BytesTx)
	c.transfer(conn, stream, &c.stats.BytesRx)
}

func (c *Client) transfer(dst io.Writer, src io.Reader, counter *uint64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			atomic.AddUint64(counter, uint64(n))
			dst.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (c *Client) handleUDPRelay(l *net.UDPConn) {
	flowID := rand.Uint32()
	c.udpFlows.Store(flowID, l)
	defer c.udpFlows.Delete(flowID)
	defer c.udpAddrs.Delete(flowID)

	buf := make([]byte, 2048)
	for {
		l.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, addr, err := l.ReadFromUDP(buf)
		if err != nil {
			return
		}

		c.udpAddrs.Store(flowID, addr)
		atomic.AddUint64(&c.stats.BytesTx, uint64(n))

		if n < 4 || buf[2] != 0 { continue }
		// ... SOCKS5 UDP Header Parsing ...
		// Simplified for brevity, same as before
		atyp := buf[3]
		var target string
		pos := 4

		switch atyp {
		case 1:
			if n < pos+6 { continue }
			target = fmt.Sprintf("%s:%d", net.IP(buf[pos:pos+4]), binary.BigEndian.Uint16(buf[pos+4:pos+6]))
			pos += 6
		case 3:
			if n < pos+1 { continue }
			dLen := int(buf[pos])
			pos++
			if n < pos+dLen+2 { continue }
			target = fmt.Sprintf("%s:%d", string(buf[pos:pos+dLen]), binary.BigEndian.Uint16(buf[pos+dLen:pos+dLen+2]))
			pos += dLen + 2
		case 4:
			if n < pos+18 { continue }
			target = fmt.Sprintf("[%s]:%d", net.IP(buf[pos:pos+16]), binary.BigEndian.Uint16(buf[pos+16:pos+16+2]))
			pos += 18
		default:
			continue
		}

		payload := buf[pos:n]
		targetBytes := []byte(target)
		addrLen := len(targetBytes)

		pkt := make([]byte, 5+addrLen+len(payload))
		binary.BigEndian.PutUint32(pkt[0:4], flowID)
		pkt[4] = byte(addrLen)
		copy(pkt[5:], targetBytes)
		copy(pkt[5+addrLen:], payload)

		c.quicSess.SendDatagram(pkt)
	}
}

func (c *Client) handleDatagrams() {
	for {
		data, err := c.quicSess.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}
		
		atomic.AddUint64(&c.stats.BytesRx, uint64(len(data)))

		if len(data) < 5 { continue }

		flowID := binary.BigEndian.Uint32(data[0:4])
		addrLen := int(data[4])
		if len(data) < 5+addrLen { continue }

		sourceAddr := string(data[5 : 5+addrLen])
		payload := data[5+addrLen:]

		val, ok := c.udpFlows.Load(flowID)
		if !ok { continue }
		l := val.(*net.UDPConn)

		host, portStr, err := net.SplitHostPort(sourceAddr)
		if err != nil { continue }
		port, _ := strconv.Atoi(portStr)

		var header []byte
		header = append(header, 0, 0, 0)

		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, 1)
			header = append(header, ip4...)
		} else if ip != nil {
			header = append(header, 4)
			header = append(header, ip...)
		} else {
			header = append(header, 3)
			header = append(header, byte(len(host)))
			header = append(header, []byte(host)...)
		}

		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		header = append(header, portBytes...)

		clientAddrVal, ok := c.udpAddrs.Load(flowID)
		if !ok {
			continue
		}
		clientAddr := clientAddrVal.(net.Addr)

		fullPkt := append(header, payload...)
		l.WriteTo(fullPkt, clientAddr)
	}
}

func (c *Client) startHTTPProxy(httpAddr string, socksAddr string) {
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
			transport := &http.Transport{
				Dial: dialer.Dial,
				DisableKeepAlives: true,
			}
			client := &http.Client{
				Transport: transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			r.RequestURI = ""
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

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}
	})
	
	// Create listener manually to close it
	l, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Error("HTTP Proxy Listen Failed: %v", err)
		return
	}
	c.httpL = l
	
	go http.Serve(l, handler)
}

// Helpers
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
