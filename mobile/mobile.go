package mobile

import (
	"context"
	"encoding/json"
	"os"
	"time"
	"w33d-tunnel/pkg/client"
	"w33d-tunnel/pkg/logger"
)

// MobileClient wraps the internal client for gomobile
type MobileClient struct {
	c       *client.Client
	cancel  context.CancelFunc
	tunFile *os.File
}

// NewMobileClient creates a new client instance.
func NewMobileClient() *MobileClient {
	return &MobileClient{}
}

// StartTun accepts a file descriptor from Android VpnService
// and starts reading/writing packets.
// Note: This is a basic implementation that verifies packet flow.
// For full VPN support, a user-space TCP/IP stack (like gVisor) is required here.
func (m *MobileClient) StartTun(fd int) {
	file := os.NewFile(uintptr(fd), "tun")
	m.tunFile = file

	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := file.Read(buf)
			if err != nil {
				logger.Error("TUN Read Error: %v", err)
				return
			}
			if n > 0 {
				// Just log the packet for now to prove it works
				// In production: forward to tun2socks stack
				// logger.Info("Read packet from TUN: %d bytes", n)
			}
		}
	}()
}

// Start launches the w33d-tunnel client.
// configJSON example: {"SubURL": "...", "SocksAddr": "127.0.0.1:1080", "Token": "..."}
func (m *MobileClient) Start(configJSON string) error {
	// 1. Parse Config
	var cfg client.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return err
	}

	// 2. Force settings suitable for mobile
	cfg.GlobalProxy = false // Mobile handles VPN routing natively or via Tun2Socks
	cfg.Verbose = true
	if cfg.SocksAddr == "" {
		cfg.SocksAddr = "127.0.0.1:1080"
	}

	// 3. Init Client
	m.c = client.NewClient(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// 4. Start in background goroutine
	// Note: We need to return immediately to avoid blocking the UI thread on Android/iOS
	go func() {
		logger.Info("Mobile Client Starting...")
		if err := m.c.Start(ctx); err != nil {
			logger.Error("Mobile Client Error: %v", err)
		}
	}()

	// Wait a brief moment to catch immediate start errors?
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop terminates the client.
func (m *MobileClient) Stop() {
	if m.tunFile != nil {
		m.tunFile.Close()
		m.tunFile = nil
	}
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil // Prevent double cancel
	}
}

// GetStats returns traffic statistics in JSON format.
// Returns: {"bytes_tx": 123, "bytes_rx": 456}
func (m *MobileClient) GetStats() string {
	if m.c == nil {
		return `{"bytes_tx": 0, "bytes_rx": 0}`
	}
	stats := m.c.GetStats()

	res := map[string]uint64{
		"bytes_tx": stats.BytesTx,
		"bytes_rx": stats.BytesRx,
	}
	b, _ := json.Marshal(res)
	return string(b)
}

// SetLogLevel sets the logger level. 0=Debug, 1=Info, 2=Warn, 3=Error
func SetLogLevel(level int) {
	logger.SetLevel(level)
}
