package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	// 1. Build Binaries
	fmt.Println("[Setup] Building binaries...")
	mustRun("go", "build", "-o", "bench_server.exe", "./cmd/server")
	mustRun("go", "build", "-o", "bench_client.exe", "./cmd/client")
	
	defer func() {
		// Cleanup
		os.Remove("bench_server.exe")
		os.Remove("bench_client.exe")
	}()

	// 2. Start Server
	fmt.Println("[Setup] Starting Server...")
	serverCmd := exec.Command("./bench_server.exe", "-port", "2838", "-v")
	stdoutPipe, err := serverCmd.StdoutPipe()
	if err != nil { panic(err) }
	serverCmd.Stderr = os.Stderr
	
	if err := serverCmd.Start(); err != nil {
		panic(err)
	}
	defer func() {
		if serverCmd.Process != nil {
			serverCmd.Process.Kill()
		}
	}()

	// Scan for Public Key
	scanner := bufio.NewScanner(stdoutPipe)
	var pubKey string
	keyRegex := regexp.MustCompile(`Static Public Key: ([a-f0-9]+)`)
	
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			// fmt.Println("[Server]", line) 
			if matches := keyRegex.FindStringSubmatch(line); len(matches) > 1 {
				pubKey = matches[1]
			}
		}
	}()
	
	// Wait for Key
	fmt.Println("Waiting for server public key...")
	for i := 0; i < 50; i++ {
		if pubKey != "" { break }
		time.Sleep(100 * time.Millisecond)
	}
	if pubKey == "" {
		panic("Failed to get server public key")
	}
	fmt.Printf("Server Key: %s\n", pubKey)

	// 3. Start Client
	fmt.Println("[Setup] Starting Client...")
	clientCmd := exec.Command("./bench_client.exe", 
		"-server", "127.0.0.1:2838",
		"-pubkey", pubKey,
		"-socks", ":1081", // Use different port than default
		"-v",
	)
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	
	if err := clientCmd.Start(); err != nil {
		panic(err)
	}
	defer func() {
		if clientCmd.Process != nil {
			clientCmd.Process.Kill()
		}
	}()

	// Wait for SOCKS
	waitForPort("127.0.0.1:1081", 10*time.Second)

	// 4. Run HTTP Test
	fmt.Println(">>> Starting HTTP Load Test to gallery.w33d.xyz (Mixed Content) <<<")
	
	// Setup SOCKS5 Client
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1081", nil, proxy.Direct)
	if err != nil {
		panic(err)
	}
	
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
			MaxIdleConns: 100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: 30 * time.Second,
	}

	var (
		success int64
		fails   int64
		bytes   int64
		wg      sync.WaitGroup
	)

	// Run for 30 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	concurrency := 20
	
	// URLs to fetch
	urls := []string{
		"http://gallery.w33d.xyz/wall",
		"http://gallery.w33d.xyz/assets/index-yGKomqUO.js",
		"http://gallery.w33d.xyz/assets/index-C-qmRaED.css",
		"http://gallery.w33d.xyz/vite.svg",
		// OSS Assets (Simulated based on typical gallery patterns)
		"https://oss.w33d.xyz/DSCF9260.jpg",
		"https://oss.w33d.xyz/DSCF8803.jpg",
		"https://oss.w33d.xyz/DSCF8697.jpg",
	}

	// Status Reporter
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := atomic.LoadInt64(&success)
				f := atomic.LoadInt64(&fails)
				b := atomic.LoadInt64(&bytes)
				fmt.Printf("[Status] Success: %d | Fails: %d | Data: %.2f MB\n", s, f, float64(b)/1024/1024)
			}
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			idx := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					target := urls[idx%len(urls)]
					idx++
					
					start := time.Now()
					// Request
					resp, err := httpClient.Get(target)
					if err != nil {
						atomic.AddInt64(&fails, 1)
						time.Sleep(100 * time.Millisecond) // Backoff
						continue
					}
					// Read Body
					n, err := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					
					if err != nil {
						atomic.AddInt64(&fails, 1)
					} else if resp.StatusCode != 200 {
						atomic.AddInt64(&fails, 1)
					} else {
						atomic.AddInt64(&success, 1)
						atomic.AddInt64(&bytes, n)
					}
					
					if time.Since(start) < 50*time.Millisecond {
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	fmt.Println("Test Completed.")
}

func mustRun(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}
