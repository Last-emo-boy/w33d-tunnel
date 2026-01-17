package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Scenario defines a test case
type Scenario struct {
	Name        string
	LossPercent int
	Duration    time.Duration
	Concurrency int
}

var scenarios = []Scenario{
	{"Ideal Network", 0, 10 * time.Second, 10},
	{"Mild Loss (5%)", 5, 10 * time.Second, 10},
	{"Heavy Loss (20%)", 20, 10 * time.Second, 10},
}

type LatencyStats struct {
	mu      sync.Mutex
	samples []time.Duration
}

func (l *LatencyStats) Record(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.samples = append(l.samples, d)
}

func (l *LatencyStats) Calculate() (p50, p95, p99 time.Duration, jitter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if len(l.samples) == 0 {
		return 0, 0, 0, 0
	}
	
	sort.Slice(l.samples, func(i, j int) bool {
		return l.samples[i] < l.samples[j]
	})
	
	n := len(l.samples)
	p50 = l.samples[n*50/100]
	p95 = l.samples[n*95/100]
	p99 = l.samples[n*99/100]
	
	// Jitter: Standard Deviation
	var sum float64
	for _, d := range l.samples {
		sum += float64(d.Microseconds())
	}
	mean := sum / float64(n)
	
	var sqDiff float64
	for _, d := range l.samples {
		diff := float64(d.Microseconds()) - mean
		sqDiff += diff * diff
	}
	
	stdDev := math.Sqrt(sqDiff / float64(n))
	jitter = time.Duration(stdDev) * time.Microsecond
	
	return
}

func main() {
	// Mode check: If running as worker, do the load test logic
	mode := flag.String("mode", "orchestrator", "Mode: orchestrator or worker")
	targetAddr := flag.String("target", "127.0.0.1:9999", "Target address")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 Proxy")
	dur := flag.Duration("duration", 10*time.Second, "Duration")
	conc := flag.Int("c", 10, "Concurrency")
	
	flag.Parse()

	if *mode == "worker" {
		runWorker(*targetAddr, *socksAddr, *dur, *conc)
		return
	}

	// Orchestrator Mode
	runOrchestrator()
}

func runOrchestrator() {
	fmt.Println("=== Starting Robustness Benchmark Suite ===")
	
	// 1. Build Binaries
	fmt.Println("[Setup] Building binaries...")
	mustRun("go", "build", "-o", "bench_server.exe", "./cmd/server")
	mustRun("go", "build", "-o", "bench_client.exe", "./cmd/client")
	// Build worker (self)
	mustRun("go", "build", "-o", "bench_worker.exe", "./cmd/bench")
	
	defer func() {
		os.Remove("bench_server.exe")
		os.Remove("bench_client.exe")
		os.Remove("bench_worker.exe")
	}()

	// 2. Start Echo Server (Global)
	echoListener, err := net.Listen("tcp", "127.0.0.1:9999")
	if err != nil {
		panic(err)
	}
	defer echoListener.Close()
	go func() {
		for {
			c, err := echoListener.Accept()
			if err != nil { return }
			go io.Copy(c, c)
		}
	}()
	fmt.Println("[Setup] Echo Server listening on 127.0.0.1:9999")

	// 3. Run Scenarios
	for _, sc := range scenarios {
		fmt.Printf("\n>>> Running Scenario: %s (Loss: %d%%) <<<\n", sc.Name, sc.LossPercent)
		
		// Start Server
		// Port 2838 + Loss
		serverCmd := exec.Command("./bench_server.exe", "-port", "2838", "-sim-loss", fmt.Sprintf("%d", sc.LossPercent))
		
		// Capture Stdout to find Public Key
		stdoutPipe, err := serverCmd.StdoutPipe()
		if err != nil { panic(err) }
		serverCmd.Stderr = os.Stderr
		
		if err := serverCmd.Start(); err != nil {
			panic(err)
		}
		
		// Scan for Public Key
		scanner := bufio.NewScanner(stdoutPipe)
		var pubKey string
		keyRegex := regexp.MustCompile(`Static Public Key: ([a-f0-9]+)`)
		
		go func() {
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Println("[Server]", line) // Passthrough logs
				if matches := keyRegex.FindStringSubmatch(line); len(matches) > 1 {
					pubKey = matches[1]
				}
			}
		}()
		
		// Wait for Server Port (Sleep for UDP)
		// Also wait for key
		for i := 0; i < 20; i++ {
			if pubKey != "" { break }
			time.Sleep(100 * time.Millisecond)
		}
		if pubKey == "" {
			fmt.Println("Failed to get server public key")
			serverCmd.Process.Kill()
			continue
		}
		
		// Start Client
		clientCmd := exec.Command("./bench_client.exe", 
			"-server", "127.0.0.1:2838",
			"-pubkey", pubKey,
			"-socks", ":1080",
			"-sim-loss", fmt.Sprintf("%d", sc.LossPercent),
		)
		clientCmd.Stdout = os.Stdout // Enable logs
		clientCmd.Stderr = os.Stderr
		if err := clientCmd.Start(); err != nil {
			serverCmd.Process.Kill()
			panic(err)
		}
		
		// Wait for SOCKS Port
		if err := waitForPort("127.0.0.1:1080", 15*time.Second); err != nil {
			fmt.Printf("Client failed to start: %v\n", err)
			clientCmd.Process.Kill()
			serverCmd.Process.Kill()
			continue
		}
		
		// Run Worker
		workerCmd := exec.Command("./bench_worker.exe", 
			"-mode", "worker",
			"-target", "127.0.0.1:9999",
			"-socks", "127.0.0.1:1080",
			"-duration", sc.Duration.String(),
			"-c", fmt.Sprintf("%d", sc.Concurrency),
		)
		workerCmd.Stdout = os.Stdout
		workerCmd.Stderr = os.Stderr
		workerCmd.Run()
		
		// Cleanup
		clientCmd.Process.Kill()
		serverCmd.Process.Kill()
		time.Sleep(1 * time.Second) // Cooldown
	}
	
	fmt.Println("\n=== Benchmark Suite Completed ===")
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
		// For UDP, we can't easily check, but Server also listens on UDP port.
		// SOCKS is TCP, so checking 1080 works.
		// Server port 2838 is UDP. net.Dial("udp") doesn't block.
		// However, Client connects to it.
		// We only need to wait for SOCKS port (Client Ready) and Echo port (Server Ready? No echo is global).
		// Wait, Server is UDP. We can't check it easily.
		// But Client won't start SOCKS until Handshake is done?
		// No, Client starts SOCKS immediately, then Dials QUIC on demand.
		// Actually, `main.go` logic:
		// 1. NewClientDialer
		// 2. Dial QUIC (Blocks until handshake success!)
		// 3. Start SOCKS
		// So if SOCKS port is open, it means Handshake + QUIC is done.
		// So checking 1080 is sufficient for Client readiness.
		
		// For Server, we just wait a bit or assume it's fast.
		// Since we check SOCKS, and Client depends on Server, SOCKS check implicitly checks Server.
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func runWorker(targetAddr, socksAddr string, duration time.Duration, concurrency int) {
	// 2. Benchmark Client
	var (
		totalBytes int64
		success    int64
		failures   int64
		wg         sync.WaitGroup
		latencies  LatencyStats
	)

	// fmt.Printf("Starting Benchmark:\nTarget: %s\nProxy: %s\nDuration: %v\nConcurrency: %d\n\n", targetAddr, socksAddr, duration, concurrency)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	// Status Reporter
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		lastBytes := int64(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				curBytes := atomic.LoadInt64(&totalBytes)
				diff := curBytes - lastBytes
				lastBytes = curBytes
				
				mbps := float64(diff) * 8 / 1024 / 1024
				fmt.Printf("[Status] Throughput: %.2f Mbps | Requests: %d | Fails: %d\n", mbps, atomic.LoadInt64(&success), atomic.LoadInt64(&failures))
			}
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Create SOCKS5 Dialer
			dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
			if err != nil {
				// fmt.Printf("[Worker %d] SOCKS5 Init Failed: %v\n", id, err)
				atomic.AddInt64(&failures, 1)
				return
			}

			// Connect
			conn, err := dialer.Dial("tcp", targetAddr)
			if err != nil {
				// fmt.Printf("[Worker %d] Connect Failed: %v\n", id, err)
				atomic.AddInt64(&failures, 1)
				return
			}
			defer conn.Close()

			// Pump Data
			buf := make([]byte, 32*1024)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					reqStart := time.Now()
					
					// Write
					n, err := conn.Write(buf)
					if err != nil {
						atomic.AddInt64(&failures, 1)
						return
					}
					
					// Read
					_, err = io.ReadFull(conn, buf[:n])
					if err != nil {
						atomic.AddInt64(&failures, 1)
						return
					}
					
					latencies.Record(time.Since(reqStart))
					atomic.AddInt64(&totalBytes, int64(n))
					atomic.AddInt64(&success, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	
	mbps := (float64(totalBytes) * 8 / 1024 / 1024) / elapsed
	p50, p95, p99, jitter := latencies.Calculate()
	
	fmt.Printf("--- Results ---\n")
	fmt.Printf("Total Data: %.2f MB\n", float64(totalBytes)/1024/1024)
	fmt.Printf("Throughput: %.2f Mbps\n", mbps)
	fmt.Printf("Success/Fail: %d / %d\n", success, failures)
	fmt.Printf("Latency P50: %v\n", p50)
	fmt.Printf("Latency P95: %v\n", p95)
	fmt.Printf("Latency P99: %v\n", p99)
	fmt.Printf("Jitter (StdDev): %v\n", jitter)
}
