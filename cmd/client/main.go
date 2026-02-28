package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"w33d-tunnel/pkg/client"
	"w33d-tunnel/pkg/logger"
)

func main() {
	cfg := client.Config{}

	flag.StringVar(&cfg.ServerAddr, "server", "", "Server address (Optional if using subscription)")
	flag.StringVar(&cfg.ServerPubStr, "pubkey", "", "Server Static Public Key (Optional if using subscription)")
	flag.StringVar(&cfg.SocksAddr, "socks", ":1080", "SOCKS5 Listen Address")
	flag.BoolVar(&cfg.GlobalProxy, "global", false, "Enable Global System Proxy (Windows Only)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose logging")
	flag.IntVar(&cfg.SimLoss, "sim-loss", 0, "Simulate Packet Loss % (0-100)")
	flag.StringVar(&cfg.Token, "token", "", "User Token for Authentication (or Subscription URL)")
	flag.StringVar(&cfg.SubURL, "subscribe", "", "Subscription URL (e.g. http://cloud.w33d.xyz/api/subscribe?token=...)")
	flag.Parse()

	if cfg.Verbose {
		logger.SetLevel(logger.LevelDebug)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	c := client.NewClient(cfg)
	if err := c.Start(ctx); err != nil {
		logger.Error("Client failed: %v", err)
		os.Exit(1)
	}
}
