package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"w33d-tunnel/pkg/client"
	"w33d-tunnel/pkg/logger"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows/registry"
)

// App struct
type App struct {
	ctx           context.Context
	currentClient *client.Client
	cancelClient  context.CancelFunc
	configPath    string
}

type Config struct {
	SubURL      string `json:"sub_url"`
	SocksAddr   string `json:"socks_addr"`
	GlobalProxy bool   `json:"global_proxy"`
	AutoStart   bool   `json:"auto_start"`
}

type Stats struct {
	BytesTx uint64 `json:"bytes_tx"`
	BytesRx uint64 `json:"bytes_rx"`
}

// NewApp creates a new App application struct
func NewApp() *App {
	configDir, _ := os.UserConfigDir()
	configPath := filepath.Join(configDir, "w33d-tunnel", "config.json")
	return &App{
		configPath: configPath,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	
	// Setup Logger to emit events to frontend
	logger.SetOutputCallback(func(msg string) {
		runtime.EventsEmit(a.ctx, "log", msg)
	})
	
	// Start Stats Ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if a.currentClient != nil {
					s := a.currentClient.GetStats()
					runtime.EventsEmit(a.ctx, "stats", Stats{
						BytesTx: s.BytesTx,
						BytesRx: s.BytesRx,
					})
				}
			}
		}
	}()
}

func (a *App) shutdown(ctx context.Context) {
	if a.cancelClient != nil {
		a.cancelClient()
	}
}

// Backend API exposed to Frontend

func (a *App) LoadConfig() Config {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return Config{SocksAddr: ":1080"}
	}
	var cfg Config
	json.Unmarshal(data, &cfg)
	if cfg.SocksAddr == "" {
		cfg.SocksAddr = ":1080"
	}
	
	// Check Registry for AutoStart status (Source of Truth)
	// Because config file might be out of sync if user changed it manually or registry failed.
	// But actually, we set registry when saving config.
	// Let's trust config file for the UI state, but maybe verify?
	// For simplicity, just read config.
	
	return cfg
}

func (a *App) setAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	if enable {
		return k.SetStringValue("w33d-tunnel", exe)
	} else {
		return k.DeleteValue("w33d-tunnel")
	}
}

func (a *App) SaveConfig(cfg Config) error {
	// Handle AutoStart
	if err := a.setAutoStart(cfg.AutoStart); err != nil {
		fmt.Printf("Failed to set auto-start: %v\n", err)
	}

	dir := filepath.Dir(a.configPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(a.configPath, data, 0644)
}

func (a *App) Connect(cfg Config) error {
	if a.currentClient != nil {
		return fmt.Errorf("already connected")
	}
	
	// Validation
	if _, err := url.Parse(cfg.SubURL); err != nil {
		return fmt.Errorf("invalid URL")
	}

	a.SaveConfig(cfg)

	clientCfg := client.Config{
		SubURL:      cfg.SubURL,
		SocksAddr:   cfg.SocksAddr,
		GlobalProxy: cfg.GlobalProxy,
		Verbose:     true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancelClient = cancel
	a.currentClient = client.NewClient(clientCfg)

	go func() {
		err := a.currentClient.Start(ctx)
		if err != nil && err != context.Canceled {
			runtime.EventsEmit(a.ctx, "error", err.Error())
		}
		a.currentClient = nil
		a.cancelClient = nil
		runtime.EventsEmit(a.ctx, "disconnected", true)
	}()

	return nil
}

func (a *App) Disconnect() {
	if a.cancelClient != nil {
		a.cancelClient()
	}
}
