package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"w33d-tunnel/pkg/client"
	"w33d-tunnel/pkg/logger"
)

const (
	prefSubURL      = "subscription_url"
	prefSocksAddr   = "socks_address"
	prefGlobalProxy = "global_proxy"
)

func main() {
	a := app.NewWithID("xyz.w33d.tunnel")
	w := a.NewWindow("w33d-tunnel Client")

	// --- Preferences ---
	subURL := a.Preferences().StringWithFallback(prefSubURL, "")
	socksAddr := a.Preferences().StringWithFallback(prefSocksAddr, ":1080")
	globalProxy := a.Preferences().BoolWithFallback(prefGlobalProxy, false)

	// --- UI Components ---
	
	// Bindings
	subUrlBind := binding.BindString(&subURL)
	socksAddrBind := binding.BindString(&socksAddr)
	globalProxyBind := binding.BindBool(&globalProxy)

	// Header
	header := container.NewHBox(
		widget.NewIcon(theme.HomeIcon()), // Placeholder for Logo
		widget.NewLabelWithStyle("w33d-tunnel", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		layout.NewSpacer(),
	)

	// Connection Status
	statusLabel := widget.NewLabel("Status: Disconnected")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	
	statusIcon := widget.NewIcon(theme.MediaRecordIcon()) // Red/Green circle logic needed
	
	// Inputs
	subUrlEntry := widget.NewEntryWithData(subUrlBind)
	subUrlEntry.SetPlaceHolder("https://cloud.w33d.xyz/api/subscribe?token=...")
	
	socksAddrEntry := widget.NewEntryWithData(socksAddrBind)
	socksAddrEntry.SetPlaceHolder(":1080")
	
	globalProxyCheck := widget.NewCheckWithData("Global System Proxy", globalProxyBind)

	// Stats
	txLabel := widget.NewLabel("Tx: 0 B")
	rxLabel := widget.NewLabel("Rx: 0 B")
	statsContainer := container.NewGridWithColumns(2, txLabel, rxLabel)

	// Logs
	logEntry := widget.NewMultiLineEntry()
	logEntry.Disable()
	logEntry.SetMinRowsVisible(15)
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}

	// Redirect Logger
	logger.SetOutputCallback(func(msg string) {
		// Append log on main thread to be safe
		// But Fyne widgets are not thread safe? 
		// Actually SetText triggers refresh which should be on UI thread?
		// Better use binding or window.Canvas().Refresh()?
		// Let's use simple append for now, but trim to avoid memory leak
		currentText := logEntry.Text
		if len(currentText) > 10000 {
			currentText = currentText[len(currentText)-8000:]
		}
		logEntry.SetText(currentText + msg + "\n")
		logEntry.CursorRow = len(logEntry.Text) 
	})

	// Client Instance
	var cancelClient context.CancelFunc
	var isConnected bool
	
	connectBtn := widget.NewButton("Connect", nil)
	connectBtn.Importance = widget.HighImportance

	updateUI := func(connected bool) {
		isConnected = connected
		if connected {
			connectBtn.SetText("Disconnect")
			connectBtn.Importance = widget.DangerImportance
			statusLabel.SetText("Status: Connected")
			subUrlEntry.Disable()
			socksAddrEntry.Disable()
			globalProxyCheck.Disable()
		} else {
			connectBtn.SetText("Connect")
			connectBtn.Importance = widget.HighImportance
			statusLabel.SetText("Status: Disconnected")
			subUrlEntry.Enable()
			socksAddrEntry.Enable()
			globalProxyCheck.Enable()
		}
	}

	connectBtn.OnTapped = func() {
		if isConnected {
			// Disconnect
			if cancelClient != nil {
				cancelClient()
			}
			return
		}

		// Save Preferences
		a.Preferences().SetString(prefSubURL, subURL)
		a.Preferences().SetString(prefSocksAddr, socksAddr)
		a.Preferences().SetBool(prefGlobalProxy, globalProxy)

		// Validation
		if subURL == "" {
			statusLabel.SetText("Error: URL Required")
			return
		}
		if _, err := url.Parse(subURL); err != nil {
			statusLabel.SetText("Error: Invalid URL")
			return
		}

		cfg := client.Config{
			SubURL:      subURL,
			SocksAddr:   socksAddr,
			GlobalProxy: globalProxy,
			Verbose:     true,
		}

		statusLabel.SetText("Status: Connecting...")
		connectBtn.Disable() // Prevent double click

		ctx, cancel := context.WithCancel(context.Background())
		cancelClient = cancel
		
		c := client.NewClient(cfg)
		// currentClient = c // Unused for now

		go func() {
			// Start Stats Updater
			ticker := time.NewTicker(1 * time.Second)
			statsDone := make(chan bool)
			go func() {
				for {
					select {
					case <-ticker.C:
						s := c.GetStats()
						txLabel.SetText(fmt.Sprintf("Tx: %s", formatBytes(s.BytesTx)))
						rxLabel.SetText(fmt.Sprintf("Rx: %s", formatBytes(s.BytesRx)))
					case <-statsDone:
						return
					}
				}
			}()

			// Start Client
			updateUI(true)
			connectBtn.Enable()

			err := c.Start(ctx)
			
			// Cleanup
			ticker.Stop()
			statsDone <- true
			
			if err != nil && err != context.Canceled {
				statusLabel.SetText(fmt.Sprintf("Error: %v", err))
			}
			
			updateUI(false)
			connectBtn.Enable()
		}()
	}

	// Layout
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Connection", theme.ComputerIcon(), container.NewVBox(
			widget.NewCard("Configuration", "", container.NewVBox(
				widget.NewLabel("Subscription URL"),
				subUrlEntry,
				widget.NewLabel("SOCKS5 Address"),
				socksAddrEntry,
				globalProxyCheck,
			)),
			widget.NewCard("Status", "", container.NewVBox(
				container.NewHBox(statusIcon, statusLabel),
				statsContainer,
			)),
			layout.NewSpacer(),
			connectBtn,
		)),
		container.NewTabItemWithIcon("Logs", theme.DocumentIcon(), container.NewPadded(logEntry)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	w.SetContent(container.NewBorder(header, nil, nil, nil, tabs))
	w.Resize(fyne.NewSize(450, 600))
	
	// System Tray
	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("w33d-tunnel",
			fyne.NewMenuItem("Show", func() {
				w.Show()
			}),
			fyne.NewMenuItem("Connect", func() {
				if !isConnected {
					connectBtn.OnTapped()
				}
			}),
			fyne.NewMenuItem("Disconnect", func() {
				if isConnected {
					connectBtn.OnTapped()
				}
			}),
		)
		desk.SetSystemTrayMenu(m)
	}
	
	// Handle Close to Tray (Optional, for now just quit)
	w.SetCloseIntercept(func() {
		// Ideally minimize to tray, but let's just close app and clean up proxies
		if isConnected && cancelClient != nil {
			cancelClient()
		}
		w.Close()
	})

	w.ShowAndRun()
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
