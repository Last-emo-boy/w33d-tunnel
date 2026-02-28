package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"w33d-tunnel/pkg/client"
	"w33d-tunnel/pkg/kernel"
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
	kernelPath    string
	kernelMeta    string

	kernelManagersLock sync.RWMutex
	kernelManagers     map[string]*kernel.RuntimeManager

	kernelControllerLock        sync.Mutex
	kernelControllerServer      *http.Server
	kernelControllerListener    net.Listener
	kernelControllerProfile     string
	kernelControllerURL         string
	kernelControllerToken       string
	kernelControllerRequireAuth bool
	kernelControllerWrite       bool
	kernelControllerClient      *http.Client
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

type KernelValidationResult struct {
	Valid         bool   `json:"valid"`
	Message       string `json:"message"`
	Outbounds     int    `json:"outbounds"`
	Rules         int    `json:"rules"`
	DefaultTarget string `json:"default_target"`
}

type KernelRouteProbeResult struct {
	OK          bool                   `json:"ok"`
	Message     string                 `json:"message"`
	Matched     bool                   `json:"matched"`
	Rule        string                 `json:"rule"`
	Outbound    string                 `json:"outbound"`
	AdapterType string                 `json:"adapter_type"`
	Trace       []KernelRouteTraceItem `json:"trace"`
}

type KernelRouteTraceItem struct {
	Index    int    `json:"index"`
	Rule     string `json:"rule"`
	Outbound string `json:"outbound"`
	Matched  bool   `json:"matched"`
}

type KernelRuntimeStats struct {
	Profile       string            `json:"profile"`
	Version       uint64            `json:"version"`
	TotalRoutes   uint64            `json:"total_routes"`
	MatchedRoutes uint64            `json:"matched_routes"`
	DefaultRoutes uint64            `json:"default_routes"`
	LastRule      string            `json:"last_rule"`
	LastOutbound  string            `json:"last_outbound"`
	OutboundHits  map[string]uint64 `json:"outbound_hits"`
	AdapterHealth map[string]string `json:"adapter_health"`
}

type KernelControllerState struct {
	Running     bool   `json:"running"`
	Profile     string `json:"profile"`
	URL         string `json:"url"`
	RequireAuth bool   `json:"require_auth"`
	Write       bool   `json:"write"`
}

type KernelProfileState struct {
	Active   string   `json:"active"`
	Profiles []string `json:"profiles"`
}

type KernelProfileRevision struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Bytes     int64  `json:"bytes"`
}

type kernelProfilesMeta struct {
	Active   string   `json:"active"`
	Profiles []string `json:"profiles"`
}

type controllerSession struct {
	state  KernelControllerState
	token  string
	client *http.Client
}

type controllerResponseEnvelope struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

const defaultKernelProfile = "default"
const defaultKernelConfigYAML = `outbounds:
  - name: direct
    type: direct
routing:
  default_outbound: direct
  rules: []
`

// NewApp creates a new App application struct
func NewApp() *App {
	configDir, _ := os.UserConfigDir()
	configPath := filepath.Join(configDir, "w33d-tunnel", "config.json")
	kernelPath := filepath.Join(configDir, "w33d-tunnel", "kernel.yaml")
	kernelMeta := filepath.Join(configDir, "w33d-tunnel", "kernel", "profiles.json")
	return &App{
		configPath:     configPath,
		kernelPath:     kernelPath,
		kernelMeta:     kernelMeta,
		kernelManagers: map[string]*kernel.RuntimeManager{},
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
	a.kernelControllerLock.Lock()
	a.stopKernelControllerLocked()
	a.kernelControllerLock.Unlock()
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

func (a *App) kernelProfilesDir() string {
	return filepath.Join(filepath.Dir(a.kernelMeta), "profiles")
}

func (a *App) profileFilePath(name string) string {
	return filepath.Join(a.kernelProfilesDir(), name+".yaml")
}

func (a *App) profileRevisionsDir(name string) string {
	return filepath.Join(filepath.Dir(a.kernelMeta), "revisions", name)
}

func normalizeProfileName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", errors.New("profile name cannot be empty")
	}
	for _, ch := range n {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return "", errors.New("profile name contains invalid characters")
	}
	return n, nil
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func validRevisionID(id string) bool {
	if strings.TrimSpace(id) == "" {
		return false
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (a *App) saveProfilesMeta(meta kernelProfilesMeta) error {
	meta.Profiles = uniqueStrings(meta.Profiles)
	if meta.Active == "" {
		meta.Active = defaultKernelProfile
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.kernelMeta), 0755); err != nil {
		return err
	}
	return os.WriteFile(a.kernelMeta, b, 0644)
}

func (a *App) ensureKernelStore() (kernelProfilesMeta, error) {
	if err := os.MkdirAll(a.kernelProfilesDir(), 0755); err != nil {
		return kernelProfilesMeta{}, err
	}

	var meta kernelProfilesMeta
	b, err := os.ReadFile(a.kernelMeta)
	if err == nil {
		if err := json.Unmarshal(b, &meta); err != nil {
			return kernelProfilesMeta{}, err
		}
	}

	if meta.Active == "" {
		meta.Active = defaultKernelProfile
	}
	if len(meta.Profiles) == 0 {
		meta.Profiles = []string{defaultKernelProfile}
	}
	meta.Profiles = uniqueStrings(meta.Profiles)

	// Migrate legacy kernel.yaml to default profile once.
	defaultProfilePath := a.profileFilePath(defaultKernelProfile)
	if _, err := os.Stat(defaultProfilePath); err != nil {
		content := defaultKernelConfigYAML
		if legacy, err := os.ReadFile(a.kernelPath); err == nil && len(strings.TrimSpace(string(legacy))) > 0 {
			content = string(legacy)
		}
		if err := os.WriteFile(defaultProfilePath, []byte(content), 0644); err != nil {
			return kernelProfilesMeta{}, err
		}
	}

	if err := a.saveProfilesMeta(meta); err != nil {
		return kernelProfilesMeta{}, err
	}
	return meta, nil
}

func (a *App) GetKernelProfiles() KernelProfileState {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return KernelProfileState{
			Active:   defaultKernelProfile,
			Profiles: []string{defaultKernelProfile},
		}
	}
	return KernelProfileState{
		Active:   meta.Active,
		Profiles: meta.Profiles,
	}
}

func (a *App) SetActiveKernelProfile(name string) error {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return err
	}
	n, err := normalizeProfileName(name)
	if err != nil {
		return err
	}
	found := false
	for _, p := range meta.Profiles {
		if p == n {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("profile not found: %s", n)
	}
	prevActive := meta.Active
	meta.Active = n
	if err := a.saveProfilesMeta(meta); err != nil {
		return err
	}
	if prevActive != n {
		a.kernelControllerLock.Lock()
		if a.kernelControllerProfile != "" && a.kernelControllerProfile != n {
			a.stopKernelControllerLocked()
		}
		a.kernelControllerLock.Unlock()
	}
	return nil
}

func (a *App) CreateKernelProfile(name string) error {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return err
	}
	n, err := normalizeProfileName(name)
	if err != nil {
		return err
	}
	for _, p := range meta.Profiles {
		if p == n {
			return fmt.Errorf("profile already exists: %s", n)
		}
	}
	if err := os.WriteFile(a.profileFilePath(n), []byte(defaultKernelConfigYAML), 0644); err != nil {
		return err
	}
	meta.Profiles = append(meta.Profiles, n)
	return a.saveProfilesMeta(meta)
}

func (a *App) DeleteKernelProfile(name string) error {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return err
	}
	n, err := normalizeProfileName(name)
	if err != nil {
		return err
	}
	if n == defaultKernelProfile {
		return errors.New("default profile cannot be deleted")
	}

	next := make([]string, 0, len(meta.Profiles))
	found := false
	for _, p := range meta.Profiles {
		if p == n {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		return fmt.Errorf("profile not found: %s", n)
	}
	meta.Profiles = next
	if meta.Active == n {
		meta.Active = defaultKernelProfile
	}
	_ = os.Remove(a.profileFilePath(n))
	_ = os.RemoveAll(a.profileRevisionsDir(n))
	a.kernelManagersLock.Lock()
	delete(a.kernelManagers, n)
	a.kernelManagersLock.Unlock()
	a.kernelControllerLock.Lock()
	if a.kernelControllerProfile == n {
		a.stopKernelControllerLocked()
	}
	a.kernelControllerLock.Unlock()
	return a.saveProfilesMeta(meta)
}

func (a *App) LoadKernelProfile(name string) (string, error) {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return "", err
	}
	n := name
	if strings.TrimSpace(n) == "" {
		n = meta.Active
	}
	n, err = normalizeProfileName(n)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(a.profileFilePath(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (a *App) SaveKernelProfile(name string, content string) error {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return err
	}
	n := name
	if strings.TrimSpace(n) == "" {
		n = meta.Active
	}
	n, err = normalizeProfileName(n)
	if err != nil {
		return err
	}

	prev, err := os.ReadFile(a.profileFilePath(n))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(strings.TrimSpace(string(prev))) > 0 && string(prev) != content {
		if err := os.MkdirAll(a.profileRevisionsDir(n), 0755); err != nil {
			return err
		}
		revID := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
		revPath := filepath.Join(a.profileRevisionsDir(n), revID+".yaml")
		if err := os.WriteFile(revPath, prev, 0644); err != nil {
			return err
		}
	}

	if err := os.WriteFile(a.profileFilePath(n), []byte(content), 0644); err != nil {
		return err
	}
	if err := a.reloadKernelManagerForProfile(n, content); err != nil {
		return err
	}
	// Keep legacy kernel path synced to active profile for compatibility.
	if meta.Active == n {
		_ = os.WriteFile(a.kernelPath, []byte(content), 0644)
	}
	return nil
}

func mapManagerStatsToKernelRuntimeStats(profile string, s kernel.ManagerStats) KernelRuntimeStats {
	return KernelRuntimeStats{
		Profile:       profile,
		Version:       s.Version,
		TotalRoutes:   s.TotalRoutes,
		MatchedRoutes: s.MatchedRoutes,
		DefaultRoutes: s.DefaultRoutes,
		LastRule:      s.LastRule,
		LastOutbound:  s.LastOutbound,
		OutboundHits:  s.OutboundHits,
		AdapterHealth: s.AdapterHealth,
	}
}

func generateControllerToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

func (a *App) resolveKernelProfileName(profile string) (string, error) {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(profile)
	if name == "" {
		name = meta.Active
	}
	return normalizeProfileName(name)
}

func (a *App) stopKernelControllerLocked() {
	if a.kernelControllerServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.kernelControllerServer.Shutdown(ctx)
		cancel()
	}
	if a.kernelControllerListener != nil {
		_ = a.kernelControllerListener.Close()
	}
	a.kernelControllerServer = nil
	a.kernelControllerListener = nil
	a.kernelControllerProfile = ""
	a.kernelControllerURL = ""
	a.kernelControllerToken = ""
	a.kernelControllerRequireAuth = false
	a.kernelControllerWrite = false
}

func (a *App) ensureKernelControllerSession(profile string) (controllerSession, error) {
	name, err := a.resolveKernelProfileName(profile)
	if err != nil {
		return controllerSession{}, err
	}

	a.kernelControllerLock.Lock()
	defer a.kernelControllerLock.Unlock()

	if a.kernelControllerClient == nil {
		a.kernelControllerClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	if a.kernelControllerServer != nil && a.kernelControllerProfile == name {
		return controllerSession{
			state: KernelControllerState{
				Running:     true,
				Profile:     a.kernelControllerProfile,
				URL:         a.kernelControllerURL,
				RequireAuth: a.kernelControllerRequireAuth,
				Write:       a.kernelControllerWrite,
			},
			token:  a.kernelControllerToken,
			client: a.kernelControllerClient,
		}, nil
	}

	a.stopKernelControllerLocked()

	mgr, err := a.getKernelManager(name)
	if err != nil {
		return controllerSession{}, err
	}

	token := generateControllerToken()
	controller := kernel.NewControllerWithOptions(mgr, kernel.ControllerOptions{
		RequireAuth: true,
		AuthToken:   token,
		EnableWrite: true,
	})
	server := &http.Server{
		Handler:           controller.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return controllerSession{}, err
	}
	go func() {
		_ = server.Serve(ln)
	}()

	a.kernelControllerServer = server
	a.kernelControllerListener = ln
	a.kernelControllerProfile = name
	a.kernelControllerURL = "http://" + ln.Addr().String()
	a.kernelControllerToken = token
	a.kernelControllerRequireAuth = true
	a.kernelControllerWrite = true

	return controllerSession{
		state: KernelControllerState{
			Running:     true,
			Profile:     name,
			URL:         a.kernelControllerURL,
			RequireAuth: true,
			Write:       true,
		},
		token:  token,
		client: a.kernelControllerClient,
	}, nil
}

func (a *App) callKernelController(profile string, method string, endpoint string, payload []byte) (controllerSession, controllerResponseEnvelope, error) {
	session, err := a.ensureKernelControllerSession(profile)
	if err != nil {
		return controllerSession{}, controllerResponseEnvelope{}, err
	}

	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, session.state.URL+endpoint, body)
	if err != nil {
		return controllerSession{}, controllerResponseEnvelope{}, err
	}
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if session.state.RequireAuth {
		req.Header.Set("X-Controller-Token", session.token)
	}

	resp, err := session.client.Do(req)
	if err != nil {
		return controllerSession{}, controllerResponseEnvelope{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return controllerSession{}, controllerResponseEnvelope{}, err
	}
	respText := strings.TrimSpace(string(respBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if respText == "" {
			respText = http.StatusText(resp.StatusCode)
		}
		return controllerSession{}, controllerResponseEnvelope{}, fmt.Errorf("controller %s %s failed (%d): %s", method, endpoint, resp.StatusCode, respText)
	}

	if len(respBody) == 0 {
		return session, controllerResponseEnvelope{OK: true}, nil
	}

	var envelope controllerResponseEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return controllerSession{}, controllerResponseEnvelope{}, err
	}
	if !envelope.OK {
		msg := strings.TrimSpace(envelope.Message)
		if msg == "" {
			msg = "controller returned non-ok response"
		}
		return controllerSession{}, controllerResponseEnvelope{}, errors.New(msg)
	}
	return session, envelope, nil
}

func (a *App) getKernelManager(profile string) (*kernel.RuntimeManager, error) {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return nil, err
	}
	name := profile
	if strings.TrimSpace(name) == "" {
		name = meta.Active
	}
	name, err = normalizeProfileName(name)
	if err != nil {
		return nil, err
	}

	a.kernelManagersLock.RLock()
	if mgr, ok := a.kernelManagers[name]; ok {
		a.kernelManagersLock.RUnlock()
		return mgr, nil
	}
	a.kernelManagersLock.RUnlock()

	content, err := a.LoadKernelProfile(name)
	if err != nil {
		return nil, err
	}
	mgr, err := kernel.NewRuntimeManagerFromBytes([]byte(content), ".yaml")
	if err != nil {
		return nil, err
	}

	a.kernelManagersLock.Lock()
	if a.kernelManagers == nil {
		a.kernelManagers = map[string]*kernel.RuntimeManager{}
	}
	if existing, ok := a.kernelManagers[name]; ok {
		a.kernelManagersLock.Unlock()
		return existing, nil
	}
	a.kernelManagers[name] = mgr
	a.kernelManagersLock.Unlock()
	return mgr, nil
}

func (a *App) reloadKernelManagerForProfile(profile string, content string) error {
	name, err := normalizeProfileName(profile)
	if err != nil {
		return err
	}

	a.kernelManagersLock.RLock()
	mgr, ok := a.kernelManagers[name]
	a.kernelManagersLock.RUnlock()
	if ok {
		return mgr.ReloadFromBytes([]byte(content), ".yaml")
	}

	newMgr, err := kernel.NewRuntimeManagerFromBytes([]byte(content), ".yaml")
	if err != nil {
		return err
	}
	a.kernelManagersLock.Lock()
	if a.kernelManagers == nil {
		a.kernelManagers = map[string]*kernel.RuntimeManager{}
	}
	a.kernelManagers[name] = newMgr
	a.kernelManagersLock.Unlock()
	return nil
}

func (a *App) LoadKernelConfig() string {
	content, err := a.LoadKernelProfile("")
	if err != nil {
		return defaultKernelConfigYAML
	}
	return content
}

func (a *App) SaveKernelConfig(content string) error {
	return a.SaveKernelProfile("", content)
}

func (a *App) ListKernelProfileRevisions(name string) ([]KernelProfileRevision, error) {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return nil, err
	}
	n := name
	if strings.TrimSpace(n) == "" {
		n = meta.Active
	}
	n, err = normalizeProfileName(n)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(a.profileRevisionsDir(n))
	if err != nil {
		if os.IsNotExist(err) {
			return []KernelProfileRevision{}, nil
		}
		return nil, err
	}

	out := make([]KernelProfileRevision, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(filepath.Ext(e.Name())) != ".yaml" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if !validRevisionID(id) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		createdAt := info.ModTime().UTC().Format(time.RFC3339)
		if ns, err := strconv.ParseInt(id, 10, 64); err == nil {
			createdAt = time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
		}
		out = append(out, KernelProfileRevision{
			ID:        id,
			CreatedAt: createdAt,
			Bytes:     info.Size(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (a *App) RollbackKernelProfile(name string, revisionID string) error {
	meta, err := a.ensureKernelStore()
	if err != nil {
		return err
	}
	n := name
	if strings.TrimSpace(n) == "" {
		n = meta.Active
	}
	n, err = normalizeProfileName(n)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(revisionID)
	if !validRevisionID(id) {
		return errors.New("invalid revision id")
	}

	revPath := filepath.Join(a.profileRevisionsDir(n), id+".yaml")
	content, err := os.ReadFile(revPath)
	if err != nil {
		return err
	}
	return a.SaveKernelProfile(n, string(content))
}

func (a *App) ValidateKernelConfig(content string, format string) KernelValidationResult {
	ext := ".yaml"
	if format == "json" {
		ext = ".json"
	}
	cfg, err := kernel.ParseConfig([]byte(content), ext)
	if err != nil {
		return KernelValidationResult{
			Valid:   false,
			Message: err.Error(),
		}
	}

	defaultTarget := cfg.Routing.DefaultOutbound
	if defaultTarget == "" && len(cfg.Outbounds) > 0 {
		defaultTarget = cfg.Outbounds[0].Name
	}

	return KernelValidationResult{
		Valid:         true,
		Message:       "ok",
		Outbounds:     len(cfg.Outbounds),
		Rules:         len(cfg.Routing.Rules),
		DefaultTarget: defaultTarget,
	}
}

func (a *App) ProbeKernelRoute(profile string, host string, ip string, port int, network string) KernelRouteProbeResult {
	mgr, err := a.getKernelManager(profile)
	if err != nil {
		return KernelRouteProbeResult{
			OK:      false,
			Message: err.Error(),
		}
	}

	var addr netip.Addr
	if strings.TrimSpace(ip) != "" {
		if parsed, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
			addr = parsed
		}
	}

	if port < 0 {
		port = 0
	}
	if port > 65535 {
		port = 65535
	}

	adapter, decision, trace, err := mgr.ExplainRoute(kernel.MatchContext{
		Host:            strings.TrimSpace(host),
		DestinationIP:   addr,
		DestinationPort: uint16(port),
		Network:         strings.ToLower(strings.TrimSpace(network)),
	})
	if err != nil {
		return KernelRouteProbeResult{
			OK:      false,
			Message: err.Error(),
		}
	}

	traceItems := make([]KernelRouteTraceItem, 0, len(trace))
	for _, step := range trace {
		traceItems = append(traceItems, KernelRouteTraceItem{
			Index:    step.Index,
			Rule:     step.Rule,
			Outbound: step.Outbound,
			Matched:  step.Matched,
		})
	}

	return KernelRouteProbeResult{
		OK:          true,
		Message:     "ok",
		Matched:     decision.Matched,
		Rule:        decision.Rule,
		Outbound:    decision.Outbound,
		AdapterType: adapter.Type(),
		Trace:       traceItems,
	}
}

func (a *App) GetKernelRuntimeStats(profile string) KernelRuntimeStats {
	mgr, err := a.getKernelManager(profile)
	if err != nil {
		return KernelRuntimeStats{
			Profile: profile,
		}
	}
	s := mgr.SnapshotStats()
	p, err := a.resolveKernelProfileName(profile)
	if err != nil {
		p = profile
	}
	return mapManagerStatsToKernelRuntimeStats(p, s)
}

func (a *App) ResetKernelRuntimeStats(profile string) error {
	mgr, err := a.getKernelManager(profile)
	if err != nil {
		return err
	}
	mgr.ResetStats()
	return nil
}

func (a *App) GetKernelControllerState(profile string) (KernelControllerState, error) {
	session, err := a.ensureKernelControllerSession(profile)
	if err != nil {
		return KernelControllerState{}, err
	}

	req, err := http.NewRequest(http.MethodGet, session.state.URL+"/v1/health", nil)
	if err != nil {
		return KernelControllerState{}, err
	}
	resp, err := session.client.Do(req)
	if err != nil {
		return KernelControllerState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return KernelControllerState{}, fmt.Errorf("controller health failed (%d)", resp.StatusCode)
	}
	return session.state, nil
}

func (a *App) ControllerGetKernelRuntimeStats(profile string) (KernelRuntimeStats, error) {
	session, envelope, err := a.callKernelController(profile, http.MethodGet, "/v1/runtime", nil)
	if err != nil {
		return KernelRuntimeStats{}, err
	}

	var stats kernel.ManagerStats
	if len(envelope.Data) == 0 {
		return KernelRuntimeStats{}, errors.New("controller runtime response missing data")
	}
	if err := json.Unmarshal(envelope.Data, &stats); err != nil {
		return KernelRuntimeStats{}, err
	}
	return mapManagerStatsToKernelRuntimeStats(session.state.Profile, stats), nil
}

func (a *App) ControllerResetKernelRuntimeStats(profile string) (KernelRuntimeStats, error) {
	session, envelope, err := a.callKernelController(profile, http.MethodPost, "/v1/runtime/reset", nil)
	if err != nil {
		return KernelRuntimeStats{}, err
	}

	var stats kernel.ManagerStats
	if len(envelope.Data) == 0 {
		return KernelRuntimeStats{}, errors.New("controller reset response missing data")
	}
	if err := json.Unmarshal(envelope.Data, &stats); err != nil {
		return KernelRuntimeStats{}, err
	}
	return mapManagerStatsToKernelRuntimeStats(session.state.Profile, stats), nil
}

func (a *App) ControllerGetKernelConfig(profile string) (string, error) {
	_, envelope, err := a.callKernelController(profile, http.MethodGet, "/v1/config", nil)
	if err != nil {
		return "", err
	}
	if len(envelope.Data) == 0 {
		return "", errors.New("controller config response missing data")
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, envelope.Data, "", "  "); err == nil {
		return pretty.String(), nil
	}
	return string(envelope.Data), nil
}

func (a *App) ControllerApplyKernelConfig(profile string, format string, content string) error {
	payload := map[string]string{
		"format":  strings.ToLower(strings.TrimSpace(format)),
		"content": content,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, _, err = a.callKernelController(profile, http.MethodPut, "/v1/config", b)
	return err
}

func (a *App) ProbeKernelRouteText(profile string, destination string) KernelRouteProbeResult {
	// helper format: host|ip|port|network
	parts := strings.Split(destination, "|")
	if len(parts) != 4 {
		return KernelRouteProbeResult{
			OK:      false,
			Message: "destination format must be host|ip|port|network",
		}
	}
	port, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
	return a.ProbeKernelRoute(profile, parts[0], parts[1], port, parts[3])
}
