package kernel

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Controller struct {
	manager *RuntimeManager
	opts    ControllerOptions
}

type ControllerOptions struct {
	RequireAuth bool
	AuthToken   string
	EnableWrite bool
}

type ControllerResponse struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func NewController(manager *RuntimeManager) *Controller {
	return &Controller{
		manager: manager,
		opts:    ControllerOptions{},
	}
}

func NewControllerWithOptions(manager *RuntimeManager, opts ControllerOptions) *Controller {
	return &Controller{
		manager: manager,
		opts:    opts,
	}
}

func (c *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", c.handleHealth)
	mux.HandleFunc("/v1/runtime", c.handleRuntime)
	mux.HandleFunc("/v1/runtime/reset", c.handleRuntimeReset)
	mux.HandleFunc("/v1/config", c.handleConfig)
	return mux
}

func (c *Controller) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (c *Controller) handleRuntime(w http.ResponseWriter, r *http.Request) {
	if err := c.requireAuth(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ControllerResponse{
		OK:   true,
		Data: c.manager.SnapshotStats(),
	})
}

func (c *Controller) handleRuntimeReset(w http.ResponseWriter, r *http.Request) {
	if err := c.requireAuth(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.opts.EnableWrite {
		http.Error(w, "controller write operations disabled", http.StatusForbidden)
		return
	}

	c.manager.ResetStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ControllerResponse{
		OK:      true,
		Message: "runtime stats reset",
		Data:    c.manager.SnapshotStats(),
	})
}

func (c *Controller) handleConfig(w http.ResponseWriter, r *http.Request) {
	if err := c.requireAuth(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ControllerResponse{
			OK:   true,
			Data: c.manager.SnapshotConfig(),
		})
	case http.MethodPut:
		if !c.opts.EnableWrite {
			http.Error(w, "controller write operations disabled", http.StatusForbidden)
			return
		}
		if err := c.reloadConfigFromRequest(r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ControllerResponse{
			OK:      true,
			Message: "config reloaded",
			Data: map[string]uint64{
				"version": c.manager.Version(),
			},
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *Controller) requireAuth(r *http.Request) error {
	if !c.opts.RequireAuth {
		return nil
	}
	if strings.TrimSpace(c.opts.AuthToken) == "" {
		return errors.New("controller auth token not configured")
	}
	got := r.Header.Get("X-Controller-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.opts.AuthToken)) != 1 {
		return errors.New("unauthorized")
	}
	return nil
}

type configReloadRequest struct {
	Format  string  `json:"format"`
	Content string  `json:"content"`
	Config  *Config `json:"config"`
}

func (c *Controller) reloadConfigFromRequest(r *http.Request) error {
	var req configReloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	if req.Config != nil {
		return c.manager.ReloadFromConfig(*req.Config)
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		return errors.New("config payload is empty")
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	ext := ".yaml"
	if format == "json" || strings.HasPrefix(content, "{") {
		ext = ".json"
	}
	return c.manager.ReloadFromBytes([]byte(content), ext)
}
