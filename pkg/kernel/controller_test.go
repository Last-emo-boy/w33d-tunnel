package kernel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestRuntimeManager(t *testing.T) *RuntimeManager {
	t.Helper()
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "proxy", Type: "w33d", Server: "1.2.3.4", Port: 8080},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
			Rules: []RuleConfig{
				{Type: "domain_suffix", Value: "telegram.org", Outbound: "proxy"},
			},
		},
	}
	mgr, err := NewRuntimeManager(cfg)
	if err != nil {
		t.Fatalf("new manager failed: %v", err)
	}
	return mgr
}

func TestControllerRuntimeAndConfigEndpoints(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewController(mgr)
	h := controller.Handler()

	// Produce one route decision so runtime stats are non-zero.
	if _, _, err := mgr.SelectAdapter(MatchContext{
		Host:            "api.telegram.org",
		DestinationPort: 443,
		Network:         "tcp",
	}); err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}

	runtimeReq := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	runtimeRR := httptest.NewRecorder()
	h.ServeHTTP(runtimeRR, runtimeReq)
	if runtimeRR.Code != http.StatusOK {
		t.Fatalf("runtime endpoint status=%d", runtimeRR.Code)
	}
	if runtimeRR.Body.String() == "" {
		t.Fatal("expected runtime endpoint response body")
	}

	configReq := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	configRR := httptest.NewRecorder()
	h.ServeHTTP(configRR, configReq)
	if configRR.Code != http.StatusOK {
		t.Fatalf("config endpoint status=%d", configRR.Code)
	}
	if configRR.Body.String() == "" {
		t.Fatal("expected config endpoint response body")
	}
}

func TestControllerMethodNotAllowed(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewController(mgr)
	h := controller.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestControllerAuthRequired(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewControllerWithOptions(mgr, ControllerOptions{
		RequireAuth: true,
		AuthToken:   "controller-token",
	})
	h := controller.Handler()

	reqNoToken := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	rrNoToken := httptest.NewRecorder()
	h.ServeHTTP(rrNoToken, reqNoToken)
	if rrNoToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth token, got %d", rrNoToken.Code)
	}

	reqOK := httptest.NewRequest(http.MethodGet, "/v1/runtime", nil)
	reqOK.Header.Set("X-Controller-Token", "controller-token")
	rrOK := httptest.NewRecorder()
	h.ServeHTTP(rrOK, reqOK)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with auth token, got %d", rrOK.Code)
	}
}

func TestControllerWriteDisabledByDefault(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewController(mgr)
	h := controller.Handler()

	putReq := httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewBufferString(`{"content":"outbounds: []"}`))
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for write config when disabled, got %d", putRR.Code)
	}

	resetReq := httptest.NewRequest(http.MethodPost, "/v1/runtime/reset", nil)
	resetRR := httptest.NewRecorder()
	h.ServeHTTP(resetRR, resetReq)
	if resetRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for reset runtime when disabled, got %d", resetRR.Code)
	}
}

func TestControllerReloadConfigAndResetStats(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewControllerWithOptions(mgr, ControllerOptions{
		RequireAuth: true,
		AuthToken:   "controller-token",
		EnableWrite: true,
	})
	h := controller.Handler()

	// Generate one route hit for runtime stats.
	if _, _, err := mgr.SelectAdapter(MatchContext{
		Host:            "api.telegram.org",
		DestinationPort: 443,
		Network:         "tcp",
	}); err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}

	resetReq := httptest.NewRequest(http.MethodPost, "/v1/runtime/reset", nil)
	resetReq.Header.Set("X-Controller-Token", "controller-token")
	resetRR := httptest.NewRecorder()
	h.ServeHTTP(resetRR, resetReq)
	if resetRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for reset runtime, got %d", resetRR.Code)
	}
	if mgr.SnapshotStats().TotalRoutes != 0 {
		t.Fatalf("expected runtime stats reset to zero, got %d", mgr.SnapshotStats().TotalRoutes)
	}

	v1 := mgr.Version()
	payload := `{
  "format": "yaml",
  "content": "outbounds:\n  - name: direct\n    type: direct\n  - name: proxy\n    type: w33d\n    server: 1.2.3.4\n    port: 8080\nrouting:\n  default_outbound: direct\n  rules:\n    - type: domain_suffix\n      value: example.com\n      outbound: proxy\n"
}`
	reloadReq := httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewBufferString(payload))
	reloadReq.Header.Set("X-Controller-Token", "controller-token")
	reloadRR := httptest.NewRecorder()
	h.ServeHTTP(reloadRR, reloadReq)
	if reloadRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for reload config, got %d body=%s", reloadRR.Code, reloadRR.Body.String())
	}
	if mgr.Version() != v1+1 {
		t.Fatalf("expected manager version increment, got %d want %d", mgr.Version(), v1+1)
	}

	adapter, d, err := mgr.SelectAdapter(MatchContext{
		Host:            "www.example.com",
		DestinationPort: 443,
		Network:         "tcp",
	})
	if err != nil {
		t.Fatalf("select adapter failed after reload: %v", err)
	}
	if adapter.Name() != "proxy" || d.Outbound != "proxy" {
		t.Fatalf("expected reloaded config routing to proxy, got adapter=%s outbound=%s", adapter.Name(), d.Outbound)
	}
}

func TestControllerRejectsInvalidConfigReload(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewControllerWithOptions(mgr, ControllerOptions{
		EnableWrite: true,
	})
	h := controller.Handler()

	v1 := mgr.Version()
	badReq := httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewBufferString(`{"format":"yaml","content":"outbounds: []"}`))
	badRR := httptest.NewRecorder()
	h.ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid config reload, got %d", badRR.Code)
	}
	if mgr.Version() != v1 {
		t.Fatalf("manager version should not change on invalid reload, got %d want %d", mgr.Version(), v1)
	}
}

func TestControllerConfigReloadFromStructuredJSON(t *testing.T) {
	mgr := newTestRuntimeManager(t)
	controller := NewControllerWithOptions(mgr, ControllerOptions{
		EnableWrite: true,
	})
	h := controller.Handler()

	reqBody, _ := json.Marshal(map[string]interface{}{
		"config": Config{
			Outbounds: []OutboundConfig{
				{Name: "direct", Type: "direct"},
				{Name: "proxy", Type: "w33d", Server: "1.2.3.4", Port: 8080},
			},
			Routing: RoutingConfig{
				DefaultOutbound: "direct",
				Rules: []RuleConfig{
					{Type: "domain_suffix", Value: "example.org", Outbound: "proxy"},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodPut, "/v1/config", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for structured config reload, got %d body=%s", rr.Code, rr.Body.String())
	}

	adapter, d, err := mgr.SelectAdapter(MatchContext{Host: "api.example.org", DestinationPort: 443, Network: "tcp"})
	if err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}
	if adapter.Name() != "proxy" || d.Outbound != "proxy" {
		t.Fatalf("expected proxy route after structured config reload, got adapter=%s outbound=%s", adapter.Name(), d.Outbound)
	}
}
