package kernel

import "testing"

func TestRuntimeManagerReloadKeepsOldRuntimeOnInvalidConfig(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
		},
	}
	m, err := NewRuntimeManager(cfg)
	if err != nil {
		t.Fatalf("new manager failed: %v", err)
	}
	v1 := m.Version()

	invalid := []byte(`outbounds: []`)
	if err := m.ReloadFromBytes(invalid, ".yaml"); err == nil {
		t.Fatal("expected reload error for invalid config")
	}

	if m.Version() != v1 {
		t.Fatalf("version should not change on invalid reload, got %d want %d", m.Version(), v1)
	}
}

func TestRuntimeManagerReloadSwapsRuntimeOnValidConfig(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "proxy", Type: "w33d", Server: "1.2.3.4", Port: 8080},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
		},
	}
	m, err := NewRuntimeManager(cfg)
	if err != nil {
		t.Fatalf("new manager failed: %v", err)
	}
	v1 := m.Version()

	valid := []byte(`
outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: proxy
`)
	if err := m.ReloadFromBytes(valid, ".yaml"); err != nil {
		t.Fatalf("unexpected reload error: %v", err)
	}
	if m.Version() != v1+1 {
		t.Fatalf("expected version increment, got %d", m.Version())
	}

	adapter, d, err := m.SelectAdapter(MatchContext{Host: "api.telegram.org", Network: "tcp", DestinationPort: 443})
	if err != nil {
		t.Fatalf("select after reload failed: %v", err)
	}
	if adapter.Name() != "proxy" || d.Outbound != "proxy" {
		t.Fatalf("expected proxy route after reload, got adapter=%s outbound=%s", adapter.Name(), d.Outbound)
	}
}
