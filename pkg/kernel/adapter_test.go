package kernel

import "testing"

func TestNewAdapterRegistryBuildsTypedAdapters(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "blocked", Type: "block"},
			{Name: "main", Type: "w33d", Server: "1.2.3.4", Port: 8080, PubKey: "abc", Token: "tok"},
		},
	}

	reg, err := NewAdapterRegistry(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	a, ok := reg.Get("main")
	if !ok {
		t.Fatal("expected main adapter")
	}
	if a.Type() != "w33d" {
		t.Fatalf("expected w33d adapter, got %s", a.Type())
	}
}

func TestNewAdapterRegistryRejectsUnsupportedType(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "x", Type: "unknown"},
		},
	}
	if _, err := NewAdapterRegistry(cfg); err == nil {
		t.Fatal("expected unsupported type error")
	}
}

func TestRuntimeSelectAdapter(t *testing.T) {
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

	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("new runtime failed: %v", err)
	}

	adapter, decision, err := rt.SelectAdapter(MatchContext{
		Host: "api.telegram.org",
	})
	if err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}
	if adapter.Name() != "proxy" {
		t.Fatalf("expected proxy adapter, got %s", adapter.Name())
	}
	if !decision.Matched {
		t.Fatal("expected matched decision")
	}
}
