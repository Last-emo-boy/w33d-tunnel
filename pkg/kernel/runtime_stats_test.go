package kernel

import "testing"

func TestRuntimeStatsCountRoutes(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "proxy", Type: "w33d", Server: "1.2.3.4", Port: 8080},
			{Name: "blocked", Type: "block"},
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

	_, _, err = rt.SelectAdapter(MatchContext{Host: "api.telegram.org", DestinationPort: 443, Network: "tcp"})
	if err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}
	_, _, err = rt.SelectAdapter(MatchContext{Host: "example.com", DestinationPort: 443, Network: "tcp"})
	if err != nil {
		t.Fatalf("select adapter failed: %v", err)
	}

	s := rt.SnapshotStats()
	if s.TotalRoutes != 2 {
		t.Fatalf("expected total routes 2, got %d", s.TotalRoutes)
	}
	if s.MatchedRoutes != 1 {
		t.Fatalf("expected matched routes 1, got %d", s.MatchedRoutes)
	}
	if s.DefaultRoutes != 1 {
		t.Fatalf("expected default routes 1, got %d", s.DefaultRoutes)
	}
	if s.OutboundHits["proxy"] != 1 || s.OutboundHits["direct"] != 1 {
		t.Fatalf("unexpected outbound hits: %+v", s.OutboundHits)
	}
	if s.AdapterHealth["proxy"] != "active" || s.AdapterHealth["direct"] != "active" || s.AdapterHealth["blocked"] != "idle" {
		t.Fatalf("unexpected adapter health: %+v", s.AdapterHealth)
	}
}
