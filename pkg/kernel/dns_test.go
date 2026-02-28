package kernel

import (
	"net/netip"
	"testing"
)

func TestRuntimeResolveDNSQueryFakeIPMode(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "proxy", Type: "w33d", Server: "1.2.3.4", Port: 8080},
		},
		DNS: DNSConfig{
			Enabled:     true,
			Mode:        "fake-ip",
			FakeIPRange: "198.18.0.0/16",
			Upstreams:   []string{"1.1.1.1"},
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

	d1, err := rt.ResolveDNSQuery("api.telegram.org", "A")
	if err != nil {
		t.Fatalf("resolve dns query failed: %v", err)
	}
	if d1.Mode != "fake-ip" {
		t.Fatalf("expected fake-ip mode, got %s", d1.Mode)
	}
	if d1.FakeIP == "" {
		t.Fatal("expected fake ip allocation")
	}
	if d1.Outbound != "proxy" {
		t.Fatalf("expected outbound proxy, got %s", d1.Outbound)
	}

	ip, err := netip.ParseAddr(d1.FakeIP)
	if err != nil {
		t.Fatalf("invalid fake ip %q: %v", d1.FakeIP, err)
	}
	prefix := netip.MustParsePrefix("198.18.0.0/16")
	if !prefix.Contains(ip) {
		t.Fatalf("fake ip %s should be in %s", ip, prefix)
	}

	d2, err := rt.ResolveDNSQuery("api.telegram.org", "A")
	if err != nil {
		t.Fatalf("resolve dns query failed: %v", err)
	}
	if d1.FakeIP != d2.FakeIP {
		t.Fatalf("expected stable fake ip mapping, got %s vs %s", d1.FakeIP, d2.FakeIP)
	}
}

func TestRuntimeResolveDNSQueryNormalMode(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		DNS: DNSConfig{
			Enabled:   true,
			Mode:      "normal",
			Upstreams: []string{"8.8.8.8"},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
			Rules:           []RuleConfig{},
		},
	}

	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("new runtime failed: %v", err)
	}

	d, err := rt.ResolveDNSQuery("example.com", "A")
	if err != nil {
		t.Fatalf("resolve dns query failed: %v", err)
	}
	if d.Mode != "normal" {
		t.Fatalf("expected normal mode, got %s", d.Mode)
	}
	if d.FakeIP != "" {
		t.Fatalf("expected empty fake ip, got %s", d.FakeIP)
	}
	if d.Upstream != "8.8.8.8" {
		t.Fatalf("expected upstream 8.8.8.8, got %s", d.Upstream)
	}
}

func TestRuntimeResolveDNSQueryDisabledPolicy(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
		},
	}

	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("new runtime failed: %v", err)
	}

	if _, err := rt.ResolveDNSQuery("example.com", "A"); err == nil {
		t.Fatal("expected error when dns policy disabled")
	}
}
