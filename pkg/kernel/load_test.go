package kernel

import "testing"

func TestParseConfigYAML(t *testing.T) {
	data := []byte(`
outbounds:
  - name: direct
    type: direct
  - name: main
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: main
`)

	cfg, err := ParseConfig(data, ".yaml")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(cfg.Outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(cfg.Outbounds))
	}
}

func TestValidateConfigRejectsUnknownDefaultOutbound(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "missing",
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for missing default outbound")
	}
}

func TestValidateConfigRejectsUnknownRuleOutbound(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		Routing: RoutingConfig{
			Rules: []RuleConfig{
				{Type: "domain_suffix", Value: "example.com", Outbound: "proxy"},
			},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for missing rule outbound")
	}
}

func TestValidateConfigRejectsInvalidDNSFakeIPRange(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		DNS: DNSConfig{
			Enabled:     true,
			Mode:        "fake-ip",
			FakeIPRange: "bad-cidr",
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for invalid dns fake_ip_range")
	}
}

func TestValidateConfigRejectsUnsupportedDNSMode(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		DNS: DNSConfig{
			Enabled: true,
			Mode:    "unknown-mode",
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for unsupported dns mode")
	}
}
