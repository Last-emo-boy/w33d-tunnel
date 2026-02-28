package kernel

import (
	"net/netip"
	"testing"
)

func newTestRouter(t *testing.T) *Router {
	t.Helper()
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
			{Name: "proxy", Type: "w33d"},
			{Name: "dns", Type: "direct"},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "direct",
			Rules: []RuleConfig{
				{Type: "domain_suffix", Value: "telegram.org", Outbound: "proxy"},
				{Type: "ip_cidr", Value: "10.0.0.0/8", Outbound: "proxy"},
				{Type: "port", Value: "53", Outbound: "dns"},
			},
		},
	}
	r, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("new router failed: %v", err)
	}
	return r
}

func TestRouteByDomainSuffix(t *testing.T) {
	r := newTestRouter(t)
	d := r.Route(MatchContext{
		Host:            "api.telegram.org",
		DestinationPort: 443,
		Network:         "tcp",
	})
	if d.Outbound != "proxy" || !d.Matched {
		t.Fatalf("expected proxy match, got %+v", d)
	}
}

func TestRouteByCIDR(t *testing.T) {
	r := newTestRouter(t)
	ip, _ := netip.ParseAddr("10.1.2.3")
	d := r.Route(MatchContext{
		DestinationIP:   ip,
		DestinationPort: 443,
		Network:         "tcp",
	})
	if d.Outbound != "proxy" || !d.Matched {
		t.Fatalf("expected proxy cidr match, got %+v", d)
	}
}

func TestRouteByPort(t *testing.T) {
	r := newTestRouter(t)
	d := r.Route(MatchContext{
		Host:            "resolver.local",
		DestinationPort: 53,
		Network:         "udp",
	})
	if d.Outbound != "dns" || !d.Matched {
		t.Fatalf("expected dns port match, got %+v", d)
	}
}

func TestRouteFallsBackToDefault(t *testing.T) {
	r := newTestRouter(t)
	d := r.Route(MatchContext{
		Host:            "example.com",
		DestinationPort: 443,
		Network:         "tcp",
	})
	if d.Outbound != "direct" || d.Matched {
		t.Fatalf("expected default direct route, got %+v", d)
	}
}

func TestNewRouterRejectsInvalidRule(t *testing.T) {
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "direct", Type: "direct"},
		},
		Routing: RoutingConfig{
			Rules: []RuleConfig{
				{Type: "ip_cidr", Value: "not-a-cidr", Outbound: "direct"},
			},
		},
	}
	if _, err := NewRouter(cfg); err == nil {
		t.Fatal("expected invalid rule compile error")
	}
}

func TestRouterTraceShowsRuleEvaluationChain(t *testing.T) {
	r := newTestRouter(t)

	decision, trace := r.Trace(MatchContext{
		Host:            "api.telegram.org",
		DestinationPort: 443,
		Network:         "tcp",
	})

	if !decision.Matched || decision.Outbound != "proxy" {
		t.Fatalf("expected proxy decision, got %+v", decision)
	}
	if len(trace) == 0 {
		t.Fatal("expected non-empty trace")
	}
	if !trace[0].Matched {
		t.Fatalf("expected first rule to match, got %+v", trace[0])
	}
}
