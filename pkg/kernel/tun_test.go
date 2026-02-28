package kernel

import "testing"

func testRuntimeForTun(t *testing.T) *Runtime {
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
	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("new runtime failed: %v", err)
	}
	return rt
}

func TestTunIngressLifecycleAndDispatch(t *testing.T) {
	rt := testRuntimeForTun(t)
	tun := NewTunIngress(rt)

	if _, err := tun.Dispatch(TunPacketMetadata{
		Network: "tcp",
		Host:    "api.telegram.org",
		DstPort: 443,
	}); err == nil {
		t.Fatal("expected dispatch failure when tun not running")
	}

	tun.Start()
	if !tun.Running() {
		t.Fatal("expected tun to be running")
	}

	res, err := tun.Dispatch(TunPacketMetadata{
		Network: "tcp",
		Host:    "api.telegram.org",
		DstPort: 443,
	})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if res.Decision.Outbound != "proxy" {
		t.Fatalf("expected proxy outbound, got %s", res.Decision.Outbound)
	}

	tun.Stop()
	if tun.Running() {
		t.Fatal("expected tun to stop")
	}
}

func TestTunIngressSniffHTTPHost(t *testing.T) {
	rt := testRuntimeForTun(t)
	tun := NewTunIngress(rt)
	tun.Start()

	payload := []byte("GET / HTTP/1.1\r\nHost: api.telegram.org\r\nUser-Agent: test\r\n\r\n")
	res, err := tun.Dispatch(TunPacketMetadata{
		Network: "tcp",
		DstPort: 80,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if res.Context.Host != "api.telegram.org" {
		t.Fatalf("expected sniffed host api.telegram.org, got %s", res.Context.Host)
	}
	if res.Decision.Outbound != "proxy" {
		t.Fatalf("expected proxy outbound from sniffed host, got %s", res.Decision.Outbound)
	}
}
