package kernel

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"sync"
)

type TunPacketMetadata struct {
	Network string
	SrcIP   netip.Addr
	DstIP   netip.Addr
	DstPort uint16
	Host    string
	Payload []byte
}

type TunRouteResult struct {
	Context   MatchContext  `json:"context"`
	Decision  RouteDecision `json:"decision"`
	Adapter   string        `json:"adapter"`
	AdapterTy string        `json:"adapter_type"`
}

type TunIngress struct {
	lock    sync.RWMutex
	runtime *Runtime
	running bool
}

func NewTunIngress(runtime *Runtime) *TunIngress {
	return &TunIngress{runtime: runtime}
}

func (t *TunIngress) Start() {
	t.lock.Lock()
	t.running = true
	t.lock.Unlock()
}

func (t *TunIngress) Stop() {
	t.lock.Lock()
	t.running = false
	t.lock.Unlock()
}

func (t *TunIngress) Running() bool {
	t.lock.RLock()
	running := t.running
	t.lock.RUnlock()
	return running
}

func (t *TunIngress) Dispatch(meta TunPacketMetadata) (TunRouteResult, error) {
	t.lock.RLock()
	running := t.running
	rt := t.runtime
	t.lock.RUnlock()

	if !running {
		return TunRouteResult{}, errors.New("tun ingress is not running")
	}
	if rt == nil {
		return TunRouteResult{}, errors.New("tun ingress runtime is nil")
	}

	network := strings.ToLower(strings.TrimSpace(meta.Network))
	if network == "" {
		network = "tcp"
	}

	host := strings.TrimSpace(meta.Host)
	if host == "" {
		host = sniffHost(meta.Payload)
	}

	ctx := MatchContext{
		Host:            host,
		DestinationIP:   meta.DstIP,
		DestinationPort: meta.DstPort,
		Network:         network,
	}

	adapter, decision, err := rt.SelectAdapter(ctx)
	if err != nil {
		return TunRouteResult{}, err
	}

	return TunRouteResult{
		Context:   ctx,
		Decision:  decision,
		Adapter:   adapter.Name(),
		AdapterTy: adapter.Type(),
	}, nil
}

func sniffHost(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	// Minimal HTTP host sniffing baseline for TUN ingress skeleton.
	lines := bytes.Split(payload, []byte("\r\n"))
	for _, line := range lines {
		lower := strings.ToLower(string(line))
		if strings.HasPrefix(lower, "host:") {
			return strings.TrimSpace(string(line[5:]))
		}
	}
	return ""
}
