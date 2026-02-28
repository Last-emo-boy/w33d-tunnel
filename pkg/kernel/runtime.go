package kernel

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

type RuntimeStats struct {
	TotalRoutes   uint64            `json:"total_routes"`
	MatchedRoutes uint64            `json:"matched_routes"`
	DefaultRoutes uint64            `json:"default_routes"`
	OutboundHits  map[string]uint64 `json:"outbound_hits"`
	AdapterHealth map[string]string `json:"adapter_health"`
	LastRule      string            `json:"last_rule"`
	LastOutbound  string            `json:"last_outbound"`
}

type Runtime struct {
	router   *Router
	registry *AdapterRegistry
	dns      *DNSPolicy

	totalRoutes   uint64
	matchedRoutes uint64
	defaultRoutes uint64

	hitsLock     sync.RWMutex
	outboundHits map[string]uint64
	lastRule     string
	lastOutbound string
}

func NewRuntime(cfg Config) (*Runtime, error) {
	router, err := NewRouter(cfg)
	if err != nil {
		return nil, err
	}
	registry, err := NewAdapterRegistry(cfg)
	if err != nil {
		return nil, err
	}
	dnsPolicy, err := NewDNSPolicy(cfg.DNS)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		router:       router,
		registry:     registry,
		dns:          dnsPolicy,
		outboundHits: map[string]uint64{},
	}, nil
}

func (r *Runtime) SelectAdapter(ctx MatchContext) (OutboundAdapter, RouteDecision, error) {
	decision := r.router.Route(ctx)
	adapter, err := r.registry.Resolve(decision)
	if err != nil {
		return nil, decision, err
	}
	r.recordDecision(decision)
	return adapter, decision, nil
}

func (r *Runtime) ExplainRoute(ctx MatchContext) (OutboundAdapter, RouteDecision, []RuleTrace, error) {
	decision, trace := r.router.Trace(ctx)
	adapter, err := r.registry.Resolve(decision)
	if err != nil {
		return nil, decision, trace, err
	}
	r.recordDecision(decision)
	return adapter, decision, trace, nil
}

func (r *Runtime) ResolveDNSQuery(host string, qtype string) (DNSDecision, error) {
	if r.dns == nil {
		return DNSDecision{}, errors.New("dns policy is disabled")
	}
	route := r.router.Route(MatchContext{
		Host:            strings.TrimSpace(host),
		DestinationPort: 53,
		Network:         "udp",
	})
	return r.dns.Decide(host, qtype, route)
}

func (r *Runtime) recordDecision(d RouteDecision) {
	atomic.AddUint64(&r.totalRoutes, 1)
	if d.Matched {
		atomic.AddUint64(&r.matchedRoutes, 1)
	} else {
		atomic.AddUint64(&r.defaultRoutes, 1)
	}

	r.hitsLock.Lock()
	r.outboundHits[d.Outbound]++
	r.lastRule = d.Rule
	r.lastOutbound = d.Outbound
	r.hitsLock.Unlock()
}

func (r *Runtime) SnapshotStats() RuntimeStats {
	stats := RuntimeStats{
		TotalRoutes:   atomic.LoadUint64(&r.totalRoutes),
		MatchedRoutes: atomic.LoadUint64(&r.matchedRoutes),
		DefaultRoutes: atomic.LoadUint64(&r.defaultRoutes),
		OutboundHits:  map[string]uint64{},
		AdapterHealth: map[string]string{},
	}

	r.hitsLock.RLock()
	for k, v := range r.outboundHits {
		stats.OutboundHits[k] = v
	}
	stats.LastRule = r.lastRule
	stats.LastOutbound = r.lastOutbound
	r.hitsLock.RUnlock()

	for name := range r.registry.adapters {
		if stats.OutboundHits[name] > 0 {
			stats.AdapterHealth[name] = "active"
		} else {
			stats.AdapterHealth[name] = "idle"
		}
	}

	return stats
}

func (r *Runtime) ResetStats() {
	atomic.StoreUint64(&r.totalRoutes, 0)
	atomic.StoreUint64(&r.matchedRoutes, 0)
	atomic.StoreUint64(&r.defaultRoutes, 0)

	r.hitsLock.Lock()
	r.outboundHits = map[string]uint64{}
	r.lastRule = ""
	r.lastOutbound = ""
	r.hitsLock.Unlock()
}
