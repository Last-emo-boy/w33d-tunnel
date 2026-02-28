package kernel

import (
	"encoding/json"
	"sync"
)

type ManagerStats struct {
	Version uint64 `json:"version"`
	RuntimeStats
}

type RuntimeManager struct {
	lock    sync.RWMutex
	runtime *Runtime
	config  Config
	version uint64
}

func NewRuntimeManager(cfg Config) (*RuntimeManager, error) {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return &RuntimeManager{
		runtime: rt,
		config:  cfg,
		version: 1,
	}, nil
}

func NewRuntimeManagerFromBytes(data []byte, ext string) (*RuntimeManager, error) {
	cfg, err := ParseConfig(data, ext)
	if err != nil {
		return nil, err
	}
	return NewRuntimeManager(cfg)
}

func (m *RuntimeManager) ReloadFromConfig(cfg Config) error {
	rt, err := NewRuntime(cfg)
	if err != nil {
		return err
	}
	m.lock.Lock()
	m.runtime = rt
	m.config = cfg
	m.version++
	m.lock.Unlock()
	return nil
}

func (m *RuntimeManager) ReloadFromBytes(data []byte, ext string) error {
	cfg, err := ParseConfig(data, ext)
	if err != nil {
		return err
	}
	return m.ReloadFromConfig(cfg)
}

func (m *RuntimeManager) SelectAdapter(ctx MatchContext) (OutboundAdapter, RouteDecision, error) {
	m.lock.RLock()
	rt := m.runtime
	m.lock.RUnlock()
	return rt.SelectAdapter(ctx)
}

func (m *RuntimeManager) ExplainRoute(ctx MatchContext) (OutboundAdapter, RouteDecision, []RuleTrace, error) {
	m.lock.RLock()
	rt := m.runtime
	m.lock.RUnlock()
	return rt.ExplainRoute(ctx)
}

func (m *RuntimeManager) ResolveDNSQuery(host string, qtype string) (DNSDecision, error) {
	m.lock.RLock()
	rt := m.runtime
	m.lock.RUnlock()
	return rt.ResolveDNSQuery(host, qtype)
}

func (m *RuntimeManager) SnapshotStats() ManagerStats {
	m.lock.RLock()
	version := m.version
	rt := m.runtime
	m.lock.RUnlock()
	stats := rt.SnapshotStats()
	return ManagerStats{
		Version:      version,
		RuntimeStats: stats,
	}
}

func (m *RuntimeManager) ResetStats() {
	m.lock.RLock()
	rt := m.runtime
	m.lock.RUnlock()
	rt.ResetStats()
}

func (m *RuntimeManager) Version() uint64 {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.version
}

func (m *RuntimeManager) SnapshotConfig() Config {
	m.lock.RLock()
	cfg := m.config
	m.lock.RUnlock()

	// Return a detached copy so callers can't mutate live runtime config references.
	var cloned Config
	if b, err := json.Marshal(cfg); err == nil {
		_ = json.Unmarshal(b, &cloned)
		return cloned
	}
	return cfg
}
