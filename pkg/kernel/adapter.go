package kernel

import (
	"fmt"
	"strings"
)

type OutboundAdapter interface {
	Name() string
	Type() string
}

type DirectAdapter struct {
	name string
}

func (a *DirectAdapter) Name() string { return a.name }
func (a *DirectAdapter) Type() string { return "direct" }

type BlockAdapter struct {
	name string
}

func (a *BlockAdapter) Name() string { return a.name }
func (a *BlockAdapter) Type() string { return "block" }

type W33DAdapter struct {
	name   string
	server string
	port   int
	pubKey string
	token  string
}

func (a *W33DAdapter) Name() string { return a.name }
func (a *W33DAdapter) Type() string { return "w33d" }

func (a *W33DAdapter) Server() string { return a.server }
func (a *W33DAdapter) Port() int      { return a.port }
func (a *W33DAdapter) PubKey() string { return a.pubKey }
func (a *W33DAdapter) Token() string  { return a.token }

type AdapterRegistry struct {
	adapters map[string]OutboundAdapter
}

func NewAdapterRegistry(cfg Config) (*AdapterRegistry, error) {
	reg := &AdapterRegistry{
		adapters: make(map[string]OutboundAdapter, len(cfg.Outbounds)),
	}

	for _, ob := range cfg.Outbounds {
		adapter, err := buildAdapter(ob)
		if err != nil {
			return nil, err
		}
		reg.adapters[ob.Name] = adapter
	}

	return reg, nil
}

func (r *AdapterRegistry) Get(name string) (OutboundAdapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

func (r *AdapterRegistry) Resolve(d RouteDecision) (OutboundAdapter, error) {
	a, ok := r.adapters[d.Outbound]
	if !ok {
		return nil, fmt.Errorf("outbound adapter not found: %s", d.Outbound)
	}
	return a, nil
}

func buildAdapter(ob OutboundConfig) (OutboundAdapter, error) {
	switch strings.ToLower(strings.TrimSpace(ob.Type)) {
	case "direct":
		return &DirectAdapter{name: ob.Name}, nil
	case "block":
		return &BlockAdapter{name: ob.Name}, nil
	case "w33d":
		if ob.Server == "" || ob.Port <= 0 {
			return nil, fmt.Errorf("w33d outbound %s requires server and port", ob.Name)
		}
		return &W33DAdapter{
			name:   ob.Name,
			server: ob.Server,
			port:   ob.Port,
			pubKey: ob.PubKey,
			token:  ob.Token,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported outbound type: %s", ob.Type)
	}
}
