package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

const defaultFakeIPRange = "198.18.0.0/16"

type DNSDecision struct {
	Query    string `json:"query"`
	QType    string `json:"qtype"`
	Mode     string `json:"mode"`
	Upstream string `json:"upstream"`
	FakeIP   string `json:"fake_ip"`
	Outbound string `json:"outbound"`
	Rule     string `json:"rule"`
	Matched  bool   `json:"matched"`
}

type DNSPolicy struct {
	mode      string
	upstreams []string
	fakePool  *FakeIPPool
}

func NewDNSPolicy(cfg DNSConfig) (*DNSPolicy, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "normal"
	}

	upstreams := append([]string{}, cfg.Upstreams...)
	if len(upstreams) == 0 {
		upstreams = []string{"system"}
	}

	p := &DNSPolicy{
		mode:      mode,
		upstreams: upstreams,
	}

	if mode == "fake-ip" {
		fakeRange := strings.TrimSpace(cfg.FakeIPRange)
		if fakeRange == "" {
			fakeRange = defaultFakeIPRange
		}
		pool, err := NewFakeIPPool(fakeRange)
		if err != nil {
			return nil, err
		}
		p.fakePool = pool
	}

	return p, nil
}

func (p *DNSPolicy) Decide(query string, qtype string, route RouteDecision) (DNSDecision, error) {
	d := DNSDecision{
		Query:    strings.TrimSpace(query),
		QType:    strings.ToUpper(strings.TrimSpace(qtype)),
		Mode:     p.mode,
		Upstream: p.upstreams[0],
		Outbound: route.Outbound,
		Rule:     route.Rule,
		Matched:  route.Matched,
	}

	if p.mode == "fake-ip" && isFakeIPQueryType(d.QType) {
		addr, err := p.fakePool.Allocate(d.Query)
		if err != nil {
			return DNSDecision{}, err
		}
		d.FakeIP = addr.String()
	}

	return d, nil
}

func isFakeIPQueryType(qtype string) bool {
	return qtype == "" || qtype == "A" || qtype == "AAAA"
}

type FakeIPPool struct {
	lock       sync.Mutex
	base       uint32
	hostMax    uint32
	nextHost   uint32
	domainToIP map[string]netip.Addr
	ipToDomain map[netip.Addr]string
}

func NewFakeIPPool(cidr string) (*FakeIPPool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	if !prefix.Addr().Is4() {
		return nil, errors.New("fake-ip range must be ipv4 cidr")
	}

	ones := prefix.Bits()
	if ones < 8 || ones > 30 {
		return nil, fmt.Errorf("fake-ip prefix size must be in [/8, /30], got /%d", ones)
	}

	hostCount := uint32(1) << uint32(32-ones)
	if hostCount <= 2 {
		return nil, errors.New("fake-ip range too small")
	}

	base := ipv4ToUint32(prefix.Masked().Addr())
	return &FakeIPPool{
		base:       base,
		hostMax:    hostCount - 1, // broadcast reserved
		nextHost:   1,             // network reserved
		domainToIP: map[string]netip.Addr{},
		ipToDomain: map[netip.Addr]string{},
	}, nil
}

func (p *FakeIPPool) Allocate(domain string) (netip.Addr, error) {
	key := strings.ToLower(strings.TrimSpace(domain))
	if key == "" {
		return netip.Addr{}, errors.New("domain cannot be empty")
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	if addr, ok := p.domainToIP[key]; ok {
		return addr, nil
	}

	for tries := uint32(0); tries < p.hostMax; tries++ {
		host := p.nextHost
		p.nextHost++
		if p.nextHost >= p.hostMax {
			p.nextHost = 1
		}
		if host == 0 || host >= p.hostMax {
			continue
		}

		addr := uint32ToIPv4(p.base + host)
		if _, used := p.ipToDomain[addr]; used {
			continue
		}

		p.domainToIP[key] = addr
		p.ipToDomain[addr] = key
		return addr, nil
	}

	return netip.Addr{}, errors.New("fake-ip pool exhausted")
}

func (p *FakeIPPool) Lookup(addr netip.Addr) (string, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	domain, ok := p.ipToDomain[addr]
	return domain, ok
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
