package kernel

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type MatchContext struct {
	Host            string
	DestinationIP   netip.Addr
	DestinationPort uint16
	Network         string // tcp / udp
}

type RouteDecision struct {
	Outbound string
	Rule     string
	Matched  bool
}

type RuleTrace struct {
	Index    int    `json:"index"`
	Rule     string `json:"rule"`
	Outbound string `json:"outbound"`
	Matched  bool   `json:"matched"`
}

type Router struct {
	rules           []compiledRule
	defaultOutbound string
}

type compiledRule struct {
	outbound string
	desc     string
	match    func(MatchContext) bool
}

func NewRouter(cfg Config) (*Router, error) {
	var err error
	cfg, err = ResolveRuleProviders(cfg)
	if err != nil {
		return nil, err
	}

	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	defaultOutbound := cfg.Routing.DefaultOutbound
	if defaultOutbound == "" {
		defaultOutbound = cfg.Outbounds[0].Name
	}

	rules := make([]compiledRule, 0, len(cfg.Routing.Rules))
	for _, rc := range cfg.Routing.Rules {
		cr, err := compileRule(rc)
		if err != nil {
			return nil, err
		}
		rules = append(rules, cr)
	}

	return &Router{
		rules:           rules,
		defaultOutbound: defaultOutbound,
	}, nil
}

func (r *Router) Route(ctx MatchContext) RouteDecision {
	decision, _ := r.Trace(ctx)
	return decision
}

func (r *Router) Trace(ctx MatchContext) (RouteDecision, []RuleTrace) {
	trace := make([]RuleTrace, 0, len(r.rules)+1)
	for _, rule := range r.rules {
		matched := rule.match(ctx)
		trace = append(trace, RuleTrace{
			Index:    len(trace),
			Rule:     rule.desc,
			Outbound: rule.outbound,
			Matched:  matched,
		})
		if matched {
			return RouteDecision{
				Outbound: rule.outbound,
				Rule:     rule.desc,
				Matched:  true,
			}, trace
		}
	}
	trace = append(trace, RuleTrace{
		Index:    -1,
		Rule:     "default_outbound",
		Outbound: r.defaultOutbound,
		Matched:  true,
	})
	return RouteDecision{
		Outbound: r.defaultOutbound,
		Rule:     "default_outbound",
		Matched:  false,
	}, trace
}

func compileRule(rc RuleConfig) (compiledRule, error) {
	ruleType := strings.ToLower(strings.TrimSpace(rc.Type))
	value := strings.TrimSpace(rc.Value)
	outbound := strings.TrimSpace(rc.Outbound)

	switch ruleType {
	case "domain_suffix":
		suffix := strings.ToLower(value)
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("domain_suffix=%s", suffix),
			match: func(ctx MatchContext) bool {
				return strings.HasSuffix(strings.ToLower(ctx.Host), suffix)
			},
		}, nil
	case "domain_keyword":
		keyword := strings.ToLower(value)
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("domain_keyword=%s", keyword),
			match: func(ctx MatchContext) bool {
				return strings.Contains(strings.ToLower(ctx.Host), keyword)
			},
		}, nil
	case "domain_exact":
		exact := strings.ToLower(value)
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("domain_exact=%s", exact),
			match: func(ctx MatchContext) bool {
				return strings.EqualFold(ctx.Host, exact)
			},
		}, nil
	case "ip_cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid ip_cidr rule value: %w", err)
		}
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("ip_cidr=%s", prefix.String()),
			match: func(ctx MatchContext) bool {
				return ctx.DestinationIP.IsValid() && prefix.Contains(ctx.DestinationIP)
			},
		}, nil
	case "port":
		p, err := strconv.Atoi(value)
		if err != nil || p < 1 || p > 65535 {
			return compiledRule{}, fmt.Errorf("invalid port rule value: %s", value)
		}
		want := uint16(p)
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("port=%d", want),
			match: func(ctx MatchContext) bool {
				return ctx.DestinationPort == want
			},
		}, nil
	case "network":
		network := strings.ToLower(value)
		if network != "tcp" && network != "udp" && network != "all" {
			return compiledRule{}, fmt.Errorf("invalid network rule value: %s", value)
		}
		return compiledRule{
			outbound: outbound,
			desc:     fmt.Sprintf("network=%s", network),
			match: func(ctx MatchContext) bool {
				if network == "all" {
					return true
				}
				return strings.EqualFold(ctx.Network, network)
			},
		}, nil
	case "default":
		return compiledRule{
			outbound: outbound,
			desc:     "default_rule",
			match: func(ctx MatchContext) bool {
				return true
			},
		}, nil
	default:
		return compiledRule{}, fmt.Errorf("unsupported rule type: %s", rc.Type)
	}
}
