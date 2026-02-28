package kernel

// Config is the top-level Clash-like core configuration model.
// It is intentionally minimal in v1 and will be extended iteratively.
type Config struct {
	Experimental ExperimentalConfig `yaml:"experimental" json:"experimental"`
	Inbounds     []InboundConfig    `yaml:"inbounds" json:"inbounds"`
	Outbounds    []OutboundConfig   `yaml:"outbounds" json:"outbounds"`
	DNS          DNSConfig          `yaml:"dns" json:"dns"`
	Routing      RoutingConfig      `yaml:"routing" json:"routing"`
}

type ExperimentalConfig struct {
	EnableSniffing bool `yaml:"enable_sniffing" json:"enable_sniffing"`
}

type InboundConfig struct {
	Name    string `yaml:"name" json:"name"`
	Type    string `yaml:"type" json:"type"` // socks / http / mixed / tun
	Listen  string `yaml:"listen" json:"listen"`
	Auth    string `yaml:"auth" json:"auth"`
	UDP     bool   `yaml:"udp" json:"udp"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type OutboundConfig struct {
	Name    string `yaml:"name" json:"name"`
	Type    string `yaml:"type" json:"type"` // direct / block / w33d
	Server  string `yaml:"server,omitempty" json:"server,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	PubKey  string `yaml:"pub_key,omitempty" json:"pub_key,omitempty"`
	Token   string `yaml:"token,omitempty" json:"token,omitempty"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type DNSConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Listen      string   `yaml:"listen" json:"listen"`
	Upstreams   []string `yaml:"upstreams" json:"upstreams"`
	Mode        string   `yaml:"mode,omitempty" json:"mode,omitempty"`                   // normal / fake-ip
	FakeIPRange string   `yaml:"fake_ip_range,omitempty" json:"fake_ip_range,omitempty"` // e.g. 198.18.0.0/16
}

type RoutingConfig struct {
	DefaultOutbound string                        `yaml:"default_outbound" json:"default_outbound"`
	Rules           []RuleConfig                  `yaml:"rules" json:"rules"`
	RuleProviders   map[string]RuleProviderConfig `yaml:"rule_providers" json:"rule_providers"`
}

type RuleConfig struct {
	Type     string `yaml:"type" json:"type"`                   // domain_suffix / domain_keyword / domain_exact / ip_cidr / port / network / default / provider
	Value    string `yaml:"value" json:"value"`                 // e.g. "google.com", "10.0.0.0/8", "53", "udp"
	Outbound string `yaml:"outbound" json:"outbound"`           // target outbound name
	Provider string `yaml:"provider,omitempty" json:"provider"` // for type=provider
}

type RuleProviderConfig struct {
	Type      string `yaml:"type" json:"type"`                                 // http / file
	URL       string `yaml:"url,omitempty" json:"url,omitempty"`               // for http provider
	Path      string `yaml:"path,omitempty" json:"path,omitempty"`             // for file provider
	Format    string `yaml:"format,omitempty" json:"format,omitempty"`         // yaml / json (optional, auto-detect by extension)
	CachePath string `yaml:"cache_path,omitempty" json:"cache_path,omitempty"` // local cache path for http/file failover
}
