package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ParseConfig(data, ext)
}

func ParseConfig(data []byte, ext string) (Config, error) {
	var cfg Config
	var err error
	switch ext {
	case ".json":
		err = json.Unmarshal(data, &cfg)
	default:
		err = yaml.Unmarshal(data, &cfg)
	}
	if err != nil {
		return Config{}, err
	}

	cfg, err = ResolveRuleProviders(cfg)
	if err != nil {
		return Config{}, err
	}

	if err := ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ValidateConfig(cfg Config) error {
	if len(cfg.Outbounds) == 0 {
		return errors.New("at least one outbound is required")
	}

	outboundSet := make(map[string]struct{}, len(cfg.Outbounds))
	for _, ob := range cfg.Outbounds {
		name := strings.TrimSpace(ob.Name)
		if name == "" {
			return errors.New("outbound name cannot be empty")
		}
		if _, exists := outboundSet[name]; exists {
			return fmt.Errorf("duplicate outbound name: %s", name)
		}
		outboundSet[name] = struct{}{}
	}

	if cfg.Routing.DefaultOutbound != "" {
		if _, ok := outboundSet[cfg.Routing.DefaultOutbound]; !ok {
			return fmt.Errorf("default outbound not found: %s", cfg.Routing.DefaultOutbound)
		}
	}

	for i, r := range cfg.Routing.Rules {
		ruleType := strings.ToLower(strings.TrimSpace(r.Type))
		if ruleType == "" {
			return fmt.Errorf("routing rule[%d] type cannot be empty", i)
		}
		if ruleType == providerRuleType {
			providerName := strings.TrimSpace(r.Provider)
			if providerName == "" {
				providerName = strings.TrimSpace(r.Value)
			}
			if providerName == "" {
				return fmt.Errorf("routing rule[%d] provider name cannot be empty", i)
			}
			if _, ok := cfg.Routing.RuleProviders[providerName]; !ok {
				return fmt.Errorf("routing rule[%d] provider not found: %s", i, providerName)
			}
			continue
		}
		if strings.TrimSpace(r.Outbound) == "" {
			return fmt.Errorf("routing rule[%d] outbound cannot be empty", i)
		}
		if _, ok := outboundSet[r.Outbound]; !ok {
			return fmt.Errorf("routing rule[%d] outbound not found: %s", i, r.Outbound)
		}
	}

	if cfg.DNS.Enabled {
		mode := strings.ToLower(strings.TrimSpace(cfg.DNS.Mode))
		if mode == "" {
			mode = "normal"
		}
		if mode != "normal" && mode != "fake-ip" {
			return fmt.Errorf("unsupported dns mode: %s", cfg.DNS.Mode)
		}
		if mode == "fake-ip" {
			fakeRange := strings.TrimSpace(cfg.DNS.FakeIPRange)
			if fakeRange == "" {
				fakeRange = "198.18.0.0/16"
			}
			prefix, err := netip.ParsePrefix(fakeRange)
			if err != nil {
				return fmt.Errorf("invalid dns fake_ip_range: %w", err)
			}
			if !prefix.Addr().Is4() {
				return errors.New("dns fake_ip_range must be ipv4 cidr")
			}
		}
	}

	return nil
}
