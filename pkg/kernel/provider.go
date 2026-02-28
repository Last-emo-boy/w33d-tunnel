package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const providerRuleType = "provider"

func ResolveRuleProviders(cfg Config) (Config, error) {
	if len(cfg.Routing.Rules) == 0 {
		return cfg, nil
	}

	expanded := make([]RuleConfig, 0, len(cfg.Routing.Rules))
	for i, rule := range cfg.Routing.Rules {
		if strings.ToLower(strings.TrimSpace(rule.Type)) != providerRuleType {
			expanded = append(expanded, rule)
			continue
		}

		providerName := strings.TrimSpace(rule.Provider)
		if providerName == "" {
			providerName = strings.TrimSpace(rule.Value)
		}
		if providerName == "" {
			return Config{}, fmt.Errorf("routing rule[%d] provider name cannot be empty", i)
		}

		pcfg, ok := cfg.Routing.RuleProviders[providerName]
		if !ok {
			return Config{}, fmt.Errorf("routing rule[%d] provider not found: %s", i, providerName)
		}

		providerRules, err := loadProviderRules(pcfg)
		if err != nil {
			return Config{}, fmt.Errorf("load rule provider %s failed: %w", providerName, err)
		}
		expanded = append(expanded, providerRules...)
	}

	cfg.Routing.Rules = expanded
	return cfg, nil
}

func loadProviderRules(cfg RuleProviderConfig) ([]RuleConfig, error) {
	pType := strings.ToLower(strings.TrimSpace(cfg.Type))
	if pType == "" {
		pType = "http"
	}

	ext := providerFormatExt(cfg)
	switch pType {
	case "http", "https":
		if strings.TrimSpace(cfg.URL) == "" {
			return nil, errors.New("http provider requires url")
		}
		data, err := fetchProviderHTTP(cfg.URL)
		if err != nil {
			if strings.TrimSpace(cfg.CachePath) == "" {
				return nil, err
			}
			cached, cacheErr := os.ReadFile(cfg.CachePath)
			if cacheErr != nil {
				return nil, fmt.Errorf("%v (cache fallback failed: %v)", err, cacheErr)
			}
			return parseProviderRules(cached, ext)
		}
		if strings.TrimSpace(cfg.CachePath) != "" {
			_ = writeProviderCache(cfg.CachePath, data)
		}
		return parseProviderRules(data, ext)
	case "file":
		source := strings.TrimSpace(cfg.Path)
		if source == "" {
			return nil, errors.New("file provider requires path")
		}
		data, err := os.ReadFile(source)
		if err != nil {
			if strings.TrimSpace(cfg.CachePath) == "" {
				return nil, err
			}
			cached, cacheErr := os.ReadFile(cfg.CachePath)
			if cacheErr != nil {
				return nil, fmt.Errorf("%v (cache fallback failed: %v)", err, cacheErr)
			}
			return parseProviderRules(cached, ext)
		}
		if strings.TrimSpace(cfg.CachePath) != "" {
			_ = writeProviderCache(cfg.CachePath, data)
		}
		return parseProviderRules(data, ext)
	default:
		return nil, fmt.Errorf("unsupported rule provider type: %s", cfg.Type)
	}
}

func providerFormatExt(cfg RuleProviderConfig) string {
	if f := strings.TrimSpace(cfg.Format); f != "" {
		if strings.HasPrefix(f, ".") {
			return strings.ToLower(f)
		}
		return "." + strings.ToLower(f)
	}
	if u := strings.TrimSpace(cfg.URL); u != "" {
		if ext := strings.ToLower(filepath.Ext(u)); ext != "" {
			return ext
		}
	}
	if p := strings.TrimSpace(cfg.Path); p != "" {
		if ext := strings.ToLower(filepath.Ext(p)); ext != "" {
			return ext
		}
	}
	return ".yaml"
}

func fetchProviderHTTP(rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider http status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func writeProviderCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func parseProviderRules(data []byte, ext string) ([]RuleConfig, error) {
	// Preferred format: { rules: [...] }
	var wrapped struct {
		Rules []RuleConfig `yaml:"rules" json:"rules"`
	}
	if err := unmarshalByExt(data, ext, &wrapped); err == nil && len(wrapped.Rules) > 0 {
		return wrapped.Rules, nil
	}

	// Fallback format: direct []RuleConfig
	var list []RuleConfig
	if err := unmarshalByExt(data, ext, &list); err == nil && len(list) > 0 {
		return list, nil
	}
	return nil, errors.New("provider payload must contain non-empty rules")
}

func unmarshalByExt(data []byte, ext string, out any) error {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".json":
		return json.Unmarshal(data, out)
	default:
		return yaml.Unmarshal(data, out)
	}
}
