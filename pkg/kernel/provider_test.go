package kernel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigWithHTTPRuleProviderAndCacheFallback(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "providers", "social.yaml")

	providerPayload := `rules:
  - type: domain_suffix
    value: telegram.org
    outbound: proxy
`

	failRemote := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failRemote {
			http.Error(w, "upstream failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(providerPayload))
	}))
	defer srv.Close()

	cfgData := []byte(fmt.Sprintf(`
outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rule_providers:
    social:
      type: http
      url: %s/rules.yaml
      cache_path: '%s'
  rules:
    - type: provider
      provider: social
`, srv.URL, strings.ReplaceAll(cachePath, "\\", "\\\\")))

	cfg, err := ParseConfig(cfgData, ".yaml")
	if err != nil {
		t.Fatalf("parse with live provider failed: %v", err)
	}
	if len(cfg.Routing.Rules) != 1 {
		t.Fatalf("expected 1 expanded rule, got %d", len(cfg.Routing.Rules))
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected provider cache file to exist: %v", err)
	}

	failRemote = true
	cfgFallback, err := ParseConfig(cfgData, ".yaml")
	if err != nil {
		t.Fatalf("parse with provider cache fallback failed: %v", err)
	}

	router, err := NewRouter(cfgFallback)
	if err != nil {
		t.Fatalf("new router failed: %v", err)
	}
	d := router.Route(MatchContext{Host: "api.telegram.org", DestinationPort: 443, Network: "tcp"})
	if !d.Matched || d.Outbound != "proxy" {
		t.Fatalf("expected provider rule match to proxy, got %+v", d)
	}
}

func TestParseConfigWithFileRuleProvider(t *testing.T) {
	base := t.TempDir()
	providerPath := filepath.Join(base, "geo-rules.yaml")
	if err := os.WriteFile(providerPath, []byte(`rules:
  - type: domain_keyword
    value: ads
    outbound: block
`), 0644); err != nil {
		t.Fatalf("write provider file failed: %v", err)
	}

	cfgData := []byte(fmt.Sprintf(`
outbounds:
  - name: direct
    type: direct
  - name: block
    type: block
routing:
  default_outbound: direct
  rule_providers:
    adblock:
      type: file
      path: '%s'
  rules:
    - type: provider
      provider: adblock
`, strings.ReplaceAll(providerPath, "\\", "\\\\")))

	cfg, err := ParseConfig(cfgData, ".yaml")
	if err != nil {
		t.Fatalf("parse with file provider failed: %v", err)
	}
	if len(cfg.Routing.Rules) != 1 {
		t.Fatalf("expected 1 expanded rule, got %d", len(cfg.Routing.Rules))
	}

	router, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("new router failed: %v", err)
	}
	d := router.Route(MatchContext{Host: "my-ads.example.com", DestinationPort: 443, Network: "tcp"})
	if !d.Matched || d.Outbound != "block" {
		t.Fatalf("expected file provider rule to match block, got %+v", d)
	}
}

func TestParseConfigRejectsUnknownRuleProviderReference(t *testing.T) {
	cfgData := []byte(`
outbounds:
  - name: direct
    type: direct
routing:
  default_outbound: direct
  rule_providers: {}
  rules:
    - type: provider
      provider: missing-provider
`)

	if _, err := ParseConfig(cfgData, ".yaml"); err == nil {
		t.Fatal("expected parse error for unknown rule provider")
	}
}
