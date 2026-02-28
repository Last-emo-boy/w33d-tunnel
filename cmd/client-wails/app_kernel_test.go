package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"w33d-tunnel/pkg/kernel"
)

func newTestKernelApp(t *testing.T) *App {
	t.Helper()
	base := t.TempDir()
	return &App{
		kernelPath:     filepath.Join(base, "kernel.yaml"),
		kernelMeta:     filepath.Join(base, "kernel", "profiles.json"),
		kernelManagers: map[string]*kernel.RuntimeManager{},
	}
}

func TestNormalizeProfileName(t *testing.T) {
	if _, err := normalizeProfileName(""); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := normalizeProfileName("bad/name"); err == nil {
		t.Fatal("expected error for invalid name")
	}
	if got, err := normalizeProfileName("profile-1"); err != nil || got != "profile-1" {
		t.Fatalf("expected valid name, got %q, err=%v", got, err)
	}
}

func TestKernelProfilesLifecycle(t *testing.T) {
	app := newTestKernelApp(t)

	state := app.GetKernelProfiles()
	if state.Active != defaultKernelProfile {
		t.Fatalf("expected default active profile, got %s", state.Active)
	}

	if err := app.CreateKernelProfile("work"); err != nil {
		t.Fatalf("create profile failed: %v", err)
	}
	if err := app.SetActiveKernelProfile("work"); err != nil {
		t.Fatalf("set active failed: %v", err)
	}
	if err := app.SaveKernelProfile("work", "outbounds:\n  - name: direct\n    type: direct\nrouting:\n  default_outbound: direct\n  rules: []\n"); err != nil {
		t.Fatalf("save profile failed: %v", err)
	}

	content, err := app.LoadKernelProfile("work")
	if err != nil {
		t.Fatalf("load profile failed: %v", err)
	}
	if content == "" {
		t.Fatal("expected non-empty profile content")
	}

	if err := app.DeleteKernelProfile("work"); err != nil {
		t.Fatalf("delete profile failed: %v", err)
	}
}

func TestProbeKernelRoute(t *testing.T) {
	app := newTestKernelApp(t)

	if err := app.SaveKernelProfile(defaultKernelProfile, `outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: proxy
`); err != nil {
		t.Fatalf("save default profile failed: %v", err)
	}

	res := app.ProbeKernelRoute(defaultKernelProfile, "api.telegram.org", "", 443, "tcp")
	if !res.OK {
		t.Fatalf("expected probe success, got: %s", res.Message)
	}
	if res.Outbound != "proxy" {
		t.Fatalf("expected proxy outbound, got %s", res.Outbound)
	}
	if len(res.Trace) == 0 {
		t.Fatal("expected non-empty rule trace")
	}
	if !res.Trace[0].Matched {
		t.Fatalf("expected first trace rule to match, got %+v", res.Trace[0])
	}

	stats := app.GetKernelRuntimeStats(defaultKernelProfile)
	if stats.TotalRoutes < 1 {
		t.Fatalf("expected runtime stats to count probe routes, got %d", stats.TotalRoutes)
	}
	if stats.AdapterHealth["proxy"] != "active" {
		t.Fatalf("expected proxy adapter health active, got %q", stats.AdapterHealth["proxy"])
	}
	if err := app.ResetKernelRuntimeStats(defaultKernelProfile); err != nil {
		t.Fatalf("reset runtime stats failed: %v", err)
	}
	stats2 := app.GetKernelRuntimeStats(defaultKernelProfile)
	if stats2.TotalRoutes != 0 {
		t.Fatalf("expected reset stats total=0, got %d", stats2.TotalRoutes)
	}
	if stats2.AdapterHealth["proxy"] != "idle" {
		t.Fatalf("expected proxy adapter health idle after reset, got %q", stats2.AdapterHealth["proxy"])
	}
}

func TestKernelProfileRollback(t *testing.T) {
	app := newTestKernelApp(t)
	profile := defaultKernelProfile

	v1 := `outbounds:
  - name: direct
    type: direct
routing:
  default_outbound: direct
  rules: []
`
	v2 := `outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: proxy
`

	if err := app.SaveKernelProfile(profile, v1); err != nil {
		t.Fatalf("save v1 failed: %v", err)
	}
	if err := app.SaveKernelProfile(profile, v2); err != nil {
		t.Fatalf("save v2 failed: %v", err)
	}

	revs, err := app.ListKernelProfileRevisions(profile)
	if err != nil {
		t.Fatalf("list revisions failed: %v", err)
	}
	if len(revs) == 0 {
		t.Fatal("expected at least one revision")
	}

	var targetID string
	for _, rev := range revs {
		content, err := os.ReadFile(filepath.Join(app.profileRevisionsDir(profile), rev.ID+".yaml"))
		if err != nil {
			t.Fatalf("read revision content failed: %v", err)
		}
		if strings.Contains(string(content), "rules: []") {
			targetID = rev.ID
			break
		}
	}
	if targetID == "" {
		t.Fatal("failed to find v1 revision in revision list")
	}

	if err := app.RollbackKernelProfile(profile, targetID); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	current, err := app.LoadKernelProfile(profile)
	if err != nil {
		t.Fatalf("load rolled back profile failed: %v", err)
	}
	if !strings.Contains(current, "rules: []") {
		t.Fatalf("expected rolled back content, got:\n%s", current)
	}
}

func TestKernelControllerRuntimeAndReset(t *testing.T) {
	app := newTestKernelApp(t)
	defer app.shutdown(context.Background())

	if err := app.SaveKernelProfile(defaultKernelProfile, `outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: proxy
`); err != nil {
		t.Fatalf("save default profile failed: %v", err)
	}

	controllerState, err := app.GetKernelControllerState(defaultKernelProfile)
	if err != nil {
		t.Fatalf("get controller state failed: %v", err)
	}
	if !controllerState.Running {
		t.Fatal("expected controller running")
	}
	if controllerState.Profile != defaultKernelProfile {
		t.Fatalf("expected controller profile %q, got %q", defaultKernelProfile, controllerState.Profile)
	}

	probe := app.ProbeKernelRoute(defaultKernelProfile, "api.telegram.org", "", 443, "tcp")
	if !probe.OK {
		t.Fatalf("expected probe success, got: %s", probe.Message)
	}

	stats, err := app.ControllerGetKernelRuntimeStats(defaultKernelProfile)
	if err != nil {
		t.Fatalf("controller runtime stats failed: %v", err)
	}
	if stats.TotalRoutes < 1 {
		t.Fatalf("expected controller runtime total routes >= 1, got %d", stats.TotalRoutes)
	}

	resetStats, err := app.ControllerResetKernelRuntimeStats(defaultKernelProfile)
	if err != nil {
		t.Fatalf("controller reset stats failed: %v", err)
	}
	if resetStats.TotalRoutes != 0 {
		t.Fatalf("expected reset runtime total=0, got %d", resetStats.TotalRoutes)
	}
}

func TestKernelControllerApplyConfig(t *testing.T) {
	app := newTestKernelApp(t)
	defer app.shutdown(context.Background())

	initial := `outbounds:
  - name: direct
    type: direct
routing:
  default_outbound: direct
  rules: []
`
	if err := app.SaveKernelProfile(defaultKernelProfile, initial); err != nil {
		t.Fatalf("save initial profile failed: %v", err)
	}

	if err := app.ControllerApplyKernelConfig(defaultKernelProfile, "yaml", `outbounds:
  - name: direct
    type: direct
  - name: proxy
    type: w33d
    server: 1.2.3.4
    port: 8080
routing:
  default_outbound: direct
  rules:
    - type: domain_suffix
      value: telegram.org
      outbound: proxy
`); err != nil {
		t.Fatalf("controller apply config failed: %v", err)
	}

	result := app.ProbeKernelRoute(defaultKernelProfile, "api.telegram.org", "", 443, "tcp")
	if !result.OK {
		t.Fatalf("expected probe success after controller apply, got: %s", result.Message)
	}
	if result.Outbound != "proxy" {
		t.Fatalf("expected outbound proxy after controller apply, got %q", result.Outbound)
	}

	configJSON, err := app.ControllerGetKernelConfig(defaultKernelProfile)
	if err != nil {
		t.Fatalf("controller get config failed: %v", err)
	}
	if !strings.Contains(configJSON, "\"proxy\"") {
		t.Fatalf("expected controller config to contain proxy outbound, got: %s", configJSON)
	}
}
