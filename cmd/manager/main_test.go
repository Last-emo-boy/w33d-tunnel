package main

import "testing"

func TestParseBoolEnv(t *testing.T) {
	casesTrue := []string{"1", "true", "TRUE", " yes ", "on"}
	for _, v := range casesTrue {
		if !parseBoolEnv(v) {
			t.Fatalf("expected true for %q", v)
		}
	}

	casesFalse := []string{"", "0", "false", "no", "off", "random"}
	for _, v := range casesFalse {
		if parseBoolEnv(v) {
			t.Fatalf("expected false for %q", v)
		}
	}
}

func TestValidateManagerAuthConfig(t *testing.T) {
	if err := validateManagerAuthConfig(nil, false); err != nil {
		t.Fatalf("non-strict mode should allow empty secret: %v", err)
	}
	if err := validateManagerAuthConfig(nil, true); err == nil {
		t.Fatal("strict mode should fail with empty node secret")
	}
	if err := validateManagerAuthConfig([]string{"node-secret"}, true); err != nil {
		t.Fatalf("strict mode should pass with node secret: %v", err)
	}
}

func TestParseSecretList(t *testing.T) {
	got := parseSecretList(" old-secret, new-secret , ,old-secret ")
	if len(got) != 2 {
		t.Fatalf("expected 2 unique secrets, got %d", len(got))
	}
	if got[0] != "old-secret" || got[1] != "new-secret" {
		t.Fatalf("unexpected secret list: %#v", got)
	}
}

func TestSecretInList(t *testing.T) {
	secrets := []string{"old-secret", "new-secret"}
	if !secretInList("new-secret", secrets) {
		t.Fatal("expected new-secret to match")
	}
	if secretInList("wrong", secrets) {
		t.Fatal("expected wrong secret not to match")
	}
}
