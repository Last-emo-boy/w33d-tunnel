package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeKicker struct {
	kickedToken string
	metrics     map[string]uint64
}

func (f *fakeKicker) CloseSessionByToken(token string) {
	f.kickedToken = token
}

func (f *fakeKicker) GetMetrics() map[string]uint64 {
	if f.metrics == nil {
		return map[string]uint64{}
	}
	return f.metrics
}

func TestAdminKickRequiresSecret(t *testing.T) {
	conn := &fakeKicker{}
	h := newPingAdminHandler(conn, []string{"test-secret"})

	req := httptest.NewRequest(http.MethodPost, "/admin/kick?token=u1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestAdminKickDisabledWithoutConfiguredSecret(t *testing.T) {
	conn := &fakeKicker{}
	h := newPingAdminHandler(conn, nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/kick?token=u1", nil)
	req.Header.Set("X-Admin-Secret", "anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
}

func TestAdminKickSuccessWithValidSecret(t *testing.T) {
	conn := &fakeKicker{}
	h := newPingAdminHandler(conn, []string{"test-secret"})

	req := httptest.NewRequest(http.MethodPost, "/admin/kick?token=u1", nil)
	req.Header.Set("X-Admin-Secret", "test-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if conn.kickedToken != "u1" {
		t.Fatalf("expected kicked token u1, got %q", conn.kickedToken)
	}
}

func TestMetricsEndpointReturnsJSON(t *testing.T) {
	conn := &fakeKicker{
		metrics: map[string]uint64{
			"active_sessions": 2,
		},
	}
	h := newPingAdminHandler(conn, []string{"test-secret"})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Header().Get("Content-Type") == "" {
		t.Fatal("expected content-type header")
	}
	if body := rr.Body.String(); body == "" {
		t.Fatal("expected non-empty metrics body")
	}
}

func TestValidateAuthConfig(t *testing.T) {
	if err := validateAuthConfig(false, "", ""); err != nil {
		t.Fatalf("non-strict mode should allow empty secrets: %v", err)
	}
	if err := validateAuthConfig(true, "", "a"); err == nil {
		t.Fatal("strict mode should require manager secret")
	}
	if err := validateAuthConfig(true, "m", ""); err == nil {
		t.Fatal("strict mode should require admin secret")
	}
	if err := validateAuthConfig(true, "m", "a"); err != nil {
		t.Fatalf("strict mode should pass with both secrets set: %v", err)
	}
	if err := validateAuthConfig(true, "old,new", "x,y"); err != nil {
		t.Fatalf("strict mode should pass with secret rotation list: %v", err)
	}
}

func TestAdminKickRotationWindowAcceptsNewSecret(t *testing.T) {
	conn := &fakeKicker{}
	h := newPingAdminHandler(conn, []string{"old-secret", "new-secret"})

	req := httptest.NewRequest(http.MethodPost, "/admin/kick?token=u1", nil)
	req.Header.Set("X-Admin-Secret", "new-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestParseSecretList(t *testing.T) {
	got := parseSecretList(" old , new,old ")
	if len(got) != 2 {
		t.Fatalf("expected 2 unique secrets, got %d", len(got))
	}
	if got[0] != "old" || got[1] != "new" {
		t.Fatalf("unexpected list: %#v", got)
	}
}
