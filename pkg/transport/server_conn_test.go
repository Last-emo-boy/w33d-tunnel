package transport

import (
	"testing"

	"w33d-tunnel/pkg/protocol"
)

func TestRegisterTokenRespectsMaxIPs(t *testing.T) {
	sm := NewSessionManager(nil)
	defer close(sm.stopChan)

	sm.UpdateValidTokens(map[string]QuotaInfo{
		"t1": {
			MaxIPs:         2,
			QuotaBytes:     1024,
			BandwidthLimit: 0,
		},
	})

	if !sm.RegisterToken("t1") {
		t.Fatal("expected first registration to succeed")
	}
	if !sm.RegisterToken("t1") {
		t.Fatal("expected second registration to succeed")
	}
	if sm.RegisterToken("t1") {
		t.Fatal("expected third registration to fail due to MaxIPs=2")
	}
}

func TestCloseSessionByTokenRemovesSessionAndCount(t *testing.T) {
	sm := NewSessionManager(nil)
	defer close(sm.stopChan)

	s1 := &protocol.Session{Token: "t1"}
	s2 := &protocol.Session{Token: "t2"}
	sm.sessions["a1"] = s1
	sm.sessions["a2"] = s2
	sm.activeCounts["t1"] = 1

	sm.CloseSessionByToken("t1")

	if _, ok := sm.sessions["a1"]; ok {
		t.Fatal("expected t1 session removed")
	}
	if _, ok := sm.sessions["a2"]; !ok {
		t.Fatal("expected other session to remain")
	}
	if sm.activeCounts["t1"] != 0 {
		t.Fatalf("expected active count reset, got %d", sm.activeCounts["t1"])
	}
}

func TestShouldDisconnectForPolicy(t *testing.T) {
	sm := NewSessionManager(nil)
	defer close(sm.stopChan)

	sm.UpdateValidTokens(map[string]QuotaInfo{
		"valid": {
			QuotaBytes: 100,
			UsedBytes:  40,
		},
	})

	sess := &protocol.Session{
		Token:        "valid",
		BytesRead:    20,
		BytesWritten: 10,
	}
	if sm.ShouldDisconnectForPolicy(sess) {
		t.Fatal("expected session within quota to stay connected")
	}

	sess.BytesRead = 50 // 40 + 50 + 10 = 100 (still allowed)
	if sm.ShouldDisconnectForPolicy(sess) {
		t.Fatal("expected exact-quota usage to remain connected")
	}

	sess.BytesRead = 51 // 40 + 51 + 10 = 101 (exceeded)
	if !sm.ShouldDisconnectForPolicy(sess) {
		t.Fatal("expected over-quota session to be disconnected")
	}

	invalid := &protocol.Session{Token: "missing"}
	if !sm.ShouldDisconnectForPolicy(invalid) {
		t.Fatal("expected missing token to be disconnected")
	}
}

func TestSnapshotMetricsIncludesCountersAndActives(t *testing.T) {
	sm := NewSessionManager(nil)
	defer close(sm.stopChan)

	sm.sessions["a1"] = &protocol.Session{Token: "t1"}
	sm.sessions["a2"] = &protocol.Session{Token: "t2"}
	sm.activeCounts["t1"] = 1
	sm.activeCounts["t2"] = 0
	sm.activeCounts["t3"] = 2

	sm.RecordSessionEstablished()
	sm.RecordHandshakeRejectInvalid()
	sm.RecordHandshakeRejectQuota()
	sm.RecordHandshakeRejectMaxIPs()
	sm.RecordPolicyDisconnect()

	m := sm.SnapshotMetrics()

	if m["active_sessions"] != 2 {
		t.Fatalf("expected active_sessions=2, got %d", m["active_sessions"])
	}
	if m["active_tokens"] != 2 { // t1 and t3
		t.Fatalf("expected active_tokens=2, got %d", m["active_tokens"])
	}
	if m["sessions_established_total"] != 1 {
		t.Fatalf("expected sessions_established_total=1, got %d", m["sessions_established_total"])
	}
	if m["handshake_reject_invalid_total"] != 1 {
		t.Fatalf("expected handshake_reject_invalid_total=1, got %d", m["handshake_reject_invalid_total"])
	}
	if m["handshake_reject_quota_total"] != 1 {
		t.Fatalf("expected handshake_reject_quota_total=1, got %d", m["handshake_reject_quota_total"])
	}
	if m["handshake_reject_max_ips_total"] != 1 {
		t.Fatalf("expected handshake_reject_max_ips_total=1, got %d", m["handshake_reject_max_ips_total"])
	}
	if m["policy_disconnects_total"] != 1 {
		t.Fatalf("expected policy_disconnects_total=1, got %d", m["policy_disconnects_total"])
	}
}
