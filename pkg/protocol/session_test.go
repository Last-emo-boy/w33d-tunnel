package protocol

import "testing"

func TestValidateRecvSeqRejectsDuplicate(t *testing.T) {
	s := NewSession(RoleClient, nil, nil)

	if !s.ValidateRecvSeq(1) {
		t.Fatal("expected first packet to be accepted")
	}
	if s.ValidateRecvSeq(1) {
		t.Fatal("expected duplicate packet to be rejected")
	}
}

func TestValidateRecvSeqAcceptsOutOfOrderWithinWindow(t *testing.T) {
	s := NewSession(RoleClient, nil, nil)

	if !s.ValidateRecvSeq(100) {
		t.Fatal("expected highest packet to be accepted")
	}
	if !s.ValidateRecvSeq(99) {
		t.Fatal("expected out-of-order packet within window to be accepted")
	}
	if s.ValidateRecvSeq(99) {
		t.Fatal("expected duplicate out-of-order packet to be rejected")
	}
}

func TestValidateRecvSeqRejectsTooOldPacket(t *testing.T) {
	s := NewSession(RoleClient, nil, nil)

	if !s.ValidateRecvSeq(2000) {
		t.Fatal("expected packet to be accepted")
	}
	if s.ValidateRecvSeq(900) {
		t.Fatal("expected packet older than window to be rejected")
	}
}

func TestValidateRecvSeqLargeJumpResetsWindow(t *testing.T) {
	s := NewSession(RoleClient, nil, nil)

	if !s.ValidateRecvSeq(5) {
		t.Fatal("expected packet to be accepted")
	}
	if !s.ValidateRecvSeq(2000) {
		t.Fatal("expected large jump packet to be accepted")
	}
	if !s.ValidateRecvSeq(1999) {
		t.Fatal("expected near-high packet to be accepted after jump")
	}
	if s.ValidateRecvSeq(5) {
		t.Fatal("expected old packet before jump to be rejected")
	}
}
