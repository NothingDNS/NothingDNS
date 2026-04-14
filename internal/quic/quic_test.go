package quic

import (
	"testing"
)

// =================== ConnectionID Tests ===================

func TestConnectionIDEqual(t *testing.T) {
	a := ConnectionID{1, 2, 3, 4}
	b := ConnectionID{1, 2, 3, 4}
	c := ConnectionID{1, 2, 3, 5}
	d := ConnectionID{1, 2, 3}

	if !a.Equal(b) {
		t.Error("equal ConnectionIDs should be equal")
	}
	if a.Equal(c) {
		t.Error("different ConnectionIDs should not be equal")
	}
	if a.Equal(d) {
		t.Error("different length ConnectionIDs should not be equal")
	}
}

func TestConnectionIDString(t *testing.T) {
	cid := ConnectionID{0x01, 0x02, 0xab, 0xcd}
	s := cid.String()
	if s != "0102abcd" {
		t.Errorf("ConnectionID.String() = %q, want %q", s, "0102abcd")
	}
}

func TestGenerateConnectionID(t *testing.T) {
	cid, err := GenerateConnectionID(8)
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}
	if len(cid) != 8 {
		t.Errorf("len = %d, want 8", len(cid))
	}

	// Two generated CIDs should be different (probabilistic but extremely unlikely to fail)
	cid2, _ := GenerateConnectionID(8)
	if cid.Equal(cid2) {
		t.Error("two random CIDs should differ")
	}
}

func TestGenerateConnectionIDInvalidLength(t *testing.T) {
	_, err := GenerateConnectionID(0)
	if err == nil {
		t.Error("expected error for zero-length CID")
	}
	_, err = GenerateConnectionID(21)
	if err == nil {
		t.Error("expected error for too-long CID")
	}
}

func TestGenerateInitialConnectionID(t *testing.T) {
	cid, err := GenerateInitialConnectionID()
	if err != nil {
		t.Fatalf("GenerateInitialConnectionID: %v", err)
	}
	if len(cid) != MinInitialConnIDLen {
		t.Errorf("len = %d, want %d", len(cid), MinInitialConnIDLen)
	}
}
