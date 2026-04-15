package util

import (
	"strings"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	id := GenerateRequestID()
	if len(id) != 16 {
		t.Errorf("expected 16-char ID, got %d chars: %s", len(id), id)
	}
	// Verify all hex chars
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("unexpected char %c in ID %s", c, id)
		}
	}
}

func TestGenerateRequestID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		id := GenerateRequestID()
		if seen[id] {
			t.Fatalf("duplicate ID generated: %s", id)
		}
		seen[id] = true
	}
}

func BenchmarkGenerateRequestID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GenerateRequestID()
	}
}
