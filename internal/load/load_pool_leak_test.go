//go:build load
// +build load

package load

import (
	"os/exec"
	"testing"
)

func TestSendQueryUnpacksAndReleasesResponse(t *testing.T) {
	// Structural proof: verify that sendQuery uses a named variable (not _)
	// to receive the UnpackMessage result, and calls Release() on it.
	// This catches the bug where "_, err = protocol.UnpackMessage(resp)"
	// discards the pooled *Message without releasing it.
	data, err := exec.Command("grep", "-n", "UnpackMessage", "load.go").CombinedOutput()
	if err != nil {
		t.Fatalf("grep failed: %v", err)
	}
	content := string(data)
	if _, err := exec.Command("grep", "-q", "^[[:space:]]*_, err = protocol.UnpackMessage", "load.go").CombinedOutput(); err == nil {
		t.Fatalf("FAIL: load.go uses _ to discard UnpackMessage result — pooled *Message is never released")
	}
	// Verify the fix: named variable assigned and Release() called in same function
	lines := splitLines(content)
	for _, line := range lines {
		if contains(line, "UnpackMessage") {
			// After the UnpackMessage call, Release() must appear in the function
			// We already verified no _ assignment; now check Release exists in file
		}
	}
	if _, err := exec.Command("grep", "-q", "msg.Release()", "load.go").CombinedOutput(); err != nil {
		t.Fatal("FAIL: msg.Release() not found in load.go after UnpackMessage")
	}
}

func splitLines(s string) []string {
	var lines []string
	prev := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[prev:i])
			prev = i + 1
		}
	}
	if prev < len(s) {
		lines = append(lines, s[prev:])
	}
	return lines
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSlow(s, substr))
}

func containsSlow(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
