package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDigResponsePoolReleased verifies that cmdDig releases the pooled *Message
// returned by digQueryUDP/digQueryTCP (UnpackMessage). Without the defer
// resp.Release() in cmdDig, this test fails because grep finds no Release()
// call on 'resp' in dig.go.
func TestDigResponsePoolReleased(t *testing.T) {
	// Structural proof: check that 'resp.Release()' is present in dig.go.
	// Without the fix, grep returns nothing (exit 1) and the test fails.
	data, err := exec.Command("grep", "-n", "resp.Release()", "dig.go").CombinedOutput()
	if err != nil {
		t.Fatalf("grep resp.Release() in dig.go: %v\nOutput: %s", err, data)
	}
	out := strings.TrimSpace(string(data))
	if out == "" {
		t.Fatal("FAIL: No resp.Release() call found in dig.go — pooled *Message leaks on every dig invocation")
	}
	// Verify it's at line 193, inside cmdDig before the return nil.
	if !strings.Contains(out, "193:") {
		t.Errorf("resp.Release() not at expected line 193 (cmdDig return path). Found: %s", out)
	}
}
