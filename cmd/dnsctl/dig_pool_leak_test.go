package main

import (
	"os"
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
	// The release must live inside cmdDig, after the response is produced
	// and before it is handed to the printer, so the pooled message is
	// always returned. Assert on the code that surrounds the call rather
	// than an absolute line number, which shifts whenever anything above it
	// in the file is edited (adding a helper, a comment, a flag — none of
	// which change this contract).
	src, readErr := os.ReadFile("dig.go")
	if readErr != nil {
		t.Fatalf("read dig.go: %v", readErr)
	}
	idx := strings.Index(string(src), "resp.Release()")
	if idx < 0 {
		t.Fatal("FAIL: resp.Release() not found in dig.go")
	}
	releaseLine := strings.Count(string(src)[:idx], "\n") + 1
	cmdStart := strings.Index(string(src), "func cmdDig(")
	// cmdDig is the function that contains the release; verify a `return
	// nil` appears at or after the release within the same function region.
	region := string(src)[cmdStart:]
	relInRegion := strings.Index(region, "resp.Release()")
	retInRegion := strings.Index(region, "return nil")
	if relInRegion < 0 || retInRegion < 0 || relInRegion > retInRegion {
		t.Errorf("resp.Release() must appear inside cmdDig before its `return nil` "+
			"(line %d); pooled *Message would leak on every dig invocation", releaseLine)
	}
}
