package cluster

import (
	_ "embed"
	"testing"
)

//go:embed gossip_handlers.go
var gossipHandlersSource string

// TestBroadcastFunctionsHaveBindPortFallback verifies that all broadcast functions
// use the BindPort fallback when node.Port == 0, matching the pattern already
// present in BroadcastCacheInvalidation.
//
// Bug: when node.Port == 0, these functions would send to udp://addr:0 which is
// silently dropped by the OS. BroadcastCacheInvalidation was fixed in d8baa98;
// the other broadcast functions were missed and are now fixed by this commit.
func TestBroadcastFunctionsHaveBindPortFallback(t *testing.T) {
	src := gossipHandlersSource

	// The correct pattern (as used in BroadcastCacheInvalidation):
	//   port := node.Port
	//   if port == 0 { port = gp.config.BindPort }
	//   ... Port: port
	//
	// Check each broadcast function: must contain all three elements of the pattern.
	for _, name := range []string{
		"BroadcastCacheInvalidation",
		"BroadcastZoneUpdate",
		"BroadcastConfigUpdate",
		"BroadcastDraining",
		"BroadcastNodeStats",
		"BroadcastClusterMetrics",
	} {
		// Extract a generous window of the function (3000 chars from func name)
		idx := -1
		for i := 0; i <= len(src)-len(name)-7; i++ {
			if src[i:i+len(name)] == name && i+len(name) < len(src) && src[i+len(name)] == '(' {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Errorf("%s: function not found in source", name)
			continue
		}
		end := idx + 3000
		if end > len(src) {
			end = len(src)
		}
		body := src[idx:end]

		hasPortVar := contains(body, "port := node.Port")
		hasZeroCheck := contains(body, "port == 0")
		hasBindFallback := contains(body, "gp.config.BindPort")
		// Two address construction patterns exist:
		// - fmt.Sprintf(..., port)  [BroadcastCacheInvalidation]
		// - Port: port              [all others]
		hasSprintfPort := contains(body, "fmt.Sprintf") && contains(body, ", port)")
		hasPortField := contains(body, "Port: port")
		hasPortInAddr := hasSprintfPort || hasPortField

		if !hasPortVar {
			t.Errorf("FAIL: %s does not declare 'port := node.Port'", name)
		}
		if !hasZeroCheck {
			t.Errorf("FAIL: %s does not check 'port == 0' — no fallback for node.Port==0", name)
		}
		if !hasBindFallback {
			t.Errorf("FAIL: %s does not fall back to gp.config.BindPort", name)
		}
		if !hasPortInAddr {
			t.Errorf("FAIL: %s does not use the 'port' variable in the address construction", name)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
