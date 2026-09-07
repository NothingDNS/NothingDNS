package upstream

import (
	_ "embed"
	"strings"
	"testing"
)

// TestQueryTCP_VerifyRelease confirms that LoadBalancer.queryTCP has
// defer resp.Release() immediately after protocol.UnpackMessage, preventing
// a pool leak on any non-TXID-mismatch exit path.
//go:embed loadbalancer.go
var source string

func TestQueryTCP_VerifyRelease(t *testing.T) {
	idx := strings.Index(source, "resp, err := protocol.UnpackMessage(buf[:respLen])")
	if idx < 0 {
		t.Fatal("could not find UnpackMessage call in loadbalancer.go")
	}
	after := source[idx : idx+200]
	if !strings.Contains(after, "resp.Release()") {
		t.Errorf("BUG: LoadBalancer.queryTCP is missing resp.Release() after UnpackMessage")
	}
}
