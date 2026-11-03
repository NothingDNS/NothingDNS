package upstream

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed client.go
var clientSource string

//go:embed loadbalancer.go
var loadBalancerSource string

func TestTruncatedUDPFallbackReleasesResponse(t *testing.T) {
	tests := []struct {
		name   string
		source string
		start  string
		end    string
	}{
		{
			name:   "client",
			source: clientSource,
			start:  "resp, err := c.queryUDP(server, msg)",
			end:    "resp, err = c.queryTCP(server, msg)",
		},
		{
			name:   "load balancer primary",
			source: loadBalancerSource,
			start:  "resp, err := lb.queryUDP(target.Address, msg)",
			end:    "resp, err = lb.queryTCP(target.Address, msg)",
		},
		{
			name:   "load balancer failover",
			source: loadBalancerSource,
			start:  "resp, retryErr := lb.queryUDP(failoverTarget.Address, msg)",
			end:    "resp, retryErr = lb.queryTCP(failoverTarget.Address, msg)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := strings.Index(test.source, test.start)
			if start < 0 {
				t.Fatalf("start marker %q not found", test.start)
			}
			end := strings.Index(test.source[start:], test.end)
			if end < 0 {
				t.Fatalf("end marker %q not found", test.end)
			}
			fallback := test.source[start : start+end]
			if !strings.Contains(fallback, "resp.Release()") {
				t.Fatal("truncated UDP response is overwritten without Release")
			}
		})
	}
}
