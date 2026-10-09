package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// A wildcard CNAME whose target is itself wildcard-covered aliases to
// itself; resolveChainTarget must stop at the repeat instead of emitting
// the same RRset until its step cap (F636).
func TestResolveChainTarget_WildcardLoopNoDuplicates(t *testing.T) {
	const body = `$ORIGIN loop.test.
$TTL 300
@   IN SOA ns1 hostmaster 1 3600 600 86400 300
@   IN NS  ns1
ns1 IN A   192.0.2.1
*   IN CNAME x
`
	h := newTestHandler()
	h.zones["loop.test."] = loadTestZoneFile(t, "loop.test.", body)
	h.RebuildZoneTree()
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, newTestQuery(t, "y.loop.test.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("no response")
	}
	seen := map[string]bool{}
	for _, rr := range w.msg.Answers {
		if k := rr.String(); seen[k] {
			t.Fatalf("duplicate answer %s (answers=%d)", k, len(w.msg.Answers))
		} else {
			seen[k] = true
		}
	}
	if len(w.msg.Answers) != 2 {
		t.Errorf("answers = %d, want 2 (y CNAME x, x CNAME x)", len(w.msg.Answers))
	}
}
