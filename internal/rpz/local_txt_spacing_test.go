package rpz

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func localTXTFromPolicy(t *testing.T, content, owner string) string {
	t.Helper()
	e := loadRPZText(t, content)
	r := e.QNAMEPolicy(owner)
	for r != nil {
		if r.RRType == "TXT" {
			txt, ok := protocol.ParseRDataText(r.RRType, r.OverrideData).(*protocol.RDataTXT)
			if !ok || txt == nil || len(txt.Strings) != 1 {
				t.Fatalf("unexpected TXT data: %#v", txt)
			}
			return txt.Strings[0]
		}
		if len(r.Additional) == 0 {
			break
		}
		r = r.Additional[0]
	}
	t.Fatal("missing TXT rule for", owner)
	return ""
}

func TestPolicyTXTContinuationPreservesSpacing_F893(t *testing.T) {
	const want = "alpha  beta"
	got := localTXTFromPolicy(t, "info.example A 192.0.2.8\n    TXT \"alpha  beta\"\n", "info.example.")
	if got != want {
		t.Fatalf("REGRESSION: TXT = %q, want %q", got, want)
	}
}
