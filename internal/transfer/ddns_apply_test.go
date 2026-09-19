package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// RFC 2136 §3.4.2: the server either performs ALL updates in a request or
// none of them. A mid-sequence validation failure (RDATA rejected by
// zone.ValidateRecordData after a valid add) must leave the zone untouched —
// previously the valid ops applied, the serial stayed unbumped, and the
// in-memory-only change vanished on restart.
func TestApplyUpdateIsAtomicOnMalformedRData(t *testing.T) {
	z := zone.NewZone("example.com.")

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Updates: []UpdateOperation{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1", Operation: UpdateOpAdd},
			{Name: "mail.example.com.", Type: protocol.TypeA, TTL: 300,
				RData:     "192.0.2.1\nmail.example.com. 300 IN A 192.0.2.99",
				Operation: UpdateOpAdd},
		},
	}

	if err := ApplyUpdate(z, update); err == nil {
		t.Fatal("FAIL: the update containing injectable RDATA was accepted")
	}

	if recs := z.Records["www.example.com."]; len(recs) > 0 {
		t.Fatalf("FAIL: partial apply — www.example.com. exists in the zone despite the atomic update failing: %+v", recs)
	}
}
