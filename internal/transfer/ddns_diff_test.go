package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F679: ApplyUpdate reports the change it actually made in UpdateRequest.Diff.
func TestApplyUpdate_ReportsNetDiff(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", Type: "SOA", Class: "IN", TTL: 300, RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", Type: "NS", Class: "IN", TTL: 300, RData: "ns1.example.com."},
	}
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.2"}}

	req := &UpdateRequest{ZoneName: "example.com.", Updates: []UpdateOperation{
		{Name: "www.example.com.", Type: protocol.TypeA, Operation: UpdateOpDeleteRRSet},                                 // removes the A
		{Name: "www.example.com.", Type: protocol.TypeCNAME, TTL: 60, RData: "ns1.example.com.", Operation: UpdateOpAdd}, // allowed after the delete
		{Name: "new.example.com.", Type: protocol.TypeA, TTL: 60, RData: "192.0.2.9", Operation: UpdateOpAdd},            // added
		{Name: "new.example.com.", Type: protocol.TypeCNAME, TTL: 60, RData: "ns1.example.com.", Operation: UpdateOpAdd}, // ignored: owner has an A
	}}
	if err := ApplyUpdate(z, req); err != nil {
		t.Fatal(err)
	}
	if req.Diff == nil {
		t.Fatal("no Diff reported")
	}
	if len(req.Diff.Removed) != 1 || req.Diff.Removed[0].Type != "A" || req.Diff.Removed[0].RData != "192.0.2.2" {
		t.Fatalf("Removed = %+v", req.Diff.Removed)
	}
	got := map[string]bool{}
	for _, r := range req.Diff.Added {
		got[r.Name+"|"+r.Type] = true
	}
	if len(req.Diff.Added) != 2 || !got["www.example.com.|CNAME"] || !got["new.example.com.|A"] {
		t.Fatalf("Added = %+v (the ignored CNAME at new.example.com. must not appear)", req.Diff.Added)
	}
}
