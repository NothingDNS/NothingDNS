package main

// F679: the IXFR journal was built from the UPDATE operations instead of the change
// ApplyUpdate made, so RRset/name deletes (no RDATA) were skipped and ignored adds
// were invented: a secondary that followed the IXFR diff kept deleted records.

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func ixfrReplKey(name, typ string, ttl uint32, rdata string) string {
	rd := rdata
	if d := protocol.ParseRDataText(typ, rdata); d != nil {
		rd = d.String()
	}
	return fmt.Sprintf("%s|%s|%d|%s", strings.ToLower(name), strings.ToUpper(typ), ttl, rd)
}

func ixfrReplSet(z *zone.Zone) []string {
	z.RLock()
	defer z.RUnlock()
	var out []string
	for _, rs := range z.Records {
		for _, r := range rs {
			if strings.EqualFold(r.Type, "SOA") {
				continue
			}
			out = append(out, ixfrReplKey(r.Name, r.Type, r.TTL, r.RData))
		}
	}
	sort.Strings(out)
	return out
}

// ixfrReplReplicate applies each UPDATE to the master through the server's own path
// (ApplyUpdate + journal consumer), then replays the IXFR answer from the old
// serial onto a copy of the original zone and returns (master, slave) record sets.
func ixfrReplReplicate(t *testing.T, updates ...[]transfer.UpdateOperation) (master, slave []string) {
	h, _ := zoneDelBoot(t)
	z := h.zones["example.com."]
	base := ixfrReplSet(z)
	baseSerial := z.SOA.Serial
	for _, ops := range updates {
		old := z.SOA.Serial
		req := &transfer.UpdateRequest{ZoneName: "example.com.", Updates: ops}
		if err := transfer.ApplyUpdate(z, req); err != nil {
			t.Fatalf("ApplyUpdate: %v", err)
		}
		req.OldSerial, req.NewSerial = old, z.SOA.Serial
		ch := make(chan *transfer.UpdateRequest, 1)
		ch <- req
		close(ch)
		h.processUpdateEventsFrom(ch)
	}
	q, _ := protocol.NewQuery(9, "example.com.", protocol.TypeIXFR)
	origin, _ := protocol.ParseName("example.com.")
	mn, _ := protocol.ParseName("ns1.example.com.")
	rn, _ := protocol.ParseName("admin.example.com.")
	q.Authorities = append(q.Authorities, &protocol.ResourceRecord{Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataSOA{MName: mn, RName: rn, Serial: baseSerial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}})
	recs, err := h.transfer.IXFRServer.HandleIXFR(q, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleIXFR: %v", err)
	}
	// replay: [SOA, (SOA old, deletes..., SOA new, adds...)*, SOA]
	have := map[string]int{}
	for _, k := range base {
		have[k]++
	}
	deleting := true
	for i := 1; i < len(recs)-1; i++ {
		rr := recs[i]
		if rr.Type == protocol.TypeSOA {
			if i != 1 {
				deleting = !deleting
			}
			continue
		}
		k := ixfrReplKey(rr.Name.String(), protocol.TypeString(rr.Type), rr.TTL, rr.Data.String())
		if deleting {
			have[k]--
		} else {
			have[k]++
		}
	}
	for k, n := range have {
		for ; n > 0; n-- {
			slave = append(slave, k)
		}
	}
	sort.Strings(slave)
	return ixfrReplSet(z), slave
}

func ixfrReplOp(name string, typ uint16, ttl uint32, rdata string, op transfer.UpdateOpType) transfer.UpdateOperation {
	return transfer.UpdateOperation{Name: name, Type: typ, TTL: ttl, RData: rdata, Operation: op}
}

func TestIXFRJournal_DDNSChangesReplicateToSecondary(t *testing.T) {
	cases := map[string][][]transfer.UpdateOperation{
		"delete rrset":        {{ixfrReplOp("www.example.com.", protocol.TypeA, 0, "", transfer.UpdateOpDeleteRRSet)}},
		"delete name":         {{ixfrReplOp("www.example.com.", protocol.TypeANY, 0, "", transfer.UpdateOpDeleteName)}},
		"delete specific":     {{ixfrReplOp("www.example.com.", protocol.TypeA, 0, "192.0.2.2", transfer.UpdateOpDelete)}},
		"add":                 {{ixfrReplOp("new.example.com.", protocol.TypeA, 60, "192.0.2.50", transfer.UpdateOpAdd)}},
		"ignored cname add":   {{ixfrReplOp("www.example.com.", protocol.TypeCNAME, 60, "ns1.example.com.", transfer.UpdateOpAdd)}},
		"duplicate add":       {{ixfrReplOp("www.example.com.", protocol.TypeA, 300, "192.0.2.2", transfer.UpdateOpAdd)}},
		"ttl change":          {{ixfrReplOp("www.example.com.", protocol.TypeA, 77, "192.0.2.2", transfer.UpdateOpAdd)}},
		"replace via ops":     {{ixfrReplOp("www.example.com.", protocol.TypeA, 0, "", transfer.UpdateOpDeleteRRSet), ixfrReplOp("www.example.com.", protocol.TypeA, 60, "192.0.2.77", transfer.UpdateOpAdd)}},
		"two updates":         {{ixfrReplOp("a.example.com.", protocol.TypeA, 60, "192.0.2.1", transfer.UpdateOpAdd)}, {ixfrReplOp("a.example.com.", protocol.TypeA, 0, "", transfer.UpdateOpDeleteRRSet)}},
		"apex delete name":    {{ixfrReplOp("example.com.", protocol.TypeANY, 0, "", transfer.UpdateOpDeleteName)}},
		"delete missing name": {{ixfrReplOp("nope.example.com.", protocol.TypeANY, 0, "", transfer.UpdateOpDeleteName)}},
	}
	for name, ups := range cases {
		m, s := ixfrReplReplicate(t, ups...)
		if !reflect.DeepEqual(m, s) {
			t.Fatalf("%s: secondary diverges from master\n master: %v\n slave:  %v", name, m, s)
		}
	}
}
