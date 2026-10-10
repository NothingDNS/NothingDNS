package transfer

// F677: an UPDATE whose apex SOA cannot be re-parsed from its text form (a wire
// label with a space) failed in the middle of the apply loop, after earlier
// operations had been applied: no serial bump, no journal entry, no side effects.

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ddnsSOAAtomicSOAText is what the UPDATE handler (parseUpdates) produces for an SOA RR
// received on the wire: rr.Data.String(). The MNAME label contains a space,
// which is a valid wire label.
func ddnsSOAAtomicSOAText(t *testing.T, label string) string {
	var rd []byte
	for i := 0; i < 2; i++ {
		rd = append(rd, byte(len(label)))
		rd = append(rd, label...)
		rd = append(rd, 7)
		rd = append(rd, "example"...)
		rd = append(rd, 3)
		rd = append(rd, "com"...)
		rd = append(rd, 0)
	}
	var tail [20]byte
	binary.BigEndian.PutUint32(tail[0:], 99)
	rd = append(rd, tail[:]...)
	soa := &protocol.RDataSOA{}
	if _, err := soa.Unpack(rd, 0, uint16(len(rd))); err != nil {
		t.Fatalf("INVALID PROOF: unpack: %v", err)
	}
	return soa.String()
}

func ddnsSOAAtomicZone() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", Type: "SOA", Class: "IN", TTL: 300, RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "example.com.", Type: "NS", Class: "IN", TTL: 300, RData: "ns1.example.com."},
	}
	return z
}

func ddnsSOAAtomicState(z *zone.Zone) string {
	z.RLock()
	defer z.RUnlock()
	return fmt.Sprintf("serial=%d a-records=%d", z.SOA.Serial, len(z.Records["new.example.com."]))
}

func TestApplyUpdate_MalformedApexSOAIsAtomic(t *testing.T) {
	bad := ddnsSOAAtomicSOAText(t, "a b")
	add := UpdateOperation{Name: "new.example.com.", Type: protocol.TypeA, TTL: 60, RData: "192.0.2.50", Operation: UpdateOpAdd}
	badSOA := UpdateOperation{Name: "example.com.", Type: protocol.TypeSOA, TTL: 300, RData: bad, Operation: UpdateOpAdd}
	req := func(ops ...UpdateOperation) *UpdateRequest {
		return &UpdateRequest{ZoneName: "example.com.", Updates: ops}
	}

	// 1. proof scenario, both orders, several preceding operations
	for _, ops := range [][]UpdateOperation{{add, badSOA}, {badSOA, add}, {add, add, badSOA, add}} {
		z := ddnsSOAAtomicZone()
		before := ddnsSOAAtomicState(z)
		if err := ApplyUpdate(z, req(ops...)); err == nil {
			t.Fatal("bad SOA accepted")
		}
		if ddnsSOAAtomicState(z) != before {
			t.Fatalf("failed update changed the zone: %s -> %s", before, ddnsSOAAtomicState(z))
		}
	}
	// 2. a well-formed, newer apex SOA still applies together with other ops (serial = 99)
	z := ddnsSOAAtomicZone()
	good := UpdateOperation{Name: "example.com.", Type: protocol.TypeSOA, TTL: 300, RData: ddnsSOAAtomicSOAText(t, "ns1"), Operation: UpdateOpAdd}
	if err := ApplyUpdate(z, req(add, good)); err != nil {
		t.Fatalf("good update: %v", err)
	}
	// IncrementSerial moves the serial to the date form, so only check it advanced (not date-dependent).
	if z.SOA.Serial < 99 || len(z.Records["new.example.com."]) != 1 {
		t.Fatalf("good update state = %s", ddnsSOAAtomicState(z))
	}
	// 3. a malformed SOA away from the apex is still silently ignored (unchanged behavior)
	z = ddnsSOAAtomicZone()
	off := UpdateOperation{Name: "new.example.com.", Type: protocol.TypeSOA, TTL: 300, RData: bad, Operation: UpdateOpAdd}
	if err := ApplyUpdate(z, req(add, off)); err != nil {
		t.Fatalf("non-apex SOA: %v", err)
	}
	if z.SOA.Serial == 1 || len(z.Records["new.example.com."]) != 1 {
		t.Fatalf("non-apex SOA state = %s", ddnsSOAAtomicState(z))
	}
	// 4. deletes before the bad SOA are not applied either
	z = ddnsSOAAtomicZone()
	z.Records["gone.example.com."] = []zone.Record{{Name: "gone.example.com.", Type: "A", Class: "IN", TTL: 60, RData: "192.0.2.9"}}
	del := UpdateOperation{Name: "gone.example.com.", Type: protocol.TypeA, Operation: UpdateOpDeleteRRSet}
	if err := ApplyUpdate(z, req(del, badSOA)); err == nil {
		t.Fatal("bad SOA accepted")
	}
	if len(z.Records["gone.example.com."]) != 1 {
		t.Fatal("delete applied although the update failed")
	}
}
