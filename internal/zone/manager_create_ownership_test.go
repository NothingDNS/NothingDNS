package zone

import "testing"

func TestManagerCreateZoneOwnsSOAAndNSInputs(t *testing.T) {
	manager := NewManager()
	soa := &SOARecord{
		MName: "ns1", RName: "hostmaster@example.com",
		Serial: 1, TTL: 300, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
	}
	ns := []NSRecord{{NSDName: "ns1", TTL: 300}}

	if err := manager.CreateZone("example.com.", 300, soa, ns); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	soa.MName = "mutated.example.net."
	ns[0].NSDName = "mutated.example.net."

	z, ok := manager.Get("example.com.")
	if !ok {
		t.Fatal("created zone not found")
	}
	z.RLock()
	defer z.RUnlock()
	if got := z.SOA.MName; got != "ns1.example.com." {
		t.Fatalf("zone SOA changed with caller pointer: got %q", got)
	}
	if got := z.NS[0].NSDName; got != "ns1.example.com." {
		t.Fatalf("zone NS changed with caller slice: got %q", got)
	}
}
