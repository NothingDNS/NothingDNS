package zone

import "testing"

func TestManagerUpdateRecordMovesOwnerIndex_F821(t *testing.T) {
	z := NewZone("example.com.")
	z.SOA = &SOARecord{Serial: 1}
	z.Records[z.Origin] = []Record{{Name: z.Origin, Type: "SOA", Class: "IN", TTL: 300, RData: "ns.example.com. hostmaster.example.com. 1 3600 600 86400 300"}}
	z.Records["old.example.com."] = []Record{{Name: "old.example.com.", Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.1"}}
	m := NewManager()
	m.LoadZone(z, "")

	err := m.UpdateRecord("example.com.", "old", "A", "192.0.2.1", Record{
		Name: "new", Type: "A", Class: "IN", TTL: 600, RData: "192.0.2.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := z.Lookup("old.example.com.", "A"); len(got) != 0 {
		t.Fatalf("old owner still has records: %+v", got)
	}
	got := z.Lookup("new.example.com.", "A")
	if len(got) != 1 || got[0].Name != "new.example.com." || got[0].RData != "192.0.2.2" {
		t.Fatalf("new owner records = %+v", got)
	}
}

func TestManagerUpdateRecordMoveRejectsDuplicate_F821(t *testing.T) {
	z := NewZone("example.com.")
	z.SOA = &SOARecord{Serial: 1}
	z.Records[z.Origin] = []Record{{Name: z.Origin, Type: "SOA", Class: "IN", TTL: 300, RData: "ns.example.com. hostmaster.example.com. 1 3600 600 86400 300"}}
	z.Records["old.example.com."] = []Record{{Name: "old.example.com.", Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.1"}}
	z.Records["new.example.com."] = []Record{{Name: "new.example.com.", Type: "A", Class: "IN", TTL: 300, RData: "192.0.2.2"}}
	m := NewManager()
	m.LoadZone(z, "")

	err := m.UpdateRecord("example.com.", "old", "A", "192.0.2.1", Record{
		Name: "new", Type: "A", Class: "IN", TTL: 600, RData: "192.0.2.2",
	})
	if err == nil {
		t.Fatal("duplicate move succeeded")
	}
	if got := z.Lookup("old.example.com.", "A"); len(got) != 1 {
		t.Fatalf("failed move mutated source: %+v", got)
	}
}
