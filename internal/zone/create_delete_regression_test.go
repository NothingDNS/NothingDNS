package zone

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSOAMailbox(t *testing.T) {
	tests := []struct {
		email, want string
		wantErr     bool
	}{
		{"", "hostmaster.example.com.", false},
		{"admin@example.com", "admin.example.com.", false},
		{"admin@example.com.", "admin.example.com.", false},
		{"hostmaster.example.com", "hostmaster.example.com.", false},
		{"hostmaster.example.com.", "hostmaster.example.com.", false},
		{"first.last@example.com", "", true},
		{"@example.com", "", true},
		{"admin@", "", true},
		{"has space@example.com", "", true},
	}
	for _, tt := range tests {
		got, err := SOAMailbox(tt.email, "example.com")
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("SOAMailbox(%q) = (%q, %v), want (%q, err=%v)", tt.email, got, err, tt.want, tt.wantErr)
		}
	}
}

// A zone created without an admin email or with names lacking a trailing
// dot must still have an SOA that survives the persistence round trip.
func TestCreateZoneNormalizesSOAForPersistence(t *testing.T) {
	m := NewManager()
	soa := &SOARecord{MName: "ns1.example.com", RName: "", Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
	if err := m.CreateZone("example.com", 3600, soa, []NSRecord{{NSDName: "ns2"}}); err != nil {
		t.Fatal(err)
	}
	z, _ := m.Get("example.com.")
	var soaRData, nsRData string
	for _, rec := range z.Records["example.com."] {
		switch rec.Type {
		case "SOA":
			soaRData = rec.RData
		case "NS":
			nsRData = rec.RData
		}
	}
	parsed := parseSOAFromRData(soaRData)
	if parsed == nil {
		t.Fatalf("SOA RDATA %q cannot be parsed back", soaRData)
	}
	if parsed.MName != "ns1.example.com." || parsed.RName != "hostmaster.example.com." {
		t.Errorf("SOA names = %q %q", parsed.MName, parsed.RName)
	}
	if nsRData != "ns2.example.com." {
		t.Errorf("relative NS = %q, want ns2.example.com.", nsRData)
	}
	if err := m.CreateZone("bad.example", 3600, &SOARecord{MName: "ns1.bad.example.", RName: "first.last@bad.example"}, []NSRecord{{NSDName: "ns1.bad.example."}}); err == nil {
		t.Error("an admin email with dots in the user part must be rejected")
	}
}

// Deleting a zone removes only files inside zone_dir; zone files listed in
// the config (outside zone_dir) belong to the operator and are kept.
func TestDeleteZoneKeepsFilesOutsideZoneDir(t *testing.T) {
	zoneDir := t.TempDir()
	external := filepath.Join(t.TempDir(), "external.test.zone")
	content := "$ORIGIN external.test.\n$TTL 300\n@ IN SOA ns1.external.test. hostmaster.external.test. 1 3600 600 86400 300\n@ IN NS ns1.external.test.\nns1 IN A 192.0.2.1\n"
	if err := os.WriteFile(external, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.SetZoneDir(zoneDir)
	// Config-listed zones are loaded with LoadZone (as cmd/nothingdns does).
	f, err := os.Open(external)
	if err != nil {
		t.Fatal(err)
	}
	z, err := ParseFile(external, f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	m.LoadZone(z, external)
	if err := m.DeleteZone("external.test."); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(external); err != nil {
		t.Errorf("config-owned zone file was deleted: %v", err)
	}

	soa := &SOARecord{MName: "ns1.owned.test.", RName: "hostmaster.owned.test."}
	if err := m.CreateZone("owned.test", 300, soa, []NSRecord{{NSDName: "ns1.owned.test."}}); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(zoneDir, sanitizeZoneFileName("owned.test.")+".zone")
	if _, err := os.Stat(owned); err != nil {
		t.Fatalf("zone_dir file not written: %v", err)
	}
	if err := m.DeleteZone("owned.test."); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Errorf("zone_dir file not removed: %v", err)
	}
}
