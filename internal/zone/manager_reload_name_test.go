package zone

import (
	"os"
	"path/filepath"
	"testing"
)

// Reload takes the zone name in any spelling the rest of the manager accepts
// (AddRecord, DeleteZone, ... normalise it): without the trailing dot and in
// any case, not only the absolute lower-case form the map is keyed by.
func TestManagerReloadAcceptsNameWithoutTrailingDot(t *testing.T) {
	const v1 = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
	const v2 = v1 + "www IN A 192.0.2.10\n"

	for _, name := range []string{"example.com.", "example.com", "Example.COM", "EXAMPLE.COM."} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "example.com.zone")
			if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
				t.Fatal(err)
			}
			m := NewManager()
			if err := m.Load("example.com.", path); err != nil {
				t.Fatal(err)
			}
			hooked := ""
			m.SetMutationHook(func(zoneName string, deleted bool) { hooked = zoneName })

			if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.Reload(name); err != nil {
				t.Fatalf("FAIL: Reload(%q): %v", name, err)
			}
			if recs, _ := m.GetRecords("example.com.", "www"); len(recs) != 1 {
				t.Errorf("reload did not pick up the edited file: www records = %d", len(recs))
			}
			if hooked != "example.com." {
				t.Errorf("mutation hook got %q, want the canonical name example.com.", hooked)
			}
		})
	}

	// Control: a zone that is not loaded is still an error, in either spelling.
	m := NewManager()
	for _, name := range []string{"absent.example.", "absent.example"} {
		if err := m.Reload(name); err == nil {
			t.Errorf("Reload(%q) of an unknown zone succeeded", name)
		}
	}
}
