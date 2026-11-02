package transfer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

// A persisted slave zone that holds a CNAME next to other data is still
// served, but the operator is told, as for replicated zone data.
func TestLoadPersistedZoneWarnsAboutCNAMEWithOtherData(t *testing.T) {
	var buf bytes.Buffer
	prev := util.GetDefaultLogger()
	util.SetDefaultLogger(util.NewLogger(util.DEBUG, util.TextFormat, &buf))
	defer util.SetDefaultLogger(prev)

	dir := t.TempDir()
	body := "$ORIGIN p.example.\n$TTL 300\n@ IN SOA ns1 h 1 3600 900 604800 300\n@ IN NS ns1\nns1 A 192.0.2.1\ncc CNAME ns1\ncc A 192.0.2.9\n"
	if err := os.WriteFile(filepath.Join(dir, "p.example.zone"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sm := NewSlaveManager(nil)
	sm.SetPersistDir(dir)
	sz := &SlaveZone{}
	sm.loadPersistedZone("p.example.", sz)
	if sz.Zone == nil {
		t.Fatalf("zone not loaded:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "CNAME and other data") {
		t.Errorf("no warning about the CNAME conflict:\n%s", buf.String())
	}
}
