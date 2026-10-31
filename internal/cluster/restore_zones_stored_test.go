package cluster

import (
	"encoding/json"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A Raft snapshot holding a record that an earlier release accepted but the
// zone-file parser now refuses must still install: the record is skipped and
// the rest of the zone is kept, so the node can start.
func TestRestoreZonesSkipsUnservableStoredRecord(t *testing.T) {
	txt := "$ORIGIN trserver.example.\n$TTL 300\n" +
		"@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n" +
		"@ IN NS ns1\n" +
		"ns1 IN A 192.0.2.1\n" +
		"r1 IN A r1-137.trserver.example.\n" +
		"www IN A 192.0.2.80\n"
	payload, err := json.Marshal(map[string]string{"trserver.example.": txt})
	if err != nil {
		t.Fatal(err)
	}

	mgr := zone.NewManager()
	c := &Cluster{zoneManager: mgr, logger: util.NewLogger(util.INFO, util.TextFormat, nil)}
	if err := c.restoreZones(payload); err != nil {
		t.Fatalf("restoreZones: %v", err)
	}
	z, ok := mgr.Get("trserver.example.")
	if !ok {
		t.Fatal("zone not installed")
	}
	if len(z.Records["www.trserver.example."]) != 1 {
		t.Error("valid record missing after restore")
	}
	if len(z.Records["r1.trserver.example."]) != 0 {
		t.Error("unservable record was installed")
	}
}
