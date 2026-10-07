package cluster

import (
	"fmt"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F450: a gossip "full"/"reload" zone update swaps a new *Zone into the
// manager; it must fire the mutation hook (like restoreZones, F342) so query
// routing adopts it instead of answering from the replaced object.
func TestHandleZoneUpdate_FullReloadNotifiesMutationHook(t *testing.T) {
	text := func(origin, ip string, serial int) []byte {
		return []byte(fmt.Sprintf("$ORIGIN %[1]s\n@ 3600 IN SOA ns1.%[1]s hostmaster.%[1]s %[3]d 3600 600 604800 86400\n@ 3600 IN NS ns1.%[1]s\nns1 3600 IN A %[2]s\n", origin, ip, serial))
	}
	m := zone.NewManager()
	m.LoadZone(zoneHooksTestZone(t, "a.example.", "192.0.2.1"), "")
	view := &zoneHooksView{}
	view.rebuild(m)
	m.SetMutationHook(func(string, bool) { view.rebuild(m) })
	c := &Cluster{zoneManager: m, logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}

	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "a.example.", Action: "full", Serial: 3, RawZone: text("a.example.", "192.0.2.99", 3)})
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "b.example.", Action: "reload", Serial: 1, RawZone: text("b.example.", "192.0.2.42", 1)})
	if a, b := view.ns1("a.example."), view.ns1("b.example."); a != "192.0.2.99" || b != "192.0.2.42" || !view.sameAsManager(m) {
		t.Fatalf("routing view after gossip full/reload: a=%s b=%s (want 192.0.2.99, 192.0.2.42)", a, b)
	}
	// An unparsable payload changes nothing.
	c.handleZoneUpdate(ZoneUpdatePayload{ZoneName: "a.example.", Action: "full", Serial: 4, RawZone: []byte("$ORIGIN a.example.\n@ IN BOGUS\n")})
	if a := view.ns1("a.example."); a != "192.0.2.99" || !view.sameAsManager(m) {
		t.Fatalf("unparsable update changed routing: a=%s", a)
	}
}
