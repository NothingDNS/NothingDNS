package cluster

import (
	"encoding/json"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func soaU32(v uint32) *uint32 { return &v }

func soaEnvelope(t *testing.T, cmd raft.ZoneCommand, p zoneSOAPayload) raft.ZoneCommand {
	t.Helper()
	meta, err := json.Marshal(zoneSOAEnvelope{SOA: &p})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Type, cmd.Metadata = "create_zone", meta
	return cmd
}

// #19: an SOA edit replicated as a create_zone envelope without nameservers
// changes the SOA, bumps the serial and reports the result to the waiter.
func TestApplyRaftZoneCommand_SOAUpdate(t *testing.T) {
	m, hooks := f497Manager(t)
	m.SetDeterministicSerials(true)
	c := &Cluster{zoneManager: m, logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}
	before, _ := m.SOA("a.example.")

	ch := c.zoneBatches.register("soa-1")
	c.applyRaftZoneCommand(soaEnvelope(t, raft.ZoneCommand{Zone: "a.example."},
		zoneSOAPayload{V: zoneSOAVersion, ID: "soa-1", Update: zone.SOAUpdate{Minimum: soaU32(300)}}))
	if err := <-ch; err != nil {
		t.Fatalf("apply result: %v", err)
	}
	after, _ := m.SOA("a.example.")
	if after.Minimum != 300 || after.Serial != before.Serial+1 || after.Refresh != before.Refresh {
		t.Fatalf("SOA after edit = %+v (before %+v)", after, before)
	}
	if hooks.Load() != 1 {
		t.Fatalf("mutation hook fired %d times, want 1", hooks.Load())
	}

	// An invalid edit (the zone changed since the proposer checked it) is
	// rejected on apply and reported; nothing changes.
	ch = c.zoneBatches.register("soa-2")
	c.applyRaftZoneCommand(soaEnvelope(t, raft.ZoneCommand{Zone: "a.example."},
		zoneSOAPayload{V: zoneSOAVersion, ID: "soa-2", Update: zone.SOAUpdate{Retry: soaU32(7200)}}))
	if err := <-ch; err == nil {
		t.Fatal("invalid edit reported success")
	}
	// An unknown payload version is rejected, not guessed at.
	ch = c.zoneBatches.register("soa-3")
	c.applyRaftZoneCommand(soaEnvelope(t, raft.ZoneCommand{Zone: "a.example."},
		zoneSOAPayload{V: 99, ID: "soa-3", Update: zone.SOAUpdate{Minimum: soaU32(60)}}))
	if err := <-ch; err == nil {
		t.Fatal("unknown version reported success")
	}
	if got, _ := m.SOA("a.example."); got != after {
		t.Fatalf("rejected edits changed the SOA: %+v -> %+v", after, got)
	}
	if hooks.Load() != 1 {
		t.Fatalf("rejected edits fired the hook (%d)", hooks.Load())
	}
}

// The payload on a create_zone with nameservers sets the new zone's timers;
// names and TTL still come from the command.
func TestApplyRaftZoneCommand_CreateZoneWithSOATimers(t *testing.T) {
	m := zone.NewManager()
	c := &Cluster{zoneManager: m, logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}
	other := "evil.example."
	c.applyRaftZoneCommand(soaEnvelope(t, raft.ZoneCommand{
		Zone: "b.example.", TTL: 600, AdminEmail: "dns@b.example", Nameservers: []string{"ns1.b.example."},
	}, zoneSOAPayload{V: zoneSOAVersion, Update: zone.SOAUpdate{
		Refresh: soaU32(7200), Retry: soaU32(900), Expire: soaU32(1209600), Minimum: soaU32(300),
		MName: &other, TTL: soaU32(5),
	}}))
	got, err := m.SOA("b.example.")
	if err != nil {
		t.Fatalf("zone not created: %v", err)
	}
	want := zone.SOARecord{TTL: 600, MName: "ns1.b.example.", RName: "dns.b.example.", Serial: 1,
		Refresh: 7200, Retry: 900, Expire: 1209600, Minimum: 300}
	if got != want {
		t.Fatalf("SOA = %+v, want %+v", got, want)
	}
}
