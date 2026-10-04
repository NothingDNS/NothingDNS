// Regression: the XoT (RFC 9103) IXFR server must fall back to a full AXFR
// when the client's serial is not covered by the retained journal.
//
// CONTRACT. RFC 1995 §4 / RFC 5936 §4.2: when a server cannot supply the
// incremental changes a secondary asks for, it MUST answer with a full AXFR.
//
// AFFECTED PATH. XoTServer.generateIXFRRecords (xot.go:615) hands the journal
// to XoTServer.buildIncrementalIXFR (xot.go:674), which guarded the journal gap
// with only:
//
//	if startIdx > 0 && entries[startIdx-1].Serial != clientSerial { ...AXFR... }
//
// The `startIdx > 0` conjunct makes the check vacuous when startIdx == 0 —
// exactly the "client is older than every retained journal entry" case, which
// is what the journal's maxJournalSize trimming produces. The code then builds
// a delta from clientSerial straight to entries[0].Serial and returns it as a
// successful incremental transfer, so the secondary converges to a wrong zone
// while the transfer looks successful. (The IXFR-over-TCP sibling
// IXFRServer.generateIncrementalIXFR was fixed for this defect in the earlier
// journal-gap round; the XoT path was left behind. Regression guard for the
// TCP path: proof_stdrnd003_ixfr_journal_gap_test.go.)
//
// The controls below pin the other direction: a client exactly one change
// behind the oldest retained entry (entries[0].OldSerial) and a client inside
// the window must still receive a real incremental delta, so the fix must not
// degrade every XoT IXFR into a full transfer.
package transfer

import (
	"strings"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const xot037Origin = "xot037.example.com."

// xot037Zone builds a zone at the given serial holding one long-lived record
// that is deliberately absent from every journal change. "static" stands in
// for every record created before the journal window: a correct full transfer
// must include it, a truncated delta will not.
func xot037Zone(serial uint32) *zone.Zone {
	return &zone.Zone{
		Origin: xot037Origin,
		SOA: &zone.SOARecord{
			Name:    xot037Origin,
			TTL:     3600,
			MName:   "ns1." + xot037Origin,
			RName:   "hostmaster." + xot037Origin,
			Serial:  serial,
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: map[string][]zone.Record{
			"static." + xot037Origin: {{
				Name: "static." + xot037Origin, TTL: 300,
				Class: "IN", Type: "A", RData: "1.2.3.4",
			}},
		},
	}
}

// xot037JournalStore is an injected JournalStore boundary that preserves
// IXFRJournalEntry.OldSerial (the persisted codec does not write it), so the
// covered-boundary control below is reachable.
type xot037JournalStore struct{ entries []*IXFRJournalEntry }

func (s *xot037JournalStore) SaveEntry(string, *IXFRJournalEntry) error { return nil }
func (s *xot037JournalStore) LoadEntries(string) ([]*IXFRJournalEntry, error) {
	return s.entries, nil
}
func (s *xot037JournalStore) Truncate(string, int) error { return nil }

// xot037Server wires a real XoTServer (the production handler's server type,
// built directly because the fields are package-private) over a real zone with
// a three-entry journal (8->9, 9->10, 10->11). The "static" record predates all
// of them.
func xot037Server(t *testing.T) *XoTServer {
	t.Helper()
	z := xot037Zone(11)
	srv := &XoTServer{
		zones:   map[string]*zone.Zone{strings.ToLower(z.Origin): z},
		zonesMu: &sync.RWMutex{},
		stopCh:  make(chan struct{}),
	}
	srv.SetJournalStore(&xot037JournalStore{entries: []*IXFRJournalEntry{
		{OldSerial: 8, Serial: 9, Added: []zone.RecordChange{
			{Name: "tmp1." + xot037Origin, Type: protocol.TypeA, TTL: 300, RData: "5.5.5.5"}}},
		{OldSerial: 9, Serial: 10, Added: []zone.RecordChange{
			{Name: "tmp2." + xot037Origin, Type: protocol.TypeA, TTL: 300, RData: "6.6.6.6"}}},
		{OldSerial: 10, Serial: 11, Added: []zone.RecordChange{
			{Name: "tmp3." + xot037Origin, Type: protocol.TypeA, TTL: 300, RData: "7.7.7.7"}}},
	}})
	return srv
}

func xot037HasA(records []*protocol.ResourceRecord, owner string) bool {
	for _, rr := range records {
		if rr != nil && rr.Name != nil && rr.Type == protocol.TypeA && rr.Name.String() == owner {
			return true
		}
	}
	return false
}

func xot037Owners(records []*protocol.ResourceRecord) []string {
	var out []string
	for _, rr := range records {
		if rr != nil && rr.Name != nil {
			out = append(out, rr.Name.String())
		}
	}
	return out
}

// TestXoTRound037IXFRFallsBackToAXFRWhenJournalDoesNotCoverClient is the defect
// case: a client serial older than the whole retained journal must be answered
// with a full transfer, not a truncated delta that omits pre-journal records.
// generateIXFRRecords is the production decision function that
// handleIXFRRequest (xot.go:471) calls for every incoming IXFR-over-TLS query.
func TestXoTRound037IXFRFallsBackToAXFRWhenJournalDoesNotCoverClient(t *testing.T) {
	srv := xot037Server(t)

	// Serial 3 predates every journal entry (8->9, 9->10, 10->11).
	records, err := srv.generateIXFRRecords(xot037Zone(11), 3)
	if err != nil {
		t.Fatalf("generateIXFRRecords returned an error instead of falling back to AXFR: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("generateIXFRRecords returned an empty response")
	}
	if !xot037HasA(records, "static."+xot037Origin) {
		t.Errorf("client serial 3 is older than the retained journal, so the XoT server must "+
			"answer with a full AXFR (RFC 1995 §4 / RFC 5936 §4.2), which necessarily contains "+
			"the zone's authoritative records. Response owners %v omit %q, proving a truncated "+
			"incremental delta was served and the secondary's zone would be silently corrupted.",
			xot037Owners(records), "static."+xot037Origin)
	}
}

// TestXoTRound037IXFRStillServesDeltaForCoveredClient pins the other direction:
// a client exactly one change behind the oldest retained entry and a client
// inside the window must still receive a real incremental delta, so the fix
// must not degrade every XoT IXFR into a full AXFR.
func TestXoTRound037IXFRStillServesDeltaForCoveredClient(t *testing.T) {
	srv := xot037Server(t)

	tests := []struct {
		name        string
		serial      uint32
		wantPresent string
	}{
		{"at the oldest entry's pre-change serial", 8, "tmp2." + xot037Origin},
		{"inside the journal window", 9, "tmp3." + xot037Origin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			records, err := srv.generateIXFRRecords(xot037Zone(11), tc.serial)
			if err != nil {
				t.Fatalf("generateIXFRRecords: %v", err)
			}
			if !xot037HasA(records, tc.wantPresent) {
				t.Errorf("a covered client (serial %d) must still get the incremental delta "+
					"containing %q; got owners %v", tc.serial, tc.wantPresent, xot037Owners(records))
			}
			if xot037HasA(records, "static."+xot037Origin) {
				t.Errorf("a covered client must receive a DELTA, not a full AXFR "+
					"(the fix must not degrade every XoT IXFR); got owners %v", xot037Owners(records))
			}
		})
	}
}

// TestXoTRound037IXFRUpToDateClientGetsSingleSOA is the neighbouring boundary: a
// client already at the server serial is answered with a single SOA and no zone
// data.
func TestXoTRound037IXFRUpToDateClientGetsSingleSOA(t *testing.T) {
	srv := xot037Server(t)

	records, err := srv.generateIXFRRecords(xot037Zone(11), 11)
	if err != nil {
		t.Fatalf("generateIXFRRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("an up-to-date client should get exactly one SOA, got %d records: %v",
			len(records), xot037Owners(records))
	}
}
