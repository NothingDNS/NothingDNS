// Regression: IXFR must fall back to a full AXFR when the client's serial is
// not covered by the retained journal.
//
// CONTRACT. RFC 1995 §4 / RFC 5936 §4.2: when a server cannot supply the
// incremental changes a secondary asks for, it MUST answer with a full AXFR.
// HandleIXFR implements that contract by falling back to generateAXFRRecords
// whenever generateIncrementalIXFR returns an error, so a client whose serial
// the journal does not cover must receive a response that necessarily contains
// the zone's authoritative records.
//
// DEFECT. generateIncrementalIXFR found the first journal entry newer than the
// client serial (startIdx) and then guarded the gap with:
//
//	if startIdx > 0 && journal[startIdx-1].Serial != clientSerial { ...error... }
//
// The `startIdx > 0` conjunct made the check vacuous when startIdx == 0 —
// exactly the "client is older than every retained journal entry" case. The
// journal is trimmed at maxJournalSize, so the changes between the client and
// journal[0] are gone. The code then built a delta from clientSerial straight
// to journal[0] and returned no error, so HandleIXFR served it. The secondary
// applied an incomplete change set and ended up with a silently corrupted zone.
//
// FIX. startIdx == 0 is now treated as "journal does not cover the client", so
// the error is returned and HandleIXFR falls back to a full AXFR.
//
// The controls below pin the other direction: a client whose serial IS covered
// must still receive a real incremental delta, so the fix must not degrade
// every IXFR into a full transfer.
package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	rrZoneOrigin = "example.com."
	rrClientIP   = "127.0.0.1"
)

// rrZone builds a zone at the given serial holding one long-lived record that
// is deliberately NOT part of any journal change. "static" stands in for every
// record created before the journal window: a correct full transfer must
// include it, a truncated delta will not.
func rrZone(serial uint32) *zone.Zone {
	return &zone.Zone{
		Origin: rrZoneOrigin,
		SOA: &zone.SOARecord{
			Name:    rrZoneOrigin,
			TTL:     3600,
			MName:   "ns1." + rrZoneOrigin,
			RName:   "hostmaster." + rrZoneOrigin,
			Serial:  serial,
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minimum: 86400,
		},
		Records: map[string][]zone.Record{
			"static." + rrZoneOrigin: {{
				Name: "static." + rrZoneOrigin, TTL: 300,
				Class: "IN", Type: "A", RData: "1.2.3.4",
			}},
		},
	}
}

// rrServer wires a real IXFR server over a real zone with a three-entry
// journal (8->9, 9->10, 10->11). The "static" record predates all of them.
func rrServer(t *testing.T) *IXFRServer {
	t.Helper()
	axfr := NewAXFRServer(nil, WithAllowList([]string{"127.0.0.0/8"}))
	axfr.AddZone(rrZone(11))
	srv := NewIXFRServer(axfr)

	srv.RecordChange(rrZoneOrigin, 8, 9,
		[]zone.RecordChange{{Name: "tmp1." + rrZoneOrigin, Type: protocol.TypeA, TTL: 300, RData: "5.5.5.5"}}, nil)
	srv.RecordChange(rrZoneOrigin, 9, 10,
		[]zone.RecordChange{{Name: "tmp2." + rrZoneOrigin, Type: protocol.TypeA, TTL: 300, RData: "6.6.6.6"}}, nil)
	srv.RecordChange(rrZoneOrigin, 10, 11,
		[]zone.RecordChange{{Name: "tmp3." + rrZoneOrigin, Type: protocol.TypeA, TTL: 300, RData: "7.7.7.7"}}, nil)

	return srv
}

// rrRequest builds a real IXFR query carrying clientSerial in the Authority
// SOA, exactly as a secondary would.
func rrRequest(t *testing.T, clientSerial uint32) *protocol.Message {
	t.Helper()
	name, err := protocol.ParseName(rrZoneOrigin)
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	mname, _ := protocol.ParseName("ns1." + rrZoneOrigin)
	rname, _ := protocol.ParseName("hostmaster." + rrZoneOrigin)
	return &protocol.Message{
		Header:    protocol.Header{ID: 4242, QDCount: 1},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{{
			Name:  name,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataSOA{
				MName: mname, RName: rname, Serial: clientSerial,
				Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
			},
		}},
	}
}

func rrHasA(records []*protocol.ResourceRecord, owner string) bool {
	for _, rr := range records {
		if rr != nil && rr.Name != nil && rr.Type == protocol.TypeA && rr.Name.String() == owner {
			return true
		}
	}
	return false
}

func rrOwners(records []*protocol.ResourceRecord) []string {
	var out []string
	for _, rr := range records {
		if rr != nil && rr.Name != nil {
			out = append(out, rr.Name.String())
		}
	}
	return out
}

// TestIXFRFallsBackToAXFRWhenJournalDoesNotCoverClient is the defect case: a
// client serial older than the whole retained journal must be answered with a
// full transfer, not a truncated delta that omits pre-journal records.
func TestIXFRFallsBackToAXFRWhenJournalDoesNotCoverClient(t *testing.T) {
	srv := rrServer(t)

	// Serial 3 predates every journal entry (9, 10, 11).
	resp, err := srv.HandleIXFR(rrRequest(t, 3), net.ParseIP(rrClientIP))
	if err != nil {
		t.Fatalf("HandleIXFR returned an error instead of falling back to AXFR: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("HandleIXFR returned an empty response")
	}
	if !rrHasA(resp, "static."+rrZoneOrigin) {
		t.Errorf("client serial 3 is older than the retained journal, so the server must "+
			"answer with a full AXFR (RFC 1995 §4 / RFC 5936 §4.2), which necessarily "+
			"contains the zone's authoritative records. Response owners %v omit %q, "+
			"proving a truncated incremental delta was served and the secondary's zone "+
			"would be silently corrupted.", rrOwners(resp), "static."+rrZoneOrigin)
	}
}

// TestIXFRStillServesDeltaForCoveredClient pins the other direction: a client
// whose serial is covered by the journal must still receive a real incremental
// delta, so the fix must not degrade every IXFR into a full AXFR.
func TestIXFRStillServesDeltaForCoveredClient(t *testing.T) {
	srv := rrServer(t)

	tests := []struct {
		name        string
		serial      uint32
		wantPresent string
	}{
		{"first journal entry", 9, "tmp2." + rrZoneOrigin},
		{"last journal entry", 10, "tmp3." + rrZoneOrigin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.HandleIXFR(rrRequest(t, tc.serial), net.ParseIP(rrClientIP))
			if err != nil {
				t.Fatalf("HandleIXFR: %v", err)
			}
			if !rrHasA(resp, tc.wantPresent) {
				t.Errorf("a covered client (serial %d) must still get the incremental delta "+
					"containing %q; got owners %v", tc.serial, tc.wantPresent, rrOwners(resp))
			}
			if rrHasA(resp, "static."+rrZoneOrigin) {
				t.Errorf("a covered client must receive a DELTA, not a full AXFR "+
					"(the fix must not degrade every IXFR); got owners %v", rrOwners(resp))
			}
		})
	}
}

// TestIXFRUpToDateClientGetsSingleSOA is the neighbouring boundary: a client
// already at the server serial is answered with a single SOA and no zone data.
func TestIXFRUpToDateClientGetsSingleSOA(t *testing.T) {
	srv := rrServer(t)

	resp, err := srv.HandleIXFR(rrRequest(t, 11), net.ParseIP(rrClientIP))
	if err != nil {
		t.Fatalf("HandleIXFR: %v", err)
	}
	if len(resp) != 1 {
		t.Errorf("an up-to-date client should get exactly one SOA, got %d records: %v",
			len(resp), rrOwners(resp))
	}
}
