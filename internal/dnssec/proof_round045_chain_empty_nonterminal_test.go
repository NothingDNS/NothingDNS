// Round-045 proof: the signed denial chain must cover every name this server
// answers for — including empty non-terminals.
//
// CONTRACT. RFC 4035 §3.1.3.1 (quoted in cmd/nothingdns/denial_proof.go): a
// NODATA answer is proven by a denial record AT the queried name — "One NSEC at
// the name itself proves it — its type bitmap is the proof". RFC 5155 §8.5 says
// the same for NSEC3: the NSEC3 whose owner hash matches the QNAME. This
// server answers NODATA (not NXDOMAIN) for a name that exists only as an empty
// non-terminal — `Zone.NodeExists` / `nodeExistsLocked` in internal/zone, used
// by cmd/nothingdns/authoritative.go — and its own validator implements exactly
// that rule (`validateNSEC3`: `hashedNameStr == ownerHash` → check the bitmap).
//
// DEFECT. `generateNSEC` and `generateNSEC3` build the chain from the unique
// owner names present in the record list. An empty non-terminal owns no records,
// so it never enters the chain: the signed zone carries no NSEC at `b.example.com.`
// and no NSEC3 whose owner hash is hash(`b.example.com.`), even though the zone
// contains `a.b.example.com.`. A query for the empty non-terminal is answered
// NODATA by the server and cannot be proven by the signed zone, so a validating
// resolver rejects the answer (Bogus) — and the same zone cannot prove the
// name's existence to an RFC 8020 resolver either.
//
// FIX. Both generators add the empty non-terminals implied by the owner names
// before building the chain.
package dnssec

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rr045Records builds a zone whose only record below the apex-level NS/SOA is
// `a.b.example.com.`, which makes `b.example.com.` an empty non-terminal.
func rr045Records(t *testing.T) []*protocol.ResourceRecord {
	t.Helper()

	mk := func(name string, rrtype uint16, text string) *protocol.ResourceRecord {
		rd := protocol.ParseRDataText(protocol.TypeString(rrtype), text)
		if rd == nil {
			t.Fatalf("ParseRDataText(%s, %q) returned nil", protocol.TypeString(rrtype), text)
		}
		rr, err := protocol.NewResourceRecord(name, rrtype, protocol.ClassIN, 300, rd)
		if err != nil {
			t.Fatalf("NewResourceRecord(%s): %v", name, err)
		}
		return rr
	}

	return []*protocol.ResourceRecord{
		mk("example.com.", protocol.TypeSOA, "ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"),
		mk("example.com.", protocol.TypeNS, "ns1.example.com."),
		mk("ns1.example.com.", protocol.TypeA, "192.0.2.53"),
		mk("a.b.example.com.", protocol.TypeA, "192.0.2.7"),
	}
}

func rr045OwnerHash(t *testing.T, rr *protocol.ResourceRecord) string {
	t.Helper()
	if rr == nil || rr.Name == nil {
		t.Fatalf("record with nil name")
	}
	return strings.ToLower(extractNSEC3Hash(rr.Name.String()))
}

// TestRound045NSEC3ChainCoversEmptyNonTerminal is the defect case: the chain
// must contain an NSEC3 whose owner hash is the hash of the empty non-terminal.
func TestRound045NSEC3ChainCoversEmptyNonTerminal(t *testing.T) {
	const (
		algo = uint8(1)
		iter = uint16(0)
	)
	s := NewSigner("example.com.", SignerConfig{NSEC3Enabled: true, NSEC3Algorithm: algo, NSEC3Iterations: iter})
	records := rr045Records(t)

	chain := s.generateNSEC3(records)
	if len(chain) == 0 {
		t.Fatal("generateNSEC3 produced no records")
	}

	hash, err := NSEC3Hash("b.example.com.", algo, iter, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	want := strings.ToLower(protocol.Base32Encode(hash))

	for _, rr := range chain {
		if rr.Type != protocol.TypeNSEC3 {
			t.Fatalf("chain holds a %s record, want only NSEC3", protocol.TypeString(rr.Type))
		}
		if rr.Type == protocol.TypeNSEC3 && rr.Name != nil {
			// guard against a nil rdata panic below
			if _, ok := rr.Data.(*protocol.RDataNSEC3); !ok {
				t.Fatalf("NSEC3 record carries %T", rr.Data)
			}
		}
		if rr045OwnerHash(t, rr) == want {
			return
		}
	}

	got := make([]string, 0, len(chain))
	for _, rr := range chain {
		got = append(got, rr045OwnerHash(t, rr))
	}
	t.Fatalf("the NSEC3 chain has no record for the empty non-terminal b.example.com. "+
		"(owner hash %s). Owner hashes present: %v. The zone holds a.b.example.com., so "+
		"b.example.com. exists as a node; this server answers NODATA for it "+
		"(Zone.NodeExists) and RFC 4035 §3.1.3.1 / RFC 5155 §8.5 require a denial record "+
		"AT that name — without it the signed zone cannot prove the answer and a validating "+
		"resolver rejects it.", want, got)
}

// TestRound045NSECChainCoversEmptyNonTerminal is the same contract for NSEC.
func TestRound045NSECChainCoversEmptyNonTerminal(t *testing.T) {
	s := NewSigner("example.com.", SignerConfig{})
	records := rr045Records(t)

	chain := s.generateNSEC(records)
	if len(chain) == 0 {
		t.Fatal("generateNSEC produced no records")
	}
	for _, rr := range chain {
		if rr.Name != nil && strings.EqualFold(rr.Name.String(), "b.example.com.") {
			return
		}
	}
	got := make([]string, 0, len(chain))
	for _, rr := range chain {
		if rr.Name != nil {
			got = append(got, rr.Name.String())
		}
	}
	t.Fatalf("the NSEC chain has no record at the empty non-terminal b.example.com. "+
		"(owners present: %v). A NODATA answer for that name needs an NSEC at the name "+
		"itself (RFC 4035 §3.1.3.1), so the signed zone cannot prove it.", got)
}

// TestRound045ChainControls pins what must not change.
func TestRound045ChainControls(t *testing.T) {
	s := NewSigner("example.com.", SignerConfig{NSEC3Enabled: true, NSEC3Algorithm: 1})
	records := rr045Records(t)
	chain := s.generateNSEC3(records)

	t.Run("existing owners keep their NSEC3", func(t *testing.T) {
		for _, name := range []string{"example.com.", "ns1.example.com.", "a.b.example.com."} {
			hash, err := NSEC3Hash(name, 1, 0, nil)
			if err != nil {
				t.Fatalf("NSEC3Hash(%s): %v", name, err)
			}
			want := strings.ToLower(protocol.Base32Encode(hash))
			found := false
			for _, rr := range chain {
				if rr045OwnerHash(t, rr) == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no NSEC3 for %s after the change", name)
			}
		}
	})

	t.Run("chain is still a closed ring in hash order", func(t *testing.T) {
		// owner hash -> next hash, then follow the ring: it must visit every
		// record exactly once and return to the start.
		next := make(map[string]string, len(chain))
		for _, rr := range chain {
			n3, ok := rr.Data.(*protocol.RDataNSEC3)
			if !ok || n3 == nil {
				t.Fatalf("NSEC3 record carries %T", rr.Data)
			}
			next[rr045OwnerHash(t, rr)] = strings.ToLower(protocol.Base32Encode(n3.NextHashed))
		}
		if len(next) != len(chain) {
			t.Fatalf("owner hashes are not unique: %d records, %d distinct owners", len(chain), len(next))
		}
		start := ""
		for owner := range next {
			if start == "" || owner < start {
				start = owner
			}
		}
		seen := map[string]bool{}
		cur := start
		for i := 0; i < len(next); i++ {
			if seen[cur] {
				t.Fatalf("the chain revisits %s after %d steps: next-hash pointers are not a ring", cur, i)
			}
			seen[cur] = true
			cur = next[cur]
		}
		if cur != start {
			t.Fatalf("the ring closes on %s instead of its start %s", cur, start)
		}
	})

	t.Run("zone without empty non-terminals is unchanged", func(t *testing.T) {
		mk := func(name string, rrtype uint16, text string) *protocol.ResourceRecord {
			rr, err := protocol.NewResourceRecord(name, rrtype, protocol.ClassIN, 300,
				protocol.ParseRDataText(protocol.TypeString(rrtype), text))
			if err != nil {
				t.Fatalf("NewResourceRecord(%s): %v", name, err)
			}
			return rr
		}
		flat := []*protocol.ResourceRecord{
			mk("example.com.", protocol.TypeSOA, "ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"),
			mk("example.com.", protocol.TypeNS, "ns1.example.com."),
			mk("ns1.example.com.", protocol.TypeA, "192.0.2.53"),
			mk("www.example.com.", protocol.TypeA, "192.0.2.1"),
		}
		got := len(s.generateNSEC3(flat))
		if got != 3 {
			t.Errorf("chain length = %d, want 3 (apex, ns1, www and nothing else): the "+
				"empty-non-terminal expansion must not invent names", got)
		}
	})
}
