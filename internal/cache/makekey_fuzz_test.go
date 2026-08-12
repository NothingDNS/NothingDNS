package cache

// Fuzz targets for the cache-key codec: MakeKey and its inverse
// ExtractQueryInfo.
//
// MakeKey switches representation at a length threshold (names longer than
// maxKeyNameLen are replaced by a keyed hash), and that conditional branch is
// where both historical bugs in this codec lived:
//
//   - a fixed `var lower [256]byte` in the hashing branch, indexed by
//     len(name), panicked with "index out of range [256]" for 257+ byte names;
//   - because the hashed key no longer contains the domain, ExtractQueryInfo
//     could not recover it and InvalidatePattern silently skipped those entries.
//
// These targets therefore concentrate seeds on the 128-byte threshold and the
// 255/256/257-byte region, and assert the invariants each branch must uphold.

import (
	"strconv"
	"strings"
	"testing"
)

// foldAZLower mirrors the exact case-folding MakeKey performs: only A-Z are
// folded (via c |= 0x20); every other byte passes through untouched. It is
// deliberately not strings.ToLower, which also folds non-ASCII and would
// therefore mask a divergence rather than detect one.
func foldAZLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] |= 0x20
		}
	}
	return string(b)
}

// foldAZUpper is the inverse fold, used to prove case-insensitivity from the
// other direction.
func foldAZUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] &^= 0x20
		}
	}
	return string(b)
}

func allDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// keyHashThreshold mirrors maxKeyNameLen, which MakeKey declares as a
// function-local const and so cannot be referenced from tests.
// TestKeyHashThresholdInSync detects drift.
const keyHashThreshold = 128

// splitKeyName strips the trailing "|<qtype>|<dobit>" suffix MakeKey always
// appends and returns the leading name portion. Trimming from the right stays
// correct even when the name itself contains '|'.
func splitKeyName(t *testing.T, key string, qtype uint16, doBit bool) string {
	t.Helper()
	doDigit := "0"
	if doBit {
		doDigit = "1"
	}
	suffix := "|" + strconv.FormatUint(uint64(qtype), 10) + "|" + doDigit
	if !strings.HasSuffix(key, suffix) {
		t.Fatalf("key %q does not end with expected suffix %q", key, suffix)
	}
	return key[:len(key)-len(suffix)]
}

// TestKeyHashThresholdInSync pins the threshold the fuzz targets branch on. If
// maxKeyNameLen moves, this fails loudly instead of letting the fuzz targets
// silently assert against the wrong branch.
func TestKeyHashThresholdInSync(t *testing.T) {
	at := strings.Repeat("a", keyHashThreshold)
	over := strings.Repeat("a", keyHashThreshold+1)

	if got := splitKeyName(t, MakeKey(at, 1, false), 1, false); got != at {
		t.Fatalf("threshold drift: %d-byte name was hashed, expected literal", len(at))
	}
	if got := splitKeyName(t, MakeKey(over, 1, false), 1, false); !allDecimalDigits(got) {
		t.Fatalf("threshold drift: %d-byte name was literal, expected hash", len(over))
	}
}

// FuzzMakeKey exercises MakeKey across both representation branches, with seeds
// clustered on the 128-byte hashing threshold and the 255/256/257-byte region.
func FuzzMakeKey(f *testing.F) {
	for _, n := range []int{0, 1, 127, 128, 129, 254, 255, 256, 257, 300, 512, 2048} {
		f.Add(strings.Repeat("a", n), uint16(1), false)
		f.Add(strings.Repeat("a", n), uint16(28), true)
	}
	f.Add("example.com", uint16(1), false)
	f.Add("EXAMPLE.COM", uint16(1), false)
	f.Add(strings.Repeat("sub.", 70)+"example.com", uint16(15), true) // 291 bytes
	f.Add(strings.Repeat("LabelWithCaps.", 20), uint16(255), false)
	f.Add("name|with|pipes.com", uint16(1), false)
	f.Add("\x00\xff\x80.com", uint16(1), false)

	f.Fuzz(func(t *testing.T, name string, qtype uint16, doBit bool) {
		// Deliberately unbounded: MakeKey must not panic at ANY length, and
		// the [256]byte overflow this guards against only appeared above 256
		// bytes. Capping the input here would have excluded the exact region
		// the regression lives in.
		//
		// Note for anyone watching a run: `go test -fuzz` reports "0/sec" for
		// long stretches once it enters minimization (the exec counter does
		// not advance during that phase, and -fuzzminimizetime defaults to
		// 60s). That is normal engine behaviour, not a hang in this target —
		// verified with -fuzzminimizetime 0, which runs without any pause.

		// Invariant 1: MakeKey never panics, at any name length. This is the
		// direct regression guard for the [256]byte overflow.
		key := MakeKey(name, qtype, doBit)

		// Invariant 2: the key always carries the "|<qtype>|<dobit>" suffix.
		namePart := splitKeyName(t, key, qtype, doBit)

		// Invariant 3: determinism within a process.
		if again := MakeKey(name, qtype, doBit); again != key {
			t.Fatalf("MakeKey not deterministic: %q vs %q", key, again)
		}

		// Invariant 4: case-insensitivity (RFC 1035 §2.3.3), from both
		// directions, so mixed-case duplicates cannot inflate the working set.
		if lower := MakeKey(foldAZLower(name), qtype, doBit); lower != key {
			t.Fatalf("case fold mismatch for %q: lower gave %q, want %q", name, lower, key)
		}
		if upper := MakeKey(foldAZUpper(name), qtype, doBit); upper != key {
			t.Fatalf("case fold mismatch for %q: upper gave %q, want %q", name, upper, key)
		}

		// Invariant 5: the DO bit partitions the keyspace (VULN-060) so a
		// DNSSEC and a plain response can never share one entry.
		if other := MakeKey(name, qtype, !doBit); other == key {
			t.Fatalf("DO bit did not change key for %q", name)
		}

		// Invariant 6: qtype partitions the keyspace.
		if other := MakeKey(name, qtype+1, doBit); other == key {
			t.Fatalf("qtype did not change key for %q", name)
		}

		if len(name) > keyHashThreshold {
			// Invariant 7: long names are represented by decimal hash digits.
			if !allDecimalDigits(namePart) {
				t.Fatalf("%d-byte name not hashed: name part %q", len(name), namePart)
			}
			// Invariant 8 (security): hashing exists to bound cache-key growth
			// against a flood of long unique names, so key size must not track
			// input size. A regression that re-embedded the name trips this.
			if len(key) > 64 {
				t.Fatalf("hashed key unbounded: len(key)=%d for %d-byte name", len(key), len(name))
			}
		} else {
			// Invariant 9: short names are embedded literally, case-folded.
			if want := foldAZLower(name); namePart != want {
				t.Fatalf("short name not embedded verbatim: got %q, want %q", namePart, want)
			}
		}
	})
}

// FuzzMakeKeyExtractRoundTrip asserts that ExtractQueryInfo inverts MakeKey on
// the short-name branch, and never panics on the hashed branch.
func FuzzMakeKeyExtractRoundTrip(f *testing.F) {
	for _, n := range []int{0, 1, 127, 128, 129, 255, 256, 257, 400} {
		f.Add(strings.Repeat("a", n), uint16(1), false)
	}
	f.Add("example.com", uint16(28), true)
	f.Add("Mixed.Case.COM", uint16(15), false)
	f.Add("pipe|name.com", uint16(1), false)

	f.Fuzz(func(t *testing.T, name string, qtype uint16, doBit bool) {
		key := MakeKey(name, qtype, doBit)
		namePart := splitKeyName(t, key, qtype, doBit)

		// Invariant 1: ExtractQueryInfo never panics on MakeKey output.
		gotName, gotType := ExtractQueryInfo(key)

		// ExtractQueryInfo splits on the FIRST '|', so a name containing '|'
		// is not round-trippable by construction. That asymmetry is asserted
		// explicitly in TestExtractQueryInfo_NameContainingPipe rather than
		// silently tolerated here.
		if strings.Contains(namePart, "|") {
			return
		}

		// Invariant 2: qtype always survives the round trip.
		if gotType != qtype {
			t.Fatalf("qtype round-trip failed for %q: got %d, want %d", name, gotType, qtype)
		}

		// Invariant 3: the recovered name equals the key's name portion. For
		// short names that is the case-folded original; for long names it is
		// the hash, which is the documented lossy behaviour that entryDomain()
		// compensates for using the cached message.
		if gotName != namePart {
			t.Fatalf("name round-trip failed: got %q, want %q", gotName, namePart)
		}
	})
}

// FuzzExtractQueryInfo feeds arbitrary strings — not only well-formed MakeKey
// output — because ExtractQueryInfo is reached from entryDomain() with whatever
// keys exist in the cache, including keys restored from persisted snapshots.
func FuzzExtractQueryInfo(f *testing.F) {
	f.Add("example.com|1|0")
	f.Add("example.com|1")
	f.Add("example.com")
	f.Add("")
	f.Add("|")
	f.Add("||")
	f.Add("|1|0")
	f.Add("a|abc|0")
	f.Add("a|99999999999999999999|0")
	f.Add("a|-1|0")
	f.Add("a|+1|0")
	f.Add("a|1abc|0")
	f.Add(strings.Repeat("a", 300) + "|1|0")

	f.Fuzz(func(t *testing.T, key string) {
		// Invariant 1: never panics on arbitrary input.
		name, qtype := ExtractQueryInfo(key)

		// Invariant 2: a key with no separator cannot yield any result.
		if !strings.Contains(key, "|") {
			if name != "" || qtype != 0 {
				t.Fatalf("separator-less key %q yielded (%q, %d)", key, name, qtype)
			}
			return
		}

		// Invariant 3: any returned name is a literal prefix of the key, and
		// never contains the field separator. This forbids fabricating or
		// rewriting a domain that was not present in the key — the property
		// InvalidatePattern depends on to avoid evicting unrelated entries.
		if name != "" {
			if !strings.HasPrefix(key, name) {
				t.Fatalf("returned name %q is not a prefix of key %q", name, key)
			}
			if strings.Contains(name, "|") {
				t.Fatalf("returned name %q contains the field separator", name)
			}
		}
	})
}

// TestExtractQueryInfo_NameContainingPipe documents the one asymmetry in the
// codec: MakeKey embeds short names verbatim, but ExtractQueryInfo splits on
// the first '|', so a name containing '|' does not round-trip.
//
// MakeKey's comment justifies '|' on the grounds that DNS names cannot contain
// it on the wire or in zone files. That holds for wire-parsed names, but
// MakeKey is also reached with names that never passed wire validation — the
// same assumption that produced the [256]byte overflow. The consequence here is
// bounded and non-corrupting: a '|'-bearing name yields a truncated domain (or
// a parse failure), so InvalidatePattern may fail to match such an entry. It
// cannot cause a mismatched eviction, because the truncated value is always a
// literal prefix of the real name.
func TestExtractQueryInfo_NameContainingPipe(t *testing.T) {
	key := MakeKey("evil|name.com", 1, false)

	name, qtype := ExtractQueryInfo(key)

	// The qtype parse fails because the text after the first '|' is
	// "name.com", not a number, so the documented ("", 0) failure is returned.
	if name != "" || qtype != 0 {
		t.Fatalf("expected ('', 0) for pipe-bearing name, got (%q, %d)", name, qtype)
	}

	// Crucially, the entry is still addressable: MakeKey remains deterministic,
	// so Get/Set on the same name continue to work. Only pattern invalidation
	// is degraded for such names.
	if again := MakeKey("evil|name.com", 1, false); again != key {
		t.Fatalf("MakeKey not deterministic for pipe-bearing name")
	}
}
