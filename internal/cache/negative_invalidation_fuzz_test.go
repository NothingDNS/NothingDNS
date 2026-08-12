package cache

// Fuzz target for the named-negative invalidation path: SetNegativeNamed ->
// entryDomain -> InvalidatePattern.
//
// This is a different surface from the MakeKey/ExtractQueryInfo targets in
// makekey_fuzz_test.go. Those exercise the key codec as a pure function and
// never construct a Cache, so they cannot reach the QName field or
// entryDomain at all. The bug class here is the one fixed in 559ab7e:
//
//   - MakeKey replaces names over maxKeyNameLen with a keyed hash, and the
//     resolver keys negatives as "name:qtype", so neither key can be parsed
//     back into a domain. Negative entries carry no Message either, so
//     entryDomain had no working source and InvalidatePattern silently
//     skipped them.
//
// The retained QName closes that. The invariants below assert both halves of
// the contract: that a retained name is always what entryDomain resolves
// (regardless of key encoding), and that the resulting match is exact — a
// sibling like badexample.com must never be caught by pattern example.com.

import (
	"strings"
	"testing"
)

// normalizeDomainForOracle mirrors the domain-side normalization performed
// inside invalidationPatternMatches: trim surrounding whitespace, lowercase,
// then remove a single trailing dot. Order matters and is copied deliberately
// (TrimSpace runs before the dot trim, so "host.com ." normalizes to
// "host.com " with the space retained).
func normalizeDomainForOracle(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// labelSuffixMatch is an independent formulation of the matching rule, stated
// over DNS labels rather than raw byte suffixes. Production asks
// `domain == pattern || strings.HasSuffix(domain, "."+pattern)`; this asks
// whether the domain's trailing labels equal the pattern's labels. The two are
// equivalent, but expressing it structurally is what gives the target teeth:
// a regression to a plain strings.HasSuffix (the classic way sibling
// over-matching is reintroduced) diverges from this oracle immediately, where
// a copy of the production expression would silently agree with the bug.
func labelSuffixMatch(domain, pattern string) bool {
	if pattern == "" {
		return false
	}
	d := strings.Split(domain, ".")
	p := strings.Split(pattern, ".")
	if len(d) < len(p) {
		return false
	}
	off := len(d) - len(p)
	for i := range p {
		if d[off+i] != p[i] {
			return false
		}
	}
	return true
}

func containsInvalidatedKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// FuzzNamedNegativeInvalidation drives SetNegativeNamed and InvalidatePattern
// with random names, patterns, qtypes and DO bits.
func FuzzNamedNegativeInvalidation(f *testing.F) {
	seeds := []struct {
		name    string
		pattern string
		qtype   uint16
		doBit   bool
	}{
		// Exact match, subdomain match, and the sibling that must not match.
		{"example.com", "example.com", 1, false},
		{"www.example.com", "example.com", 1, true},
		{"badexample.com", "example.com", 1, false},
		{"a.com", "b.com", 1, false},

		// Around the 128-byte hashing threshold: the key stops carrying the
		// name here, so QName becomes the only viable source for entryDomain.
		{strings.Repeat("a", keyHashThreshold-1) + ".example.com", "example.com", 28, false},
		{strings.Repeat("a", keyHashThreshold+1) + ".example.com", "example.com", 1, false},
		{strings.Repeat("a", 200) + ".example.com", "example.com", 1, true},

		// The 255/256/257 region that overflowed the old fixed-size buffer.
		{strings.Repeat("a", 255), strings.Repeat("a", 255), 1, false},
		{strings.Repeat("a", 256), strings.Repeat("a", 256), 1, true},
		{strings.Repeat("a", 257), strings.Repeat("a", 257), 15, false},

		// Normalization corners: case, trailing dot, padding, empty pattern.
		{"Mixed.Case.COM", "mixed.case.com", 1, false},
		{"trailing.dot.com.", "trailing.dot.com", 1, false},
		{"example.com", "  example.com  ", 1, false},
		{"example.com", "EXAMPLE.COM.", 1, false},
		{"example.com", "", 1, false},

		// Names that defeat the key codec but not the retained name.
		{"pipe|name.example.com", "example.com", 1, false},
		{"\x00\xff\x80.example.com", "example.com", 1, false},
	}
	for _, s := range seeds {
		f.Add(s.name, s.pattern, s.qtype, s.doBit)
	}

	f.Fuzz(func(t *testing.T, name, pattern string, qtype uint16, doBit bool) {
		// The retained-name contract only applies when a name was supplied.
		// With an empty name entryDomain deliberately falls back to the key,
		// which is the unnamed-SetNegative path covered elsewhere.
		if name == "" {
			t.Skip()
		}

		c := newInvalidationCache()
		key := MakeKey(name, qtype, doBit)
		c.SetNegativeNamed(key, name, 3)

		entry := c.Get(key)
		if entry == nil {
			t.Fatalf("negative entry not stored for %d-byte name", len(name))
		}

		// Invariant 1: the name is retained verbatim, not normalized on the
		// way in. Normalization is the matcher's job; folding it into storage
		// would silently change what callers read back off the entry.
		if entry.QName != name {
			t.Fatalf("QName not retained: got %q, want %q", entry.QName, name)
		}

		// Invariant 2: entryDomain resolves the retained name whatever the key
		// encoding is. This is the assertion the whole fix exists for.
		if got := entryDomain(key, entry); got != name {
			t.Fatalf("entryDomain = %q, want retained name %q", got, name)
		}

		// Invariant 3: above the threshold the key genuinely cannot yield the
		// name, so invariant 2 above was carried by QName rather than passing
		// for the wrong reason.
		if len(name) > keyHashThreshold {
			if got, _ := ExtractQueryInfo(key); got == name {
				t.Fatalf("precondition drift: hashed key %q still yields the name", key)
			}
		}

		np := normalizeInvalidatePattern(pattern)
		want := labelSuffixMatch(normalizeDomainForOracle(name), np)

		invalidated := c.InvalidatePattern(pattern)
		got := containsInvalidatedKey(invalidated, key)

		// Invariant 4: invalidation agrees with the label-wise oracle. An
		// under-match here is the original bug (entry unreachable); an
		// over-match is the sibling-domain bug.
		if got != want {
			t.Fatalf("invalidation mismatch: name=%q pattern=%q got=%v want=%v (domain=%q normPattern=%q)",
				name, pattern, got, want, normalizeDomainForOracle(name), np)
		}

		// Invariant 5: the reported key list and the cache's actual contents
		// agree. Reporting a key without removing it (or vice versa) would
		// make invalidation lie to its callers.
		switch alive := c.Get(key) != nil; {
		case want && alive:
			t.Fatalf("pattern %q reported %q invalidated but entry survived", pattern, key)
		case !want && !alive:
			t.Fatalf("pattern %q removed non-matching entry %q", pattern, key)
		}

		// Invariant 6 (over-match): a sibling formed by prefixing the pattern
		// must never be caught. For pattern "example.com" this is exactly
		// "badexample.com". Proof it can never legitimately match: the
		// normalized sibling domain is "bad"+P for normalized pattern P, so it
		// is longer than P (never equal) and the byte preceding the trailing P
		// is 'd', never '.', so the "."+P suffix rule cannot fire either.
		// A fresh cache keeps this independent of the assertions above.
		if np != "" {
			sc := newInvalidationCache()
			sibling := "bad" + np
			skey := MakeKey(sibling, qtype, doBit)
			sc.SetNegativeNamed(skey, sibling, 3)

			if sc.Get(skey) == nil {
				t.Fatalf("sibling entry not stored for %q", sibling)
			}
			if inv := sc.InvalidatePattern(pattern); containsInvalidatedKey(inv, skey) {
				t.Fatalf("over-match: sibling %q reported invalidated by pattern %q", sibling, pattern)
			}
			if sc.Get(skey) == nil {
				t.Fatalf("over-match: sibling %q was removed by pattern %q", sibling, pattern)
			}
		}
	})
}
