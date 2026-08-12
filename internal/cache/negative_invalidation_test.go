package cache

import (
	"strings"
	"testing"
)

// longInvalidationName builds a name past maxKeyNameLen (128), so MakeKey
// substitutes a keyed hash and the key alone can no longer yield the domain.
func longInvalidationName() string {
	return strings.Repeat("a", 200) + ".example.com"
}

// assertKeyHidesName pins the precondition every test below depends on: the
// key genuinely cannot be parsed back into the domain. Without this, a change
// to maxKeyNameLen would make these tests pass for the wrong reason.
func assertKeyHidesName(t *testing.T, key, name string) {
	t.Helper()
	if got, _ := ExtractQueryInfo(key); got == name {
		t.Fatalf("precondition failed: key %q still yields the name; "+
			"maxKeyNameLen may have changed and this test no longer covers the hashed branch", key)
	}
}

func newInvalidationCache() *Cache {
	cfg := DefaultConfig()
	cfg.Capacity = 128
	return New(cfg)
}

// TestInvalidatePattern_LongNamedNegativeEntry is the regression test for the
// residual gap documented at entryDomain: a negative entry whose name is too
// long to survive in the key used to be invisible to InvalidatePattern and
// lingered until its negative TTL expired.
func TestInvalidatePattern_LongNamedNegativeEntry(t *testing.T) {
	c := newInvalidationCache()

	name := longInvalidationName()
	key := MakeKey(name, 1, false)
	assertKeyHidesName(t, key, name)

	c.SetNegativeNamed(key, name, 3)
	if c.Get(key) == nil {
		t.Fatal("negative entry was not stored")
	}

	invalidated := c.InvalidatePattern("example.com")
	if len(invalidated) != 1 || invalidated[0] != key {
		t.Fatalf("expected the long-named negative entry to be invalidated, got %v", invalidated)
	}
	if c.Get(key) != nil {
		t.Fatal("entry still present after InvalidatePattern")
	}
}

// TestInvalidatePattern_LongNamedNegativeEntryWithTTL covers the SOA-derived
// TTL variant, which reaches the cache through a different setter.
func TestInvalidatePattern_LongNamedNegativeEntryWithTTL(t *testing.T) {
	c := newInvalidationCache()

	name := longInvalidationName()
	key := MakeKey(name, 28, true)
	assertKeyHidesName(t, key, name)

	c.SetNegativeWithTTLNamed(key, name, 3, 60)
	if c.Get(key) == nil {
		t.Fatal("negative entry was not stored")
	}

	if invalidated := c.InvalidatePattern("example.com"); len(invalidated) != 1 {
		t.Fatalf("expected 1 invalidation, got %v", invalidated)
	}
	if c.Get(key) != nil {
		t.Fatal("entry still present after InvalidatePattern")
	}
}

// TestInvalidatePattern_ResolverStyleKeyNegativeEntry covers the second half of
// the gap. The resolver keys negatives as "name:qtype", which the pipe-based
// ExtractQueryInfo cannot parse at all, so these entries were unreachable by
// pattern invalidation at *any* name length, not just past the hash threshold.
func TestInvalidatePattern_ResolverStyleKeyNegativeEntry(t *testing.T) {
	c := newInvalidationCache()

	// Deliberately short: proves the resolver-key half of the bug is
	// independent of the hashing threshold.
	name := "short.example.com"
	key := name + ":1"
	if got, _ := ExtractQueryInfo(key); got == name {
		t.Fatalf("precondition failed: ExtractQueryInfo unexpectedly parsed resolver key %q", key)
	}

	c.SetNegativeNamed(key, name, 3)

	if invalidated := c.InvalidatePattern("example.com"); len(invalidated) != 1 {
		t.Fatalf("expected resolver-keyed negative entry to be invalidated, got %v", invalidated)
	}
	if c.Get(key) != nil {
		t.Fatal("entry still present after InvalidatePattern")
	}
}

// TestInvalidatePattern_NamedNegativeIsCaseInsensitive guards the retained name
// against a case-sensitivity regression: the name is stored verbatim, so
// matching must fold case rather than relying on the caller to normalize.
func TestInvalidatePattern_NamedNegativeIsCaseInsensitive(t *testing.T) {
	c := newInvalidationCache()

	name := strings.Repeat("a", 200) + ".EXAMPLE.CoM"
	key := MakeKey(name, 1, false)
	assertKeyHidesName(t, key, name)

	c.SetNegativeNamed(key, name, 3)

	if invalidated := c.InvalidatePattern("example.com"); len(invalidated) != 1 {
		t.Fatalf("expected case-insensitive match on retained name, got %v", invalidated)
	}
}

// TestInvalidatePattern_NamedNegativeDoesNotOverMatch ensures closing the gap
// did not turn InvalidatePattern into a substring match. "badexample.com" must
// survive an "example.com" invalidation.
func TestInvalidatePattern_NamedNegativeDoesNotOverMatch(t *testing.T) {
	c := newInvalidationCache()

	victim := strings.Repeat("a", 200) + ".badexample.com"
	victimKey := MakeKey(victim, 1, false)
	assertKeyHidesName(t, victimKey, victim)
	c.SetNegativeNamed(victimKey, victim, 3)

	target := longInvalidationName()
	targetKey := MakeKey(target, 1, false)
	c.SetNegativeNamed(targetKey, target, 3)

	invalidated := c.InvalidatePattern("example.com")
	if len(invalidated) != 1 || invalidated[0] != targetKey {
		t.Fatalf("expected only the example.com entry to be invalidated, got %v", invalidated)
	}
	if c.Get(victimKey) == nil {
		t.Fatal("badexample.com entry was wrongly invalidated")
	}
}

// TestInvalidatePattern_UnnamedLongNegativeStillSkipped pins the limitation
// that remains by design. Plain SetNegative takes no name, so a long-named
// entry stored through it still cannot be resolved back to a domain and is
// skipped by pattern invalidation; it expires on its negative TTL instead.
//
// This is the honest boundary of the fix, asserted rather than left implicit:
// if a future change makes the unnamed path recoverable, this test fails and
// the entryDomain documentation must be updated to match.
func TestInvalidatePattern_UnnamedLongNegativeStillSkipped(t *testing.T) {
	c := newInvalidationCache()

	name := longInvalidationName()
	key := MakeKey(name, 1, false)
	assertKeyHidesName(t, key, name)

	c.SetNegative(key, 3)

	if invalidated := c.InvalidatePattern("example.com"); len(invalidated) != 0 {
		t.Fatalf("unnamed long negative unexpectedly invalidated (%v); "+
			"if this is now supported, update the entryDomain documentation", invalidated)
	}
	if c.Get(key) == nil {
		t.Fatal("entry should still be present, expiring on its negative TTL")
	}
}

// TestEntryDomain_PrefersRetainedNameOverKey checks the precedence order
// entryDomain documents: an explicitly supplied name outranks the key, which
// matters when the two disagree.
func TestEntryDomain_PrefersRetainedNameOverKey(t *testing.T) {
	entry := &Entry{Key: "other.com|1|0", QName: "real.example.com"}
	if got := entryDomain(entry.Key, entry); got != "real.example.com" {
		t.Fatalf("expected retained name to win, got %q", got)
	}

	// With no retained name, the key remains the fallback.
	bare := &Entry{Key: "other.com|1|0"}
	if got := entryDomain(bare.Key, bare); got != "other.com" {
		t.Fatalf("expected key fallback, got %q", got)
	}
}

// TestSetNegativeNamed_RetainsNameThroughStaleCopy guards the stale-entry copy
// path in getStale, which rebuilds an Entry field by field and would silently
// drop QName if a new field were forgotten there.
func TestSetNegativeNamed_RetainsNameThroughStaleCopy(t *testing.T) {
	c := newInvalidationCache()

	name := longInvalidationName()
	key := MakeKey(name, 1, false)
	c.SetNegativeNamed(key, name, 3)

	entry := c.Get(key)
	if entry == nil {
		t.Fatal("negative entry was not stored")
	}
	if entry.QName != name {
		t.Fatalf("QName not retained: got %q, want %q", entry.QName, name)
	}
}
