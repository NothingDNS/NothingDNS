package cache

import (
	"sort"
	"testing"
	"time"
)

// InvalidateName removes the entries of exactly one name (every type, DNSSEC
// or not), reports the keys it removed, and tells the cluster callback about
// each one. Other names, including its subdomains, stay.
func TestInvalidateNameRemovesOnlyThatName(t *testing.T) {
	c := New(Config{Capacity: 100, MinTTL: time.Second, MaxTTL: time.Hour, DefaultTTL: 5 * time.Minute, NegativeTTL: 5 * time.Minute})
	set := func(name string, qtype uint16, do bool) string {
		key := MakeKey(name, qtype, do)
		c.SetNegativeWithTTL(key, 3, 300)
		return key
	}
	target := []string{
		set("a.example.", 1, false), set("a.example.", 28, false), set("a.example.", 1, true),
	}
	keep := []string{
		set("b.example.", 1, false), set("sub.a.example.", 1, false), set("xa.example.", 1, false),
	}

	if got := c.Size(); got != len(target)+len(keep) {
		t.Fatalf("setup: %d entries cached, want %d", got, len(target)+len(keep))
	}

	var notified []string
	c.SetInvalidateFunc(func(key string) { notified = append(notified, key) })

	removed := c.InvalidateName("A.Example") // case and trailing dot do not matter
	sort.Strings(removed)
	sort.Strings(target)
	if len(removed) != len(target) {
		t.Fatalf("removed %v, want %v", removed, target)
	}
	for i := range target {
		if removed[i] != target[i] {
			t.Fatalf("removed %v, want %v", removed, target)
		}
	}
	for _, k := range target {
		if c.Get(k) != nil {
			t.Errorf("%s is still cached", k)
		}
	}
	for _, k := range keep {
		if c.Get(k) == nil {
			t.Errorf("%s was removed", k)
		}
	}
	if len(notified) != len(target) {
		t.Errorf("cluster callback saw %d keys, want %d", len(notified), len(target))
	}
	if got := c.InvalidateName(""); got != nil {
		t.Errorf("empty name removed %v", got)
	}
}
