package zone

import "testing"

func cacheTagTestZone(addr string, line int) *Zone {
	z := NewZone("example.com.")
	z.DefaultTTL = 300
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: addr, Line: line},
	}
	return z
}

func TestInheritCacheTag_SameContent(t *testing.T) {
	old := cacheTagTestZone("192.0.2.1", 3)
	old.Lock() // advance the generation, as an edit would
	old.DefaultTTL = 300
	old.Unlock()
	oldID, oldGen := old.CacheTag()

	z := cacheTagTestZone("192.0.2.1", 7) // same data, different source line
	if !z.InheritCacheTag(old) {
		t.Fatal("identical content was not recognised")
	}
	if id, gen := z.CacheTag(); id != oldID || gen != oldGen {
		t.Errorf("tag = %d/%d, want inherited %d/%d", id, gen, oldID, oldGen)
	}
	if id, _ := old.CacheTag(); id == oldID {
		t.Error("retired zone kept the tag it handed over")
	}
}

func TestInheritCacheTag_ChangedContent(t *testing.T) {
	old := cacheTagTestZone("192.0.2.1", 3)
	oldID, _ := old.CacheTag()

	z := cacheTagTestZone("192.0.2.2", 3)
	if z.InheritCacheTag(old) {
		t.Fatal("changed content inherited the cache tag")
	}
	if id, _ := z.CacheTag(); id == oldID {
		t.Error("changed zone shares the old zone's tag")
	}
	if id, _ := old.CacheTag(); id != oldID {
		t.Error("old zone's tag changed although nothing was inherited")
	}
}

func TestInheritCacheTag_NilOrUnusedOld(t *testing.T) {
	z := cacheTagTestZone("192.0.2.1", 3)
	if z.InheritCacheTag(nil) {
		t.Error("inherited from nil")
	}
	if z.InheritCacheTag(cacheTagTestZone("192.0.2.1", 3)) {
		t.Error("inherited from a zone that never handed out a tag")
	}
}
