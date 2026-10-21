package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
)

// POST /api/v1/cache/flush?name=<name> flushes that name only; without name it
// still clears the whole cache. dnsctl's `cache flush <name>` relied on this,
// but the handler ignored the parameter and emptied everything.
func TestHandleCacheFlushByName(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *cache.Cache, string, map[string]string) {
		t.Helper()
		c := cache.New(cache.Config{Capacity: 100, MinTTL: time.Second, MaxTTL: time.Hour, DefaultTTL: 5 * time.Minute, NegativeTTL: 5 * time.Minute})
		keys := map[string]string{}
		for _, name := range []string{"a.example.", "b.example."} {
			k := cache.MakeKey(name, 1, false)
			c.SetNegativeWithTTL(k, 3, 300)
			keys[name] = k
		}
		if c.Size() != len(keys) {
			t.Fatalf("setup: %d entries cached, want %d", c.Size(), len(keys))
		}
		s := NewServer(config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}, nil, c, nil, nil, nil, nil)
		return s, c, attachTestAuth(s), keys
	}
	post := func(s *Server, token, target string) (int, string) {
		rec := httptest.NewRecorder()
		s.handleCacheFlush(rec, withTestAdminAuth(httptest.NewRequest(http.MethodPost, target, nil), token))
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		msg, _ := body["message"].(string)
		return rec.Code, msg
	}

	t.Run("name flushes only that name", func(t *testing.T) {
		s, c, token, keys := newServer(t)
		code, msg := post(s, token, "/api/v1/cache/flush?name=a.example")
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if c.Get(keys["a.example."]) != nil {
			t.Error("a.example. is still cached")
		}
		if c.Get(keys["b.example."]) == nil {
			t.Errorf("FAIL: flushing a.example. also removed b.example. (message %q)", msg)
		}
	})

	t.Run("without a name the whole cache is cleared", func(t *testing.T) {
		s, c, token, keys := newServer(t)
		if code, msg := post(s, token, "/api/v1/cache/flush"); code != http.StatusOK || msg != "Cache flushed" {
			t.Fatalf("status %d message %q", code, msg)
		}
		for name, k := range keys {
			if c.Get(k) != nil {
				t.Errorf("%s survived a full flush", name)
			}
		}
	})
}
