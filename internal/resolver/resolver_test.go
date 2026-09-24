package resolver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// --- Mock Transport ---

type mockTransport struct {
	mu      sync.Mutex
	handler map[string]func(msg *protocol.Message) *protocol.Message // addr -> handler
	calls   []string
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		handler: make(map[string]func(msg *protocol.Message) *protocol.Message),
	}
}

func (m *mockTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	m.mu.Lock()
	fn, ok := m.handler[addr]
	m.mu.Unlock()

	m.mu.Lock()
	m.calls = append(m.calls, addr)
	m.mu.Unlock()

	if !ok {
		// Default: SERVFAIL
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    msg.Header.ID,
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeServerFailure},
			},
			Questions: msg.Questions,
		}
		return resp, nil
	}

	// Run handler in a goroutine so we can respect context cancellation
	type result struct {
		resp *protocol.Message
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ch <- result{resp: fn(msg)}
	}()

	select {
	case r := <-ch:
		return r.resp, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *mockTransport) setHandler(addr string, fn func(msg *protocol.Message) *protocol.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handler[addr] = fn
}

func (m *mockTransport) getCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

// setAllRootHandlers registers the same handler for all root server addresses.
func (m *mockTransport) setAllRootHandlers(fn func(msg *protocol.Message) *protocol.Message) {
	for _, h := range RootHints() {
		for _, ip := range h.IPv4 {
			m.setHandler(withPort(ip, "53"), fn)
		}
		for _, ip := range h.IPv6 {
			m.setHandler(withPort(ip, "53"), fn)
		}
	}
}

// --- Mock Cache ---

type mockCache struct {
	mu           sync.Mutex
	entries      map[string]*CacheEntry
	sets         []string
	negatives    []string
	negativeTTLs []uint32
}

func newMockCache() *mockCache {
	return &mockCache{
		entries: make(map[string]*CacheEntry),
	}
}

func (m *mockCache) Get(key string) *CacheEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries[key]
}

func (m *mockCache) Set(key string, msg *protocol.Message, ttl uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = &CacheEntry{Message: msg}
	m.sets = append(m.sets, key)
}

func (m *mockCache) SetNegative(key string, rcode uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = &CacheEntry{IsNegative: true, RCode: rcode}
	m.negatives = append(m.negatives, key)
}

func (m *mockCache) SetNegativeWithTTL(key string, rcode uint8, ttl uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = &CacheEntry{IsNegative: true, RCode: rcode}
	m.negatives = append(m.negatives, key)
	m.negativeTTLs = append(m.negativeTTLs, ttl)
}

func (m *mockCache) ApplyTTLPolicy(msg *protocol.Message, ttl uint32) uint32 {
	if msg == nil {
		return 0
	}
	// Minimal mock: no-op, caller-provided TTL is used as-is.
	// Tests that need clamping behavior should use the real cache.Cache.
	return ttl
}

// --- Helpers ---

func makeNSRR(name, nsName string) *protocol.ResourceRecord {
	nsNameObj, _ := protocol.ParseName(nsName)
	return &protocol.ResourceRecord{
		Name:  mustName(name),
		Type:  protocol.TypeNS,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataNS{NSDName: nsNameObj},
	}
}

func makeARR(name, ip string) *protocol.ResourceRecord {
	var addr [4]byte
	copy(addr[:], net.ParseIP(ip).To4())
	return &protocol.ResourceRecord{
		Name:  mustName(name),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: addr},
	}
}

func makeCNAMERR(name, target string) *protocol.ResourceRecord {
	targetObj, _ := protocol.ParseName(target)
	return &protocol.ResourceRecord{
		Name:  mustName(name),
		Type:  protocol.TypeCNAME,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataCNAME{CName: targetObj},
	}
}

func makeSOARR(name string) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{
		Name:  mustName(name),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   900,
		Data: &protocol.RDataSOA{
			MName:   mustName("a.root-servers.net."),
			RName:   mustName("nstld.verisign-grs.com."),
			Serial:  2024010101,
			Refresh: 1800,
			Retry:   900,
			Expire:  604800,
			Minimum: 86400,
		},
	}
}

func mustName(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// --- Tests ---

func TestRootHints(t *testing.T) {
	hints := RootHints()
	if len(hints) != 13 {
		t.Fatalf("Expected 13 root hints, got %d", len(hints))
	}

	for _, h := range hints {
		if h.Name == "" {
			t.Error("Root hint has empty name")
		}
		if len(h.IPv4) == 0 {
			t.Errorf("Root hint %s has no IPv4 address", h.Name)
		}
	}
}

func TestResolver_CacheHit(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Pre-populate cache
	cachedResp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RA: true, RCODE: protocol.RcodeSuccess},
		},
	}
	q, _ := protocol.NewQuestion("cached.example.com.", protocol.TypeA, protocol.ClassIN)
	cachedResp.AddQuestion(q)
	cachedResp.AddAnswer(makeARR("cached.example.com.", "1.2.3.4"))

	cache.Set("cached.example.com.:1", cachedResp, 300)

	r := NewResolver(DefaultConfig(), cache, transport)

	resp, err := r.Resolve(context.Background(), "cached.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.Answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
	}

	// Should not have called transport
	if len(transport.getCalls()) != 0 {
		t.Errorf("Expected no transport calls for cache hit, got %d", len(transport.getCalls()))
	}
}

func TestResolver_CacheNegativeHit(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Pre-populate with negative cache entry
	cache.SetNegative("nx.example.com.:1", protocol.RcodeNameError)

	r := NewResolver(DefaultConfig(), cache, transport)

	resp, err := r.Resolve(context.Background(), "nx.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got RCODE %d", resp.Header.Flags.RCODE)
	}

	if len(transport.getCalls()) != 0 {
		t.Errorf("Expected no transport calls for negative cache hit")
	}
}

func TestResolver_SingleReferral(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Root server returns referral to .com NS
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		}
		resp.Questions = msg.Questions
		resp.AddAuthority(makeNSRR("com.", "a.gtld-servers.net."))
		resp.AddAdditional(makeARR("a.gtld-servers.net.", "192.5.6.30"))
		return resp
	})

	// .com NS returns the answer
	comAddr := "192.5.6.30:53"
	transport.setHandler(comAddr, func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
		}
		resp.Questions = msg.Questions
		resp.AddAnswer(makeARR("example.com.", "93.184.216.34"))
		return resp
	})

	r := NewResolver(DefaultConfig(), cache, transport)

	resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}

	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatal("Expected A record")
	}

	ip := net.IP(a.Address[:]).String()
	if ip != "93.184.216.34" {
		t.Errorf("Expected 93.184.216.34, got %s", ip)
	}

	// Verify it queried the root then the .com server
	calls := transport.getCalls()
	if len(calls) < 2 {
		t.Errorf("Expected at least 2 transport calls, got %d", len(calls))
	}

	// Should be cached now
	if len(cache.sets) == 0 {
		t.Error("Expected response to be cached")
	}
}

func TestResolver_NXDomain(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeNameError}},
		}
		resp.Questions = msg.Questions
		// Add SOA in authority to indicate negative response
		resp.AddAuthority(makeSOARR("."))
		return resp
	})

	r := NewResolver(DefaultConfig(), cache, transport)
	resp, err := r.Resolve(context.Background(), "nonexistent.invalid.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got RCODE %d", resp.Header.Flags.RCODE)
	}

	// Should be negatively cached
	if len(cache.negatives) == 0 {
		t.Error("Expected negative cache entry")
	}
}

func TestResolver_NODATA(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAuthority(makeSOARR("example.com."))
		return resp
	})

	r := NewResolver(DefaultConfig(), cache, transport)
	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeAAAA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("Expected NOERROR/NODATA, got RCODE %d", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("Expected no answers for NODATA, got %d", len(resp.Answers))
	}
	if !resp.Header.Flags.RA {
		t.Fatal("Expected RA bit on recursive NODATA response")
	}
	if len(cache.negatives) != 1 {
		t.Fatalf("Expected one negative cache entry, got %d", len(cache.negatives))
	}
	if got, want := cache.negatives[0], "www.example.com.:28"; got != want {
		t.Fatalf("Negative cache key = %q, want %q", got, want)
	}
	if len(cache.negativeTTLs) != 1 {
		t.Fatalf("Expected one negative cache TTL, got %d", len(cache.negativeTTLs))
	}
	if got, want := cache.negativeTTLs[0], uint32(900); got != want {
		t.Fatalf("Negative cache TTL = %d, want %d", got, want)
	}
}

func TestResolver_CNAMEChasing(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Root refers to .com
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		}
		resp.Questions = msg.Questions
		resp.AddAuthority(makeNSRR("com.", "a.gtld-servers.net."))
		resp.AddAdditional(makeARR("a.gtld-servers.net.", "192.5.6.30"))
		return resp
	})

	comAddr := "192.5.6.30:53"
	transport.setHandler(comAddr, func(msg *protocol.Message) *protocol.Message {
		qname := ""
		if len(msg.Questions) > 0 {
			qname = msg.Questions[0].Name.String()
		}

		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
		}
		resp.Questions = msg.Questions

		switch qname {
		case "www.example.com.":
			// Return CNAME -> example.com
			resp.AddAnswer(makeCNAMERR("www.example.com.", "example.com."))
		case "example.com.":
			// Return A record
			resp.AddAnswer(makeARR("example.com.", "93.184.216.34"))
		}

		return resp
	})

	r := NewResolver(DefaultConfig(), cache, transport)

	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.Answers) < 1 {
		t.Fatalf("Expected at least 1 answer, got %d", len(resp.Answers))
	}

	// First answer should be CNAME, last should be A
	hasCNAME := false
	hasA := false
	for _, rr := range resp.Answers {
		switch rr.Type {
		case protocol.TypeCNAME:
			hasCNAME = true
		case protocol.TypeA:
			hasA = true
		}
	}

	if !hasCNAME {
		t.Error("Expected CNAME in answers")
	}
	if !hasA {
		t.Error("Expected A record in answers after CNAME chase")
	}
}

func TestResolver_MaxDepthExceeded(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Create infinite referral loop
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		}
		resp.Questions = msg.Questions
		// Always refer back to root
		resp.AddAuthority(makeNSRR("com.", "a.root-servers.net."))
		resp.AddAdditional(makeARR("a.root-servers.net.", "198.41.0.4"))
		return resp
	})

	cfg := DefaultConfig()
	cfg.MaxDepth = 5

	r := NewResolver(cfg, cache, transport)

	resp, err := r.Resolve(context.Background(), "loop.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve should not return error, got: %v", err)
	}

	// Should get SERVFAIL after max depth
	if resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("Expected SERVFAIL after max depth, got RCODE %d", resp.Header.Flags.RCODE)
	}
}

func TestResolver_NoTransport(t *testing.T) {
	transport := newMockTransport()
	// No handlers — all queries fail

	r := NewResolver(DefaultConfig(), newMockCache(), transport)

	resp, err := r.Resolve(context.Background(), "test.example.com.", protocol.TypeA)
	if err == nil {
		// Should return SERVFAIL response
		if resp.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Errorf("Expected SERVFAIL, got RCODE %d", resp.Header.Flags.RCODE)
		}
	}
}

func TestResolver_ContextCancellation(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Handler that respects context via a channel
	blockCh := make(chan struct{})
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		<-blockCh // Block forever until test completes
		return nil
	})

	cfg := DefaultConfig()
	cfg.Timeout = 50 * time.Millisecond

	r := NewResolver(cfg, cache, transport)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_, _ = r.Resolve(ctx, "slow.example.com.", protocol.TypeA)
		close(done)
	}()

	select {
	case <-done:
		// Good — didn't hang
	case <-time.After(2 * time.Second):
		t.Error("Resolve should have returned after context cancellation")
	}

	// Unblock the handler so the goroutine can clean up
	close(blockCh)
}

func TestStdioTransport_AddressFormat(t *testing.T) {
	tr := NewStdioTransport(5 * time.Second)

	// Just verify it doesn't crash on address parsing
	// We can't actually test network queries without a real server
	_, _ = tr.QueryContext(context.Background(), &protocol.Message{
		Header: protocol.Header{ID: 1234, Flags: protocol.Flags{RD: true}},
	}, "127.0.0.1") // Should add :53 automatically
}

func TestIsReferral(t *testing.T) {
	tests := []struct {
		name     string
		msg      *protocol.Message
		expected bool
	}{
		{
			name: "referral with NS in authority",
			msg: &protocol.Message{
				Authorities: []*protocol.ResourceRecord{
					makeNSRR("com.", "a.gtld-servers.net."),
				},
			},
			expected: true,
		},
		{
			name: "not referral - has answers",
			msg: &protocol.Message{
				Answers: []*protocol.ResourceRecord{
					makeARR("example.com.", "1.2.3.4"),
				},
			},
			expected: false,
		},
		{
			name: "not referral - SOA in authority (negative)",
			msg: &protocol.Message{
				Authorities: []*protocol.ResourceRecord{
					{
						Name:  mustName("com."),
						Type:  protocol.TypeSOA,
						Class: protocol.ClassIN,
						TTL:   900,
						Data: &protocol.RDataSOA{
							MName: mustName("a.gtld-servers.net."),
							RName: mustName("nstld.verisign-grs.com."),
						},
					},
				},
			},
			expected: false,
		},
		{
			name:     "not referral - empty",
			msg:      &protocol.Message{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isReferral(tt.msg)
			if got != tt.expected {
				t.Errorf("isReferral() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCacheKey(t *testing.T) {
	key := cacheKey("example.com.", protocol.TypeA)
	if key != "example.com.:1" {
		t.Errorf("Expected 'example.com.:1', got '%s'", key)
	}
	key = cacheKey("WWW.Example.COM.", protocol.TypeA)
	if key != "www.example.com.:1" {
		t.Errorf("Expected lowercase cache key, got '%s'", key)
	}
}

func TestResolver_CacheHitIsCaseInsensitive(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()
	r := NewResolver(DefaultConfig(), cache, transport)
	msg := protocol.NewMessage(protocol.Header{
		Flags: protocol.Flags{QR: true, RA: true, RCODE: protocol.RcodeSuccess},
	})
	cache.entries[cacheKey("www.example.com.", protocol.TypeA)] = &CacheEntry{Message: msg}

	resp, err := r.Resolve(context.Background(), "WWW.Example.COM.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resp == nil {
		t.Fatal("Resolve() returned nil response")
	}
	if calls := transport.getCalls(); len(calls) != 0 {
		t.Fatalf("Resolve() queried transport despite cache hit: %v", calls)
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b", "c"}, "b") {
		t.Error("Expected to find 'b'")
	}
	if containsString([]string{"a", "b", "c"}, "d") {
		t.Error("Did not expect to find 'd'")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxDepth != 30 {
		t.Errorf("Expected MaxDepth 30, got %d", cfg.MaxDepth)
	}
	if cfg.MaxCNAMEDepth != 16 {
		t.Errorf("Expected MaxCNAMEDepth 16, got %d", cfg.MaxCNAMEDepth)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected Timeout 5s, got %v", cfg.Timeout)
	}
	if cfg.EDNS0BufSize != 4096 {
		t.Errorf("Expected EDNS0BufSize 4096, got %d", cfg.EDNS0BufSize)
	}
}

// TestQuestionMatches locks the response-question validation used by the UDP/TCP
// transports: a response must echo the asked question (name case-insensitively,
// type and class exactly) or it is dropped — a buggy/malicious authoritative
// server must not be able to have an off-question answer cached under the
// queried key.
func TestQuestionMatches(t *testing.T) {
	mk := func(name string, qt, qc uint16) *protocol.Message {
		n, err := protocol.ParseName(name)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", name, err)
		}
		return &protocol.Message{Questions: []*protocol.Question{{Name: n, QType: qt, QClass: qc}}}
	}
	query := mk("www.Example.com.", protocol.TypeA, protocol.ClassIN)

	cases := []struct {
		name  string
		query *protocol.Message
		resp  *protocol.Message
		want  bool
	}{
		{"case-insensitive echo", query, mk("www.example.com.", protocol.TypeA, protocol.ClassIN), true},
		{"different name", query, mk("evil.com.", protocol.TypeA, protocol.ClassIN), false},
		{"different qtype", query, mk("www.example.com.", protocol.TypeAAAA, protocol.ClassIN), false},
		{"different qclass", query, mk("www.example.com.", protocol.TypeA, protocol.ClassCH), false},
		{"nil query", nil, mk("www.example.com.", protocol.TypeA, protocol.ClassIN), false},
		{"nil response", query, nil, false},
		{"empty query question", &protocol.Message{}, mk("www.example.com.", protocol.TypeA, protocol.ClassIN), false},
		{"empty response question", query, &protocol.Message{}, false},
		{"nil query question", &protocol.Message{Questions: []*protocol.Question{nil}}, mk("www.example.com.", protocol.TypeA, protocol.ClassIN), false},
		{"nil response question", query, &protocol.Message{Questions: []*protocol.Question{nil}}, false},
		{"nil query question name", &protocol.Message{Questions: []*protocol.Question{{QType: protocol.TypeA, QClass: protocol.ClassIN}}}, mk("www.example.com.", protocol.TypeA, protocol.ClassIN), false},
		{"nil response question name", query, &protocol.Message{Questions: []*protocol.Question{{QType: protocol.TypeA, QClass: protocol.ClassIN}}}, false},
	}
	for _, tc := range cases {
		if got := questionMatches(tc.query, tc.resp); got != tc.want {
			t.Errorf("%s: questionMatches = %v, want %v", tc.name, got, tc.want)
		}
	}
}
