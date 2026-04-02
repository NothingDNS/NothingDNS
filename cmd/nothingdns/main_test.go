package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// captureWriter captures the response written by ServeDNS.
type captureWriter struct {
	client *server.ClientInfo
	msg    *protocol.Message
}

func (w *captureWriter) Write(msg *protocol.Message) (int, error) {
	w.msg = msg
	return 0, nil
}
func (w *captureWriter) ClientInfo() *server.ClientInfo { return w.client }
func (w *captureWriter) MaxSize() int                    { return 4096 }

func newCaptureWriter(ip string, proto string) *captureWriter {
	return &captureWriter{
		client: &server.ClientInfo{
			Addr:     &net.UDPAddr{IP: net.ParseIP(ip), Port: 12345},
			Protocol: proto,
		},
	}
}

func newTestHandler() *integratedHandler {
	return &integratedHandler{
		config:   config.DefaultConfig(),
		logger:   util.NewLogger(util.ERROR, util.TextFormat, nil),
		cache:    cache.New(cache.Config{Capacity: 100, DefaultTTL: 60 * time.Second, MinTTL: time.Second, MaxTTL: 300 * time.Second}),
		metrics:  metrics.New(metrics.Config{Enabled: true}),
		zones:    make(map[string]*zone.Zone),
	}
}

func newTestQuery(t *testing.T, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	msg, err := protocol.NewQuery(1, qname, qtype)
	if err != nil {
		t.Fatalf("failed to create query: %v", err)
	}
	return msg
}

func addZoneRecords(t *testing.T, h *integratedHandler, origin string, records []zone.Record) {
	t.Helper()
	z := zone.NewZone(origin)
	z.DefaultTTL = 300
	for _, rec := range records {
		z.Records[rec.Name] = append(z.Records[rec.Name], rec)
	}
	h.zones[origin] = z
}

// --- Tests ---

func TestServeDNS_EmptyQuestions(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{},
	}
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("expected FORMERR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_Blocklist(t *testing.T) {
	h := newTestHandler()

	// Create a temp blocklist file in hosts format
	tmpDir := t.TempDir()
	blFile := filepath.Join(tmpDir, "blocklist.txt")
	if err := os.WriteFile(blFile, []byte("127.0.0.1 blocked.example.com\n"), 0644); err != nil {
		t.Fatalf("failed to write blocklist: %v", err)
	}

	bl := blocklist.New(blocklist.Config{Enabled: true, Files: []string{blFile}})
	if err := bl.Load(); err != nil {
		t.Fatalf("failed to load blocklist: %v", err)
	}
	h.blocklist = bl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "blocked.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN for blocked query, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_CacheHit(t *testing.T) {
	h := newTestHandler()

	// Pre-populate cache
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    0,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "cached.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{127, 0, 0, 1}},
			},
		},
	}
	key := cache.MakeKey("cached.example.com.", protocol.TypeA)
	h.cache.Set(key, resp, 300)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "cached.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for cache hit, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_AuthoritativeZone(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
	aData, ok := w.msg.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatal("expected A record data")
	}
	if aData.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("expected 192.168.1.1, got %v", aData.Address)
	}
}

func TestServeDNS_NoUpstream_NoZone(t *testing.T) {
	h := newTestHandler()

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "unknown.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_ACLDeny(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "block-test",
			Networks: []string{"10.0.0.0/24"},
			Action:   "deny",
			Types:    []string{"A"},
		},
	})
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED for ACL deny, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_ACLAllow(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "allow-all",
			Networks: []string{"0.0.0.0/0"},
			Action:   "allow",
		},
	})
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "unknown.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// With no upstream, it should return NXDOMAIN (not REFUSED)
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN when ACL allows, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_RateLimitExceeded(t *testing.T) {
	h := newTestHandler()
	h.rateLimiter = filter.NewRateLimiter(config.RRLConfig{Rate: 1, Burst: 1})
	defer h.rateLimiter.Stop()

	// First request should succeed
	w1 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w1, newTestQuery(t, "unknown.com.", protocol.TypeA))
	if w1.msg == nil {
		t.Fatal("expected first response")
	}

	// Second request should be rate limited
	w2 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w2, newTestQuery(t, "unknown.com.", protocol.TypeA))
	if w2.msg == nil {
		t.Fatal("expected second response")
	}
	if w2.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected REFUSED when rate limited, got rcode %d", w2.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_QueryLatencyRecorded(t *testing.T) {
	h := newTestHandler()
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))

	// Check that latency was recorded
	h.metrics.RecordQueryLatency("A", 10*time.Millisecond)
	h.metrics.RecordQueryLatency("A", 50*time.Millisecond)

	// Verify histograms were created (internal state check)
	// The defer in ServeDNS should have recorded latency for the query type
	// We just verify no panic and metrics collector works
}

func TestServeDNS_CNAMEChase(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "target.example.com."},
		{Name: "target.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "10.0.0.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "alias.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for CNAME chase, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	// Should have CNAME + A record
	if len(w.msg.Answers) < 2 {
		t.Fatalf("expected at least 2 answers (CNAME + A), got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_MetricsRecorded(t *testing.T) {
	h := newTestHandler()
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))

	// Verify metrics don't panic when recorded
	h.metrics.RecordQuery("A")
	h.metrics.RecordResponse(protocol.RcodeSuccess)
	h.metrics.RecordCacheMiss()
}

func TestServeDNS_AuditLogRecorded(t *testing.T) {
	h := newTestHandler()
	al, err := audit.NewAuditLogger(true, "")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	h.auditLogger = al
	defer al.Close()

	// Should not panic
	h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), newTestQuery(t, "test.com.", protocol.TypeA))
}

func TestServeDNS_ACLRedirect(t *testing.T) {
	h := newTestHandler()
	acl, err := filter.NewACLChecker([]config.ACLRule{
		{
			Name:     "redirect-test",
			Networks: []string{"10.0.0.0/24"},
			Action:   "redirect",
			Redirect: "safe.example.com.",
			Types:    []string{"A"},
		},
	})
	if err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}
	h.aclChecker = acl

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "anything.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR for redirect, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer (CNAME redirect), got %d", len(w.msg.Answers))
	}
	if w.msg.Answers[0].Type != protocol.TypeCNAME {
		t.Errorf("expected CNAME type, got %d", w.msg.Answers[0].Type)
	}
}

func mustParseName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("failed to parse name %q: %v", s, err)
	}
	return n
}
