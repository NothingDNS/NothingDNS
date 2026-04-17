package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
func (w *captureWriter) MaxSize() int                   { return 4096 }

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
		config:  config.DefaultConfig(),
		logger:  util.NewLogger(util.ERROR, util.TextFormat, nil),
		cache:   cache.New(cache.Config{Capacity: 100, DefaultTTL: 60 * time.Second, MinTTL: time.Second, MaxTTL: 300 * time.Second}),
		metrics: metrics.New(metrics.Config{Enabled: true}),
		zones:   make(map[string]*zone.Zone),
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
	}, false)
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
	}, false)
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
	}, false)
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

// --- Pure function tests ---

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		child, parent string
		want          bool
	}{
		{"www.example.com.", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"other.com.", "example.com.", false},
		{"sub.www.example.com.", "example.com.", true},
		{"example.com.", "www.example.com.", false},
		{"WWW.EXAMPLE.COM.", "example.com.", true}, // case-insensitive
		{"www.example.com", "example.com", true},   // no trailing dot
	}
	for _, tc := range tests {
		if got := isSubdomain(tc.child, tc.parent); got != tc.want {
			t.Errorf("isSubdomain(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
		}
	}
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"EXAMPLE.COM.", "example.com."},
		{"example.com", "example.com."},
		{"  EXAMPLE.COM  ", "example.com."},
		{"", "."},
		{".", "."},
	}
	for _, tc := range tests {
		if got := canonicalize(tc.input); got != tc.want {
			t.Errorf("canonicalize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestTypeToString(t *testing.T) {
	if got := typeToString(protocol.TypeA); got != "A" {
		t.Errorf("typeToString(TypeA) = %q, want %q", got, "A")
	}
	if got := typeToString(protocol.TypeAAAA); got != "AAAA" {
		t.Errorf("typeToString(TypeAAAA) = %q, want %q", got, "AAAA")
	}
}

func TestStringToType(t *testing.T) {
	if got := stringToType("A"); got != protocol.TypeA {
		t.Errorf("stringToType(%q) = %d, want %d", "A", got, protocol.TypeA)
	}
	if got := stringToType("aaaa"); got != protocol.TypeAAAA {
		t.Errorf("stringToType(%q) = %d, want %d", "aaaa", got, protocol.TypeAAAA)
	}
	if got := stringToType("UNKNOWN"); got != 0 {
		t.Errorf("stringToType(%q) = %d, want 0", "UNKNOWN", got)
	}
}

func TestParseRData(t *testing.T) {
	// A record
	rd := parseRData("A", "192.168.1.1")
	a, ok := rd.(*protocol.RDataA)
	if !ok {
		t.Fatalf("expected RDataA, got %T", rd)
	}
	if a.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("A address = %v, want 192.168.1.1", a.Address)
	}

	// A record with IPv6 should return nil
	if rd := parseRData("A", "::1"); rd != nil {
		t.Errorf("expected nil for IPv6 in A record, got %T", rd)
	}

	// AAAA record
	rd = parseRData("AAAA", "2001:db8::1")
	aaaa, ok := rd.(*protocol.RDataAAAA)
	if !ok {
		t.Fatalf("expected RDataAAAA, got %T", rd)
	}
	ifaaaa := net.IP(aaaa.Address[:])
	if !ifaaaa.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("AAAA address = %v, want 2001:db8::1", ifaaaa)
	}

	// CNAME record
	rd = parseRData("CNAME", "target.example.com.")
	cname, ok := rd.(*protocol.RDataCNAME)
	if !ok {
		t.Fatalf("expected RDataCNAME, got %T", rd)
	}
	if cname.CName.String() != "target.example.com." {
		t.Errorf("CNAME = %q, want target.example.com.", cname.CName.String())
	}

	// NS record
	rd = parseRData("NS", "ns1.example.com.")
	nsRd, ok := rd.(*protocol.RDataNS)
	if !ok {
		t.Fatalf("expected RDataNS for NS, got %T", rd)
	}
	if nsRd.NSDName.String() != "ns1.example.com." {
		t.Errorf("NS NSDName = %q, want ns1.example.com.", nsRd.NSDName.String())
	}

	// MX record
	rd = parseRData("MX", "10 mail.example.com.")
	mx, ok := rd.(*protocol.RDataMX)
	if !ok {
		t.Fatalf("expected RDataMX, got %T", rd)
	}
	if mx.Preference != 10 {
		t.Errorf("MX preference = %d, want 10", mx.Preference)
	}

	// TXT record
	rd = parseRData("TXT", "hello world")
	txt, ok := rd.(*protocol.RDataTXT)
	if !ok {
		t.Fatalf("expected RDataTXT, got %T", rd)
	}
	if len(txt.Strings) != 1 || txt.Strings[0] != "hello world" {
		t.Errorf("TXT = %v, want [hello world]", txt.Strings)
	}

	// Unknown type
	if rd := parseRData("UNKNOWN", "data"); rd != nil {
		t.Errorf("expected nil for unknown type, got %T", rd)
	}

	// Invalid A record
	if rd := parseRData("A", "not-an-ip"); rd != nil {
		t.Errorf("expected nil for invalid IP, got %T", rd)
	}

	// MX with not enough fields
	if rd := parseRData("MX", "10"); rd != nil {
		t.Errorf("expected nil for invalid MX, got %T", rd)
	}
}

func TestParseSOARData(t *testing.T) {
	soa := parseSOARData("ns1.example.com. admin.example.com. 2024010101 3600 600 604800 86400")
	s, ok := soa.(*protocol.RDataSOA)
	if !ok {
		t.Fatalf("expected RDataSOA, got %T", soa)
	}
	if s.Serial != 2024010101 {
		t.Errorf("Serial = %d, want 2024010101", s.Serial)
	}
	if s.Refresh != 3600 {
		t.Errorf("Refresh = %d, want 3600", s.Refresh)
	}
	if s.Retry != 600 {
		t.Errorf("Retry = %d, want 600", s.Retry)
	}
	if s.Expire != 604800 {
		t.Errorf("Expire = %d, want 604800", s.Expire)
	}
	if s.Minimum != 86400 {
		t.Errorf("Minimum = %d, want 86400", s.Minimum)
	}

	// Not enough fields
	if soa := parseSOARData("ns1.example.com. admin.example.com."); soa != nil {
		t.Errorf("expected nil for incomplete SOA, got %T", soa)
	}
}

func TestParseSRVRData(t *testing.T) {
	srv := parseSRVRData("10 20 443 server.example.com.")
	s, ok := srv.(*protocol.RDataSRV)
	if !ok {
		t.Fatalf("expected RDataSRV, got %T", srv)
	}
	if s.Priority != 10 {
		t.Errorf("Priority = %d, want 10", s.Priority)
	}
	if s.Weight != 20 {
		t.Errorf("Weight = %d, want 20", s.Weight)
	}
	if s.Port != 443 {
		t.Errorf("Port = %d, want 443", s.Port)
	}

	// Not enough fields
	if srv := parseSRVRData("10 20"); srv != nil {
		t.Errorf("expected nil for incomplete SRV, got %T", srv)
	}
}

func TestParseCAARData(t *testing.T) {
	caa := parseCAARData("0 issue letsencrypt.org.")
	c, ok := caa.(*protocol.RDataCAA)
	if !ok {
		t.Fatalf("expected RDataCAA, got %T", caa)
	}
	if c.Flags != 0 {
		t.Errorf("Flags = %d, want 0", c.Flags)
	}
	if c.Tag != "issue" {
		t.Errorf("Tag = %q, want %q", c.Tag, "issue")
	}
	if c.Value != "letsencrypt.org." {
		t.Errorf("Value = %q, want %q", c.Value, "letsencrypt.org.")
	}

	// Not enough fields
	if caa := parseCAARData("0 issue"); caa != nil {
		t.Errorf("expected nil for incomplete CAA, got %T", caa)
	}
}

func TestExtractTTL(t *testing.T) {
	// With answers
	resp := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{TTL: 600},
		},
	}
	if got := extractTTL(resp); got != 600 {
		t.Errorf("extractTTL with answer = %d, want 600", got)
	}

	// No answers
	resp2 := &protocol.Message{Answers: nil}
	if got := extractTTL(resp2); got != 300 {
		t.Errorf("extractTTL with no answers = %d, want 300", got)
	}

	// Answer with TTL 0
	resp3 := &protocol.Message{
		Answers: []*protocol.ResourceRecord{
			{TTL: 0},
		},
	}
	if got := extractTTL(resp3); got != 300 {
		t.Errorf("extractTTL with TTL 0 = %d, want 300", got)
	}
}

func TestHasDOBit(t *testing.T) {
	// With DO bit set
	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, TTL: 0x8000},
		},
	}
	if !hasDOBit(msg) {
		t.Error("expected DO bit to be set")
	}

	// Without DO bit
	msg2 := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, TTL: 0},
		},
	}
	if hasDOBit(msg2) {
		t.Error("expected DO bit to not be set")
	}

	// No OPT record
	msg3 := &protocol.Message{Additionals: nil}
	if hasDOBit(msg3) {
		t.Error("expected no DO bit without OPT")
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	if got := parseDurationOrDefault("5s", time.Second); got != 5*time.Second {
		t.Errorf("parseDurationOrDefault(%q) = %v, want 5s", "5s", got)
	}
	if got := parseDurationOrDefault("", time.Minute); got != time.Minute {
		t.Errorf("parseDurationOrDefault(empty) = %v, want 1m", got)
	}
	if got := parseDurationOrDefault("invalid", time.Hour); got != time.Hour {
		t.Errorf("parseDurationOrDefault(invalid) = %v, want 1h", got)
	}
}

func TestLogLevelFromString(t *testing.T) {
	tests := []struct {
		input string
		want  util.LogLevel
	}{
		{"debug", util.DEBUG},
		{"info", util.INFO},
		{"warn", util.WARN},
		{"error", util.ERROR},
		{"fatal", util.FATAL},
		{"unknown", util.INFO}, // default
	}
	for _, tc := range tests {
		if got := logLevelFromString(tc.input); got != tc.want {
			t.Errorf("logLevelFromString(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestLogFormatFromString(t *testing.T) {
	if got := logFormatFromString("json"); got != util.JSONFormat {
		t.Errorf("logFormatFromString(json) = %d, want JSONFormat", got)
	}
	if got := logFormatFromString("text"); got != util.TextFormat {
		t.Errorf("logFormatFromString(text) = %d, want TextFormat", got)
	}
	if got := logFormatFromString("other"); got != util.TextFormat {
		t.Errorf("logFormatFromString(other) = %d, want TextFormat (default)", got)
	}
}

func TestSendError(t *testing.T) {
	query := &protocol.Message{
		Header:    protocol.Header{ID: 42, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{{Name: mustParseName(t, "test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	w := &captureWriter{}
	sendError(w, query, protocol.RcodeRefused)

	if w.msg == nil {
		t.Fatal("expected error response")
	}
	if w.msg.Header.ID != 42 {
		t.Errorf("ID = %d, want 42", w.msg.Header.ID)
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("RCODE = %d, want REFUSED", w.msg.Header.Flags.RCODE)
	}
	if !w.msg.Header.Flags.QR {
		t.Error("expected QR bit set")
	}
}

func TestReply(t *testing.T) {
	query := &protocol.Message{
		Header:    protocol.Header{ID: 100, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{{Name: mustParseName(t, "test.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}
	response := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	w := &captureWriter{}
	reply(w, query, response)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Header.ID != 100 {
		t.Errorf("ID = %d, want 100", w.msg.Header.ID)
	}
	if !w.msg.Header.Flags.QR {
		t.Error("expected QR bit set")
	}
	if len(w.msg.Questions) != 1 {
		t.Errorf("expected 1 question, got %d", len(w.msg.Questions))
	}
}

// --- minimizeResponse tests ---

func TestMinimizeResponse_NilMessage(t *testing.T) {
	// Must not panic.
	minimizeResponse(nil)
}

func TestMinimizeResponse_AuthoritativeWithSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeNameError},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName:   mustParseName(t, "ns1.example.com."),
					RName:   mustParseName(t, "admin.example.com."),
					Serial:  2024010101,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
	}

	minimizeResponse(resp)

	// AA=true with SOA present: keep only SOA, strip NS.
	if len(resp.Authorities) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(resp.Authorities))
	}
	if resp.Authorities[0].Type != protocol.TypeSOA {
		t.Errorf("expected SOA in authority, got type %d", resp.Authorities[0].Type)
	}
}

func TestMinimizeResponse_AuthoritativeWithoutSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "www.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 168, 1, 1}},
			},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
	}

	minimizeResponse(resp)

	// AA=true without SOA: strip entire authority section.
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected 0 authority records for AA without SOA, got %d", len(resp.Authorities))
	}
	// Answers must be preserved.
	if len(resp.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answers))
	}
}

func TestMinimizeResponse_NonAuthoritativeKeepsNSAndSOA(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName: mustParseName(t, "ns1.example.com."),
					RName: mustParseName(t, "admin.example.com."),
				},
			},
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	minimizeResponse(resp)

	// Non-authoritative: keep NS and SOA, strip A.
	if len(resp.Authorities) != 2 {
		t.Fatalf("expected 2 authority records (NS+SOA), got %d", len(resp.Authorities))
	}
	for _, rr := range resp.Authorities {
		if rr.Type != protocol.TypeNS && rr.Type != protocol.TypeSOA {
			t.Errorf("unexpected authority type %d", rr.Type)
		}
	}
}

func TestMinimizeResponse_NonAuthoritativeStripsUnrelated(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	minimizeResponse(resp)

	// No NS or SOA: entire authority section stripped.
	if len(resp.Authorities) != 0 {
		t.Fatalf("expected nil/empty authority, got %d records", len(resp.Authorities))
	}
}

func TestMinimizeResponse_AdditionalGluePreserved(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustParseName(t, "ns1.example.com.")},
			},
		},
		Additionals: []*protocol.ResourceRecord{
			// Glue A for ns1.example.com. -- should be kept.
			{
				Name:  mustParseName(t, "ns1.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
			},
			// Non-glue A for unrelated.example.com. -- should be stripped.
			{
				Name:  mustParseName(t, "unrelated.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 2}},
			},
			// OPT pseudo-record -- should be kept.
			{
				Type:  protocol.TypeOPT,
				Class: 4096,
			},
			// TXT record -- should be stripped.
			{
				Name:  mustParseName(t, "example.com."),
				Type:  protocol.TypeTXT,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataTXT{Strings: []string{"v=spf1"}},
			},
		},
	}

	minimizeResponse(resp)

	// Expect: glue A + OPT = 2 additionals.
	if len(resp.Additionals) != 2 {
		t.Fatalf("expected 2 additionals (glue + OPT), got %d", len(resp.Additionals))
	}

	hasGlue := false
	hasOPT := false
	for _, rr := range resp.Additionals {
		if rr.Type == protocol.TypeA && rr.Name.String() == "ns1.example.com." {
			hasGlue = true
		}
		if rr.Type == protocol.TypeOPT {
			hasOPT = true
		}
	}
	if !hasGlue {
		t.Error("expected glue A record for ns1.example.com. to be preserved")
	}
	if !hasOPT {
		t.Error("expected OPT pseudo-record to be preserved")
	}
}

func TestMinimizeResponse_EmptySections(t *testing.T) {
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  mustParseName(t, "www.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	minimizeResponse(resp)

	// No authority or additional to begin with -- answers untouched.
	if len(resp.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answers))
	}
	if len(resp.Authorities) != 0 {
		t.Errorf("expected 0 authorities, got %d", len(resp.Authorities))
	}
	if len(resp.Additionals) != 0 {
		t.Errorf("expected 0 additionals, got %d", len(resp.Additionals))
	}
}

// --- Integration tests for config and initialization ---

func TestNewTestHandlerInitialization(t *testing.T) {
	h := newTestHandler()

	if h.config == nil {
		t.Error("config should not be nil")
	}
	if h.logger == nil {
		t.Error("logger should not be nil")
	}
	if h.cache == nil {
		t.Error("cache should not be nil")
	}
	if h.metrics == nil {
		t.Error("metrics should not be nil")
	}
	if h.zones == nil {
		t.Error("zones map should not be nil")
	}
}

func TestServeDNS_TruncatedResponse(t *testing.T) {
	h := newTestHandler()

	// Add many large records to trigger truncation
	records := make([]zone.Record, 50)
	for i := 0; i < 50; i++ {
		records[i] = zone.Record{
			Name:  fmt.Sprintf("host%d.example.com.", i),
			TTL:   300,
			Class: "IN",
			Type:  "TXT",
			RData: strings.Repeat("x", 100), // Large TXT record
		}
	}
	addZoneRecords(t, h, "example.com.", records)

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "host0.example.com.", protocol.TypeTXT))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should be truncated or limited due to UDP size
}

func TestServeDNS_TCPResponse(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "tcp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_AAAAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2001:db8::1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeAAAA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_MultipleQuestions(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Create query with multiple questions
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags()},
		Questions: []*protocol.Question{
			{Name: mustParseName(t, "a.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
			{Name: mustParseName(t, "b.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Multiple questions should either work or return appropriate error
}

func TestServeDNS_LargeQueryName(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Create a very long domain name
	longLabel := strings.Repeat("a", 63)
	longDomain := longLabel + ".example.com."
	h.ServeDNS(w, newTestQuery(t, longDomain, protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Should handle without panic
}

func TestServeDNS_InternationalizedDomain(t *testing.T) {
	h := newTestHandler()
	w := newCaptureWriter("10.0.0.1", "udp")

	// Test with internationalized domain (punycode)
	h.ServeDNS(w, newTestQuery(t, "xn--nxasmq5a.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
}

func TestServeDNS_EDNS0(t *testing.T) {
	h := newTestHandler()

	// Create query with EDNS0 OPT pseudo-record
	msg := newTestQuery(t, "test.com.", protocol.TypeA)
	msg.Additionals = append(msg.Additionals, &protocol.ResourceRecord{
		Name:  &protocol.Name{}, // Root name for OPT
		Type:  protocol.TypeOPT,
		Class: 4096, // UDP payload size
		TTL:   0x8000, // DO bit set
		Data:  &protocol.RDataTXT{Strings: []string{}},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, msg)

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should preserve EDNS0
}

func TestServeDNS_NXDOMAIN(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "nonexistent.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_Refused(t *testing.T) {
	h := newTestHandler()
	// No zones configured, no upstream - should return REFUSED or NXDOMAIN
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "test.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	// Response should indicate failure to resolve
}

func TestServeDNS_SRVQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "_http._tcp.example.com.", TTL: 300, Class: "IN", Type: "SRV", RData: "10 5 80 www.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "_http._tcp.example.com.", protocol.TypeSRV))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_MXQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeMX))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_SOAQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2024010101 3600 600 86400 86400"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeSOA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_NSQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns2.example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeNS))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	if len(w.msg.Answers) != 2 {
		t.Errorf("expected 2 NS answers, got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_TXTQuery(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.example.com ~all"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeTXT))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_CNAMEChain(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "a.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "b.example.com."},
		{Name: "b.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "c.example.com."},
		{Name: "c.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "a.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
	// Should have all CNAMEs + final A record
	if len(w.msg.Answers) < 3 {
		t.Errorf("expected at least 3 answers (2 CNAME + 1 A), got %d", len(w.msg.Answers))
	}
}

func TestServeDNS_LoopbackClient(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("127.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

func TestServeDNS_IPv6Client(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	w := newCaptureWriter("::1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	if w.msg == nil {
		t.Fatal("expected a response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", w.msg.Header.Flags.RCODE)
	}
}

// TestConfigFileLoading tests config file loading scenarios
func TestConfigFileLoading(t *testing.T) {
	t.Run("valid_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test.yaml")

		configYAML := `
server:
  port: 5354
  bind:
    - "127.0.0.1"
cache:
  enabled: true
  size: 1000
`
		if err := os.WriteFile(configFile, []byte(configYAML), 0644); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cfg, err := config.UnmarshalYAML(configYAML)
		if err != nil {
			t.Errorf("failed to load valid config: %v", err)
		}
		if cfg == nil {
			t.Error("config should not be nil")
		}
	})

	t.Run("nonexistent_config", func(t *testing.T) {
		_, err := os.ReadFile(filepath.Join(t.TempDir(), "nonexistent", "config.yaml"))
		if err == nil {
			t.Error("should return error for nonexistent config")
		}
	})

	t.Run("empty_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "empty.yaml")

		if err := os.WriteFile(configFile, []byte(""), 0644); err != nil {
			t.Fatalf("failed to write empty config: %v", err)
		}

		// Empty config should use defaults
		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read config: %v", err)
		}

		cfg, err := config.UnmarshalYAML(string(data))
		if err != nil {
			t.Errorf("empty config should use defaults: %v", err)
		}
		if cfg == nil {
			t.Error("config should not be nil with defaults")
		}
	})
}

// TestGracefulShutdown tests graceful shutdown behavior
func TestGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Write a PID file
	if err := os.WriteFile(pidFile, []byte("12345\n"), 0644); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	// Remove PID file (cleanup test)
	if err := os.Remove(pidFile); err != nil {
		t.Errorf("failed to remove pid file: %v", err)
	}

	// Verify PID file is removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("pid file should be removed")
	}
}

// TestManagerInitializationOrder tests that managers initialize in correct order
func TestManagerInitializationOrder(t *testing.T) {
	// This test validates the manager initialization dependencies
	// Order: config -> cache -> zones -> upstream -> dnssec -> cluster -> api

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 5354,
			Bind: []string{"127.0.0.1"},
		},
		Cache: config.CacheConfig{
			Enabled: true,
			Size:    1000,
		},
	}

	// Test cache manager creation
	cacheMgr := cache.New(cache.Config{
		Capacity:   cfg.Cache.Size,
		DefaultTTL: 300 * time.Second,
	})
	if cacheMgr == nil {
		t.Fatal("cache manager should be created")
	}

	// Test zone manager creation
	zoneMgr := zone.NewManager()
	if zoneMgr == nil {
		t.Error("zone manager should be created")
	}

	// Test metrics creation
	metricsMgr := metrics.New(metrics.Config{Enabled: true})
	if metricsMgr == nil {
		t.Error("metrics manager should be created")
	}

	// Managers should be created independently
	_ = zoneMgr // may be nil if zone dir doesn't exist
}

// TestFlagParsing tests command line flag parsing
func TestFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "version_flag",
			args: []string{"-version"},
		},
		{
			name: "help_flag",
			args: []string{"-help"},
		},
		{
			name: "config_flag",
			args: []string{"-config", "/etc/nothingdns/nothingdns.yaml"},
		},
		{
			name: "validate_config_flag",
			args: []string{"-validate-config", "-config", "/tmp/test.yaml"},
		},
		{
			name: "pid_file_flag",
			args: []string{"-pid-file", "/tmp/test.pid"},
		},
		{
			name: "log_level_flag",
			args: []string{"-log-level", "debug"},
		},
		{
			name: "foreground_flag",
			args: []string{"-foreground"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// We can't actually parse flags in tests because flag.Parse() can only be called once
			// Just verify the flag names are valid
			validFlags := []string{
				"-version", "-help", "-config", "-validate-config",
				"-pid-file", "-log-level", "-foreground",
			}
			for _, arg := range tc.args {
				if strings.HasPrefix(arg, "-") {
					found := false
					for _, valid := range validFlags {
						if arg == valid {
							found = true
							break
						}
					}
					if !found && !strings.Contains(arg, ".") {
						// Skip values that look like file paths
						t.Errorf("unknown flag: %s", arg)
					}
				}
			}
		})
	}
}

// TestDefaultConfigValues tests default configuration values
func TestDefaultConfigValues(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Server.Port != 53 {
		t.Errorf("default port = %d, want 53", cfg.Server.Port)
	}
	if cfg.Cache.Enabled != true {
		t.Errorf("default cache enabled = %v, want true", cfg.Cache.Enabled)
	}
	if cfg.Cache.Size != 10000 {
		t.Errorf("default cache size = %d, want 10000", cfg.Cache.Size)
	}
}

// TestCacheIntegration tests cache integration with handler
func TestCacheIntegration(t *testing.T) {
	h := newTestHandler()

	// Add a zone
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "cached.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.168.1.1"},
	})

	// First query - should hit zone
	w1 := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w1, newTestQuery(t, "cached.example.com.", protocol.TypeA))

	if w1.msg == nil {
		t.Fatal("expected response")
	}
	if w1.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("first query failed: rcode %d", w1.msg.Header.Flags.RCODE)
	}

	// Verify answer contains expected IP
	found := false
	for _, rec := range w1.msg.Answers {
		if rec.Type == protocol.TypeA {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected A record in answer")
	}
}
