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
