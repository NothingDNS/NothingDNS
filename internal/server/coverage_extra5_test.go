package server

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// TLSProfile.String
// ---------------------------------------------------------------------------

func TestTLSProfile_String(t *testing.T) {
	tests := []struct {
		profile TLSProfile
		want    string
	}{
		{TLSProfileOpportunistic, "opportunistic"},
		{TLSProfileStrict, "strict"},
		{TLSProfilePrivacy, "privacy"},
		{TLSProfile(99), "opportunistic"}, // unknown defaults to opportunistic
	}
	for _, tt := range tests {
		if got := tt.profile.String(); got != tt.want {
			t.Errorf("TLSProfile(%d).String() = %q, want %q", tt.profile, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TLSProfileConfig constructors
// ---------------------------------------------------------------------------

func TestDefaultTLSProfileConfig(t *testing.T) {
	cfg := DefaultTLSProfileConfig()
	if cfg.Profile != TLSProfileOpportunistic {
		t.Errorf("Profile = %v, want Opportunistic", cfg.Profile)
	}
	if !cfg.VerifyCertificate {
		t.Error("VerifyCertificate should be true")
	}
	if !cfg.VerifyHostname {
		t.Error("VerifyHostname should be true")
	}
	if cfg.MinimumTLSVersion != tls.VersionTLS13 {
		t.Errorf("MinimumTLSVersion = %x, want TLS 1.3", cfg.MinimumTLSVersion)
	}
}

func TestStrictTLSProfileConfig(t *testing.T) {
	cfg := StrictTLSProfileConfig("dns.example.com", nil)
	if cfg.Profile != TLSProfileStrict {
		t.Errorf("Profile = %v, want Strict", cfg.Profile)
	}
	if cfg.Hostname != "dns.example.com" {
		t.Errorf("Hostname = %q, want dns.example.com", cfg.Hostname)
	}
}

func TestPrivacyTLSProfileConfig(t *testing.T) {
	cfg := PrivacyTLSProfileConfig("dns.example.com", nil)
	if cfg.Profile != TLSProfilePrivacy {
		t.Errorf("Profile = %v, want Privacy", cfg.Profile)
	}
	if cfg.Hostname != "dns.example.com" {
		t.Errorf("Hostname = %q, want dns.example.com", cfg.Hostname)
	}
}

// ---------------------------------------------------------------------------
// ValidateTLSProfile
// ---------------------------------------------------------------------------

func TestValidateTLSProfile_Nil(t *testing.T) {
	err := ValidateTLSProfile(nil)
	if err == nil {
		t.Error("expected error for nil profile")
	}
}

func TestValidateTLSProfile_StrictNoHostname(t *testing.T) {
	cfg := &TLSProfileConfig{
		Profile:           TLSProfileStrict,
		MinimumTLSVersion: tls.VersionTLS13,
	}
	err := ValidateTLSProfile(cfg)
	if err == nil {
		t.Error("expected error for strict profile without hostname")
	}
}

func TestValidateTLSProfile_PrivacyNoHostname(t *testing.T) {
	cfg := &TLSProfileConfig{
		Profile:           TLSProfilePrivacy,
		MinimumTLSVersion: tls.VersionTLS13,
	}
	err := ValidateTLSProfile(cfg)
	if err == nil {
		t.Error("expected error for privacy profile without hostname")
	}
}

func TestValidateTLSProfile_OldTLSVersion(t *testing.T) {
	cfg := &TLSProfileConfig{
		Profile:           TLSProfileOpportunistic,
		MinimumTLSVersion: tls.VersionTLS10,
	}
	err := ValidateTLSProfile(cfg)
	if err == nil {
		t.Error("expected error for TLS version < 1.2")
	}
}

func TestValidateTLSProfile_Valid(t *testing.T) {
	cfg := &TLSProfileConfig{
		Profile:           TLSProfileOpportunistic,
		MinimumTLSVersion: tls.VersionTLS13,
	}
	err := ValidateTLSProfile(cfg)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateTLSProfile_StrictWithHostname(t *testing.T) {
	cfg := &TLSProfileConfig{
		Profile:           TLSProfileStrict,
		Hostname:          "dns.example.com",
		MinimumTLSVersion: tls.VersionTLS13,
	}
	err := ValidateTLSProfile(cfg)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TLSProfile methods
// ---------------------------------------------------------------------------

func TestTLSProfile_GetNextProtos(t *testing.T) {
	opportunistic := TLSProfileOpportunistic.GetNextProtos()
	if len(opportunistic) != 2 || opportunistic[0] != "dot" || opportunistic[1] != "dns" {
		t.Errorf("Opportunistic GetNextProtos = %v, want [dot dns]", opportunistic)
	}

	strict := TLSProfileStrict.GetNextProtos()
	if len(strict) != 1 || strict[0] != "dot" {
		t.Errorf("Strict GetNextProtos = %v, want [dot]", strict)
	}

	privacy := TLSProfilePrivacy.GetNextProtos()
	if len(privacy) != 1 || privacy[0] != "dot" {
		t.Errorf("Privacy GetNextProtos = %v, want [dot]", privacy)
	}
}

func TestTLSProfile_ShouldFallback(t *testing.T) {
	if !TLSProfileOpportunistic.ShouldFallback() {
		t.Error("Opportunistic should allow fallback")
	}
	if TLSProfileStrict.ShouldFallback() {
		t.Error("Strict should not allow fallback")
	}
	if TLSProfilePrivacy.ShouldFallback() {
		t.Error("Privacy should not allow fallback")
	}
}

func TestTLSProfile_RequiresTLS(t *testing.T) {
	if TLSProfileOpportunistic.RequiresTLS() {
		t.Error("Opportunistic should not require TLS")
	}
	if !TLSProfileStrict.RequiresTLS() {
		t.Error("Strict should require TLS")
	}
	if !TLSProfilePrivacy.RequiresTLS() {
		t.Error("Privacy should require TLS")
	}
}

// ---------------------------------------------------------------------------
// BuildTLSConfigForProfile
// ---------------------------------------------------------------------------

func TestBuildTLSConfigForProfile_NoCerts(t *testing.T) {
	cfg := DefaultTLSProfileConfig()
	tlsCfg, err := BuildTLSConfigForProfile(cfg, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", tlsCfg.MinVersion)
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Error("expected no certificates when no cert/key files provided")
	}
}

func TestBuildTLSConfigForProfile_InvalidCert(t *testing.T) {
	cfg := DefaultTLSProfileConfig()
	_, err := BuildTLSConfigForProfile(cfg, "/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for invalid cert files")
	}
}

// ---------------------------------------------------------------------------
// sendSERVFAIL
// ---------------------------------------------------------------------------

type servfailMockWriter struct {
	written *protocol.Message
}

func (m *servfailMockWriter) Write(msg *protocol.Message) (int, error) {
	m.written = msg
	return 0, nil
}

func (m *servfailMockWriter) ClientInfo() *ClientInfo {
	return &ClientInfo{Protocol: "udp"}
}

func (m *servfailMockWriter) MaxSize() int {
	return 4096
}

func TestSendSERVFAIL_ValidRequest(t *testing.T) {
	rw := &servfailMockWriter{}
	req := &protocol.Message{
		Header:    protocol.Header{ID: 42},
		Questions: []*protocol.Question{{Name: &protocol.Name{Labels: []string{"example", "com"}, FQDN: true}, QType: protocol.TypeA}},
	}

	sendSERVFAIL(rw, req)

	if rw.written == nil {
		t.Fatal("expected response to be written")
	}
	if rw.written.Header.ID != 42 {
		t.Errorf("response ID = %d, want 42", rw.written.Header.ID)
	}
	if rw.written.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("RCODE = %d, want SERVFAIL (%d)", rw.written.Header.Flags.RCODE, protocol.RcodeServerFailure)
	}
}

func TestSendSERVFAIL_NilRequest(t *testing.T) {
	rw := &servfailMockWriter{}
	sendSERVFAIL(rw, nil)
	if rw.written != nil {
		t.Error("should not write response for nil request")
	}
}

func TestSendSERVFAIL_NoQuestions(t *testing.T) {
	rw := &servfailMockWriter{}
	req := &protocol.Message{
		Header:    protocol.Header{ID: 1},
		Questions: []*protocol.Question{},
	}
	sendSERVFAIL(rw, req)
	if rw.written != nil {
		t.Error("should not write response for request with no questions")
	}
}

// ---------------------------------------------------------------------------
// rateLimiter.Prune
// ---------------------------------------------------------------------------

func TestRateLimiter_Prune(t *testing.T) {
	rl := newRateLimiter(time.Second, 100)

	// Add an entry with an expired window
	rl.mu.Lock()
	rl.entries["expired"] = &rateEntry{
		count:       1,
		windowStart: time.Now().Add(-5 * time.Second),
	}
	rl.entries["valid"] = &rateEntry{
		count:       1,
		windowStart: time.Now(),
	}
	rl.mu.Unlock()

	rl.Prune()

	rl.mu.Lock()
	_, hasExpired := rl.entries["expired"]
	_, hasValid := rl.entries["valid"]
	rl.mu.Unlock()

	if hasExpired {
		t.Error("expired entry should be pruned")
	}
	if !hasValid {
		t.Error("valid entry should remain")
	}
}

func TestRateLimiter_PruneEmpty(t *testing.T) {
	rl := newRateLimiter(time.Second, 100)

	// Should not panic on empty map
	rl.Prune()
}

// ---------------------------------------------------------------------------
// UDPServer.SetRateLimit
// ---------------------------------------------------------------------------

func TestUDPServer_SetRateLimit_Positive(t *testing.T) {
	s := NewUDPServer("127.0.0.1:0", nil)
	defer s.Stop()

	s.SetRateLimit(500)

	if s.rateLimiter == nil {
		t.Fatal("rateLimiter should not be nil")
	}
	if s.rateLimiter.maxCount != 500 {
		t.Errorf("maxCount = %d, want 500", s.rateLimiter.maxCount)
	}
}

func TestUDPServer_SetRateLimit_Zero(t *testing.T) {
	s := NewUDPServer("127.0.0.1:0", nil)
	defer s.Stop()

	s.SetRateLimit(0)

	if s.rateLimiter == nil {
		t.Fatal("rateLimiter should not be nil")
	}
	if s.rateLimiter.maxCount != 1000000 {
		t.Errorf("maxCount = %d, want 1000000 (unlimited)", s.rateLimiter.maxCount)
	}
}

func TestUDPServer_SetRateLimit_Negative(t *testing.T) {
	s := NewUDPServer("127.0.0.1:0", nil)
	defer s.Stop()

	s.SetRateLimit(-1)

	if s.rateLimiter.maxCount != 1000000 {
		t.Errorf("maxCount = %d, want 1000000 for negative input", s.rateLimiter.maxCount)
	}
}
