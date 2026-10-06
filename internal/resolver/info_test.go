package resolver

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestBasicResolverInfo(t *testing.T) {
	capabilities := []string{"dnssec", "filtering"}
	info := BasicResolverInfo("test-resolver", capabilities)

	if info.Version != "1.0" {
		t.Errorf("Version = %q, want 1.0", info.Version)
	}
	if info.ID != "test-resolver" {
		t.Errorf("ID = %q, want test-resolver", info.ID)
	}
	if len(info.Capabilities) != len(capabilities) {
		t.Errorf("Capabilities len = %d, want %d", len(info.Capabilities), len(capabilities))
	}
	// Should be a copy
	info.Capabilities[0] = "modified"
	if capabilities[0] == "modified" {
		t.Error("capabilities should be copied, not the same slice")
	}
}

func TestExtendedResolverInfo(t *testing.T) {
	upstreams := []string{"8.8.8.8:53", "1.1.1.1:53"}
	info := ExtendedResolverInfo("ext-resolver", "2.0", true, false, 10000, upstreams)

	if info.Version != "2.0" {
		t.Errorf("Version = %q, want 2.0", info.Version)
	}
	if info.ID != "ext-resolver" {
		t.Errorf("ID = %q, want ext-resolver", info.ID)
	}
	if !info.DNSSecValidation {
		t.Error("DNSSecValidation should be true")
	}
	if info.FilteringEnabled {
		t.Error("FilteringEnabled should be false")
	}
	if info.CacheSize != 10000 {
		t.Errorf("CacheSize = %d, want 10000", info.CacheSize)
	}
	if len(info.Upstreams) != len(upstreams) {
		t.Errorf("Upstreams len = %d, want %d", len(info.Upstreams), len(upstreams))
	}
}

func TestAddCapability(t *testing.T) {
	info := BasicResolverInfo("test", nil)

	info.AddCapability("dnssec")
	info.AddCapability("filtering")
	info.AddCapability("dnssec") // Duplicate - should not add

	if len(info.Capabilities) != 2 {
		t.Errorf("Capabilities len = %d, want 2", len(info.Capabilities))
	}
}

func TestHasCapability(t *testing.T) {
	info := BasicResolverInfo("test", []string{"dnssec", "filtering"})

	if !info.HasCapability("dnssec") {
		t.Error("HasCapability(dnssec) = false, want true")
	}
	if !info.HasCapability("filtering") {
		t.Error("HasCapability(filtering) = false, want true")
	}
	if info.HasCapability("unknown") {
		t.Error("HasCapability(unknown) = true, want false")
	}

	var nilInfo *ResolverInfo
	if nilInfo.HasCapability("dnssec") {
		t.Error("HasCapability on nil resolver info should return false")
	}
}

func TestValidate(t *testing.T) {
	// Valid info
	info := BasicResolverInfo("test", nil)
	if err := info.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	// Nil info
	var nilInfo *ResolverInfo
	if err := nilInfo.Validate(); err == nil {
		t.Error("Validate() on nil should return error")
	}

	// Empty ID
	info.ID = ""
	if err := info.Validate(); err == nil {
		t.Error("Validate() on empty ID should return error")
	}
}

func TestResolverInfoToWire(t *testing.T) {
	info := BasicResolverInfo("test-resolver", []string{"dnssec"})

	wire, err := info.ToWire(ResponderOptionCodeResolverInfo, 300)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}
	if wire.InfoType != ResponderOptionCodeResolverInfo {
		t.Errorf("InfoType = %d, want %d", wire.InfoType, ResponderOptionCodeResolverInfo)
	}
	if wire.TTL != 300 {
		t.Errorf("TTL = %d, want 300", wire.TTL)
	}
	if len(wire.Data) == 0 {
		t.Error("Data should not be empty")
	}

	// Extended info
	extInfo := ExtendedResolverInfo("ext", "2.0", true, false, 1000, nil)
	wire, err = extInfo.ToWire(ResponderOptionCodeExtendedInfo, 600)
	if err != nil {
		t.Fatalf("ToWire extended failed: %v", err)
	}
	if wire.InfoType != ResponderOptionCodeExtendedInfo {
		t.Errorf("InfoType = %d, want %d", wire.InfoType, ResponderOptionCodeExtendedInfo)
	}

	// Unknown type
	_, err = info.ToWire(99, 300)
	if err == nil {
		t.Error("ToWire with unknown type should fail")
	}

	var nilInfo *ResolverInfo
	if _, err := nilInfo.ToWire(ResponderOptionCodeResolverInfo, 300); err == nil {
		t.Error("ToWire on nil resolver info should fail")
	}
	if _, err := (&ResolverInfo{}).ToWire(ResponderOptionCodeResolverInfo, 300); err == nil {
		t.Error("ToWire with empty resolver ID should fail")
	}
}

func TestResolverInfoToWireRejectsOversizedByteFields(t *testing.T) {
	long := strings.Repeat("x", 256)
	tests := []struct {
		name     string
		info     *ResolverInfo
		infoType uint8
	}{
		{
			name:     "basic ID",
			info:     BasicResolverInfo(long, nil),
			infoType: ResponderOptionCodeResolverInfo,
		},
		{
			name:     "basic version",
			info:     &ResolverInfo{ID: "id", Version: long},
			infoType: ResponderOptionCodeResolverInfo,
		},
		{
			name:     "extended upstream count",
			info:     ExtendedResolverInfo("id", "1.0", false, false, 0, make([]string, 256)),
			infoType: ResponderOptionCodeExtendedInfo,
		},
		{
			name:     "extended hostname",
			info:     ExtendedResolverInfo("id", "1.0", false, false, 0, []string{long}),
			infoType: ResponderOptionCodeExtendedInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.info.ToWire(tt.infoType, 300); err == nil {
				t.Fatal("expected oversized resolver info field to fail")
			}
		})
	}
}

func TestResolverInfoHostnameMarkerAvoidsIPMarkerCollision(t *testing.T) {
	info := ExtendedResolverInfo("id", "1.0", false, false, 0, []string{"abcd", "abcdef"})
	wire, err := info.ToWire(ResponderOptionCodeExtendedInfo, 300)
	if err != nil {
		t.Fatalf("ToWire: %v", err)
	}

	parsed, err := parseExtendedRESPInfo(wire.Data)
	if err != nil {
		t.Fatalf("parseExtendedRESPInfo: %v", err)
	}
	if len(parsed.Upstreams) != 2 || parsed.Upstreams[0] != "abcd" || parsed.Upstreams[1] != "abcdef" {
		t.Fatalf("Upstreams = %#v, want [abcd abcdef]", parsed.Upstreams)
	}
}

func TestResolverInfoString(t *testing.T) {
	info := BasicResolverInfo("test-resolver", []string{"dnssec"})
	s := info.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
	t.Logf("ResolverInfo.String() = %s", s)

	var nilInfo *ResolverInfo
	if got := nilInfo.String(); got != "ResolverInfo{}" {
		t.Errorf("nil ResolverInfo.String() = %q, want ResolverInfo{}", got)
	}
}

func TestParseRESPInfo(t *testing.T) {
	info := BasicResolverInfo("test-resolver", []string{"dnssec"})
	wire, err := info.ToWire(ResponderOptionCodeResolverInfo, 300)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}

	// Parse should work
	parsed, err := ParseRESPInfo(ResponderOptionCodeResolverInfo, wire.Data)
	if err != nil {
		t.Fatalf("ParseRESPInfo failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("ParseRESPInfo returned nil")
	}
	if parsed.ID != "test-resolver" {
		t.Errorf("ID = %q, want test-resolver", parsed.ID)
	}
}

func TestParseRESPInfoNil(t *testing.T) {
	_, err := ParseRESPInfo(0, nil)
	if err == nil {
		t.Error("ParseRESPInfo(nil) should fail")
	}
}

func TestResolverInfoFromCapabilities(t *testing.T) {
	info := ResolverInfoFromCapabilities("test-resolver", []string{"dnssec", "filtering", "edns"})
	if info == nil {
		t.Fatal("ResolverInfoFromCapabilities returned nil")
	}
	if !info.HasCapability("dnssec") {
		t.Error("should have dnssec capability")
	}
	if !info.HasCapability("filtering") {
		t.Error("should have filtering capability")
	}
	if info.Version != "1.0" {
		t.Errorf("Version = %q, want 1.0", info.Version)
	}
}

// RDNSS tests

func TestNewRDNSSOption(t *testing.T) {
	servers := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}
	opt := NewRDNSSOption(5*time.Minute, servers)

	if opt.Lifetime != 300 {
		t.Errorf("Lifetime = %d, want 300", opt.Lifetime)
	}
	if len(opt.Servers) != len(servers) {
		t.Errorf("Servers len = %d, want %d", len(opt.Servers), len(servers))
	}

	servers[0][15] = 0xff
	if opt.Servers[0][15] == 0xff {
		t.Fatal("NewRDNSSOption aliased caller server IP bytes")
	}
}

func TestNewRDNSSOptionClampsLifetime(t *testing.T) {
	servers := []net.IP{net.ParseIP("2001:db8::1")}

	opt := NewRDNSSOption(-time.Second, servers)
	if opt.Lifetime != 0 {
		t.Errorf("negative lifetime = %d, want 0", opt.Lifetime)
	}

	overflow := time.Duration(int64(^uint32(0))+1) * time.Second
	opt = NewRDNSSOption(overflow, servers)
	if opt.Lifetime != ^uint32(0) {
		t.Errorf("overflow lifetime = %d, want %d", opt.Lifetime, ^uint32(0))
	}
}

func TestRDNSSValidate(t *testing.T) {
	// Valid
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	if err := opt.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	// No servers
	opt2 := NewRDNSSOption(time.Minute, nil)
	if err := opt2.Validate(); err == nil {
		t.Error("Validate() on nil servers should fail")
	}

	// Too many servers
	servers := make([]net.IP, 5)
	for i := range servers {
		servers[i] = net.ParseIP("2001:db8::1")
	}
	opt3 := NewRDNSSOption(time.Minute, servers)
	if err := opt3.Validate(); err == nil {
		t.Error("Validate() with too many servers should fail")
	}

	// IPv4 server
	opt4 := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("192.168.1.1")})
	if err := opt4.Validate(); err == nil {
		t.Error("Validate() with IPv4 should fail")
	}

	// Unspecified address
	opt5 := NewRDNSSOption(time.Minute, []net.IP{net.IPv6unspecified})
	if err := opt5.Validate(); err == nil {
		t.Error("Validate() with unspecified should fail")
	}

	var nilOpt *RDNSSOption
	if err := nilOpt.Validate(); err == nil {
		t.Error("Validate() on nil RDNSS option should fail")
	}
}

func TestRDNSSIsExpired(t *testing.T) {
	opt := NewRDNSSOption(0, []net.IP{net.ParseIP("2001:db8::1")})
	if !opt.IsExpired() {
		t.Error("IsExpired() with lifetime=0 should be true")
	}

	opt2 := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	if opt2.IsExpired() {
		t.Error("IsExpired() with lifetime>0 should be false")
	}

	var nilOpt *RDNSSOption
	if !nilOpt.IsExpired() {
		t.Error("IsExpired() on nil RDNSS option should be true")
	}
}

func TestRDNSSRemainingLifetime(t *testing.T) {
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})

	// Lifetime 0
	opt.Lifetime = 0
	if rem := opt.RemainingLifetime(time.Now()); rem != 0 {
		t.Errorf("RemainingLifetime() with 0 = %v, want 0", rem)
	}

	// Infinite lifetime
	opt.Lifetime = 0xFFFFFFFF
	rem := opt.RemainingLifetime(time.Now())
	if rem <= 0 {
		t.Errorf("RemainingLifetime() with INF = %v, should be positive", rem)
	}

	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	if rem := remainingLifetimeAt(60, now.Add(-59*time.Second), now); rem != time.Second {
		t.Errorf("remainingLifetimeAt() before expiry = %v, want 1s", rem)
	}
	if rem := remainingLifetimeAt(60, now.Add(-60*time.Second), now); rem != 0 {
		t.Errorf("remainingLifetimeAt() at exact expiry = %v, want 0", rem)
	}
	if rem := remainingLifetimeAt(60, now.Add(-61*time.Second), now); rem != 0 {
		t.Errorf("remainingLifetimeAt() after expiry = %v, want 0", rem)
	}

	var nilOpt *RDNSSOption
	if rem := nilOpt.RemainingLifetime(time.Now()); rem != 0 {
		t.Errorf("RemainingLifetime() on nil RDNSS option = %v, want 0", rem)
	}
}

func TestRDNSSString(t *testing.T) {
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	s := opt.String()
	if s == "" {
		t.Error("String() should not be empty")
	}

	var nilOpt *RDNSSOption
	if got := nilOpt.String(); got != "RDNSS{}" {
		t.Errorf("nil RDNSS String() = %q, want RDNSS{}", got)
	}
}

// DNSSL tests

func TestNewDNSSLOption(t *testing.T) {
	domains := []string{"example.com", "test.com"}
	opt := NewDNSSLOption(5*time.Minute, domains)

	if opt.Lifetime != 300 {
		t.Errorf("Lifetime = %d, want 300", opt.Lifetime)
	}
	if len(opt.SearchDomains) != len(domains) {
		t.Errorf("SearchDomains len = %d, want %d", len(opt.SearchDomains), len(domains))
	}
}

func TestNewDNSSLOptionClampsLifetime(t *testing.T) {
	domains := []string{"example.com"}

	opt := NewDNSSLOption(-time.Second, domains)
	if opt.Lifetime != 0 {
		t.Errorf("negative lifetime = %d, want 0", opt.Lifetime)
	}

	overflow := time.Duration(int64(^uint32(0))+1) * time.Second
	opt = NewDNSSLOption(overflow, domains)
	if opt.Lifetime != ^uint32(0) {
		t.Errorf("overflow lifetime = %d, want %d", opt.Lifetime, ^uint32(0))
	}
}

func TestDNSSLValidate(t *testing.T) {
	// Valid
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	if err := opt.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	// No domains
	opt2 := NewDNSSLOption(time.Minute, nil)
	if err := opt2.Validate(); err == nil {
		t.Error("Validate() on nil domains should fail")
	}

	// Too many domains
	domains := make([]string, 70)
	for i := range domains {
		domains[i] = "example.com"
	}
	opt3 := NewDNSSLOption(time.Minute, domains)
	if err := opt3.Validate(); err == nil {
		t.Error("Validate() with too many domains should fail")
	}

	// Empty domain
	opt4 := NewDNSSLOption(time.Minute, []string{""})
	if err := opt4.Validate(); err == nil {
		t.Error("Validate() with empty domain should fail")
	}

	// Total encoded option does not fit in the 8-bit Length field.
	largeDomains := make([]string, 64)
	for i := range largeDomains {
		largeDomains[i] = strings.Repeat("a", 31) + ".example.com"
	}
	opt5 := NewDNSSLOption(time.Minute, largeDomains)
	if err := opt5.Validate(); err == nil {
		t.Error("Validate() with oversized encoded DNSSL option should fail")
	}

	var nilOpt *DNSSLOption
	if err := nilOpt.Validate(); err == nil {
		t.Error("Validate() on nil DNSSL option should fail")
	}
}

func TestDNSSLIsExpired(t *testing.T) {
	opt := NewDNSSLOption(0, []string{"example.com"})
	if !opt.IsExpired() {
		t.Error("IsExpired() with lifetime=0 should be true")
	}

	opt2 := NewDNSSLOption(time.Minute, []string{"example.com"})
	if opt2.IsExpired() {
		t.Error("IsExpired() with lifetime>0 should be false")
	}

	var nilOpt *DNSSLOption
	if !nilOpt.IsExpired() {
		t.Error("IsExpired() on nil DNSSL option should be true")
	}
}

func TestDNSSLRemainingLifetime(t *testing.T) {
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})

	// Lifetime 0
	opt.Lifetime = 0
	if rem := opt.RemainingLifetime(time.Now()); rem != 0 {
		t.Errorf("RemainingLifetime() with 0 = %v, want 0", rem)
	}

	// Infinite lifetime
	opt.Lifetime = 0xFFFFFFFF
	rem := opt.RemainingLifetime(time.Now())
	if rem <= 0 {
		t.Errorf("RemainingLifetime() with INF = %v, should be positive", rem)
	}

	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	if rem := remainingLifetimeAt(60, now.Add(-59*time.Second), now); rem != time.Second {
		t.Errorf("remainingLifetimeAt() before expiry = %v, want 1s", rem)
	}
	if rem := remainingLifetimeAt(60, now.Add(-60*time.Second), now); rem != 0 {
		t.Errorf("remainingLifetimeAt() at exact expiry = %v, want 0", rem)
	}
	if rem := remainingLifetimeAt(60, now.Add(-61*time.Second), now); rem != 0 {
		t.Errorf("remainingLifetimeAt() after expiry = %v, want 0", rem)
	}

	var nilOpt *DNSSLOption
	if rem := nilOpt.RemainingLifetime(time.Now()); rem != 0 {
		t.Errorf("RemainingLifetime() on nil DNSSL option = %v, want 0", rem)
	}
}

func TestDNSSLString(t *testing.T) {
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	s := opt.String()
	if s == "" {
		t.Error("String() should not be empty")
	}

	var nilOpt *DNSSLOption
	if got := nilOpt.String(); got != "DNSSL{}" {
		t.Errorf("nil DNSSL String() = %q, want DNSSL{}", got)
	}
}

// DNSConfig tests

func TestNewDNSConfig(t *testing.T) {
	cfg := NewDNSConfig()
	if cfg == nil {
		t.Fatal("NewDNSConfig returned nil")
	}
	if cfg.RDNSS == nil {
		t.Error("RDNSS should be initialized")
	}
	if cfg.DNSSL == nil {
		t.Error("DNSSL should be initialized")
	}
}

func TestDNSConfigAddRDNSS(t *testing.T) {
	cfg := NewDNSConfig()
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	cfg.AddRDNSS(opt)

	if len(cfg.RDNSS) != 1 {
		t.Errorf("RDNSS len = %d, want 1", len(cfg.RDNSS))
	}

	var nilCfg *DNSConfig
	nilCfg.AddRDNSS(opt)
}

func TestDNSConfigAddDNSSL(t *testing.T) {
	cfg := NewDNSConfig()
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	cfg.AddDNSSL(opt)

	if len(cfg.DNSSL) != 1 {
		t.Errorf("DNSSL len = %d, want 1", len(cfg.DNSSL))
	}

	var nilCfg *DNSConfig
	nilCfg.AddDNSSL(opt)
}

func TestDNSConfigGetServers(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddRDNSS(nil)
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")}))
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::2")}))

	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("GetServers() len = %d, want 2", len(servers))
	}
	servers[0][15] = 0xff
	if cfg.RDNSS[1].Servers[0][15] == 0xff {
		t.Fatal("GetServers() aliased stored server IP bytes")
	}

	var nilCfg *DNSConfig
	if got := nilCfg.GetServers(); len(got) != 0 {
		t.Errorf("nil DNSConfig GetServers() len = %d, want 0", len(got))
	}
}

func TestDNSConfigGetSearchDomains(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddDNSSL(nil)
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"example.com"}))
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"test.com"}))

	domains := cfg.GetSearchDomains()
	if len(domains) != 2 {
		t.Errorf("GetSearchDomains() len = %d, want 2", len(domains))
	}

	var nilCfg *DNSConfig
	if got := nilCfg.GetSearchDomains(); len(got) != 0 {
		t.Errorf("nil DNSConfig GetSearchDomains() len = %d, want 0", len(got))
	}
}

func TestDNSConfigIsEmpty(t *testing.T) {
	cfg := NewDNSConfig()
	if !cfg.IsEmpty() {
		t.Error("IsEmpty() on empty config should be true")
	}

	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")}))
	if cfg.IsEmpty() {
		t.Error("IsEmpty() on non-empty config should be false")
	}

	var nilCfg *DNSConfig
	if !nilCfg.IsEmpty() {
		t.Error("IsEmpty() on nil config should be true")
	}
}

func TestDNSConfigRemoveExpired(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddRDNSS(nil)
	cfg.AddRDNSS(NewRDNSSOption(0, []net.IP{net.ParseIP("2001:db8::1")}))
	cfg.AddRDNSS(NewRDNSSOption(time.Hour, []net.IP{net.ParseIP("2001:db8::2")}))
	cfg.AddDNSSL(nil)
	cfg.AddDNSSL(NewDNSSLOption(0, []string{"example.com"}))

	cfg.RemoveExpired()

	if len(cfg.RDNSS) != 1 {
		t.Errorf("RDNSS after RemoveExpired = %d, want 1", len(cfg.RDNSS))
	}
	if len(cfg.DNSSL) != 0 {
		t.Errorf("DNSSL after RemoveExpired = %d, want 0", len(cfg.DNSSL))
	}

	var nilCfg *DNSConfig
	nilCfg.RemoveExpired()
}

// parseExtendedRESPInfo tests

func TestParseExtendedRESPInfo(t *testing.T) {
	// Build valid extended info wire format
	info := ExtendedResolverInfo("test-resolver", "2.0", true, false, 10000, []string{"8.8.8.8:53", "1.1.1.1:53"})
	wire, err := info.ToWire(ResponderOptionCodeExtendedInfo, 300)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}

	// Parse should work
	parsed, err := parseExtendedRESPInfo(wire.Data)
	if err != nil {
		t.Fatalf("parseExtendedRESPInfo failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("parseExtendedRESPInfo returned nil")
	}
	if parsed.ID != "test-resolver" {
		t.Errorf("ID = %q, want test-resolver", parsed.ID)
	}
	if parsed.Version != "2.0" {
		t.Errorf("Version = %q, want 2.0", parsed.Version)
	}
	if !parsed.DNSSecValidation {
		t.Error("DNSSecValidation should be true")
	}
	if parsed.FilteringEnabled {
		t.Error("FilteringEnabled should be false")
	}
	if parsed.CacheSize != 10000 {
		t.Errorf("CacheSize = %d, want 10000", parsed.CacheSize)
	}
}

func TestParseExtendedRESPInfoTruncated(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short for header", []byte{1}},
		{"truncated ID len", []byte{10, 1, 2, 3}},
		{"truncated version", []byte{4, 't', 'e', 's', 't', 10, 1, 2, 3}},
		{"truncated DNSSEC flag", []byte{4, 't', 'e', 's', 't', 2, 'v', 1}},
		{"truncated filtering flag", []byte{4, 't', 'e', 's', 't', 2, 'v', 1, 1}},
		{"truncated cache size", []byte{4, 't', 'e', 's', 't', 2, 'v', 1, 1, 0}},
		{"truncated upstream count", []byte{4, 't', 'e', 's', 't', 2, 'v', 1, 1, 0, 0, 0}},
	}

	for _, tc := range tests {
		_, err := parseExtendedRESPInfo(tc.data)
		if err == nil {
			t.Errorf("parseExtendedRESPInfo(%q) should fail", tc.name)
		}
	}
}

// RDNSS TLV tests

func TestRDNSSToTLV(t *testing.T) {
	servers := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}
	opt := NewRDNSSOption(time.Minute, servers)
	tlv := opt.ToTLV()

	if tlv.Type != 31 {
		t.Errorf("Type = %d, want 31", tlv.Type)
	}
	// RFC 8106 §5.1: OPTION-LENGTH counts the option DATA — RESERVED (2) +
	// LIFETIME (4) padded to the next 8-byte boundary, then the validator
	// addresses (16 octets each). Length = (8 + 16*2)/8 = 40/8 = 5.
	// (This previously expected 4, pinning a formula that dropped the RESERVED
	// octets and so was one unit short for every address count.)
	if tlv.Length != 5 {
		t.Errorf("Length = %d, want 5", tlv.Length)
	}
	if len(tlv.Addresses) != 2 {
		t.Errorf("Addresses len = %d, want 2", len(tlv.Addresses))
	}

	var nilOpt *RDNSSOption
	if got := nilOpt.ToTLV(); got != nil {
		t.Errorf("nil RDNSS ToTLV() = %#v, want nil", got)
	}
}

func TestRDNSSToTLVClampsLengthToWireRange(t *testing.T) {
	opt := &RDNSSOption{
		Lifetime: 300,
		Servers:  make([]net.IP, 200),
	}

	tlv := opt.ToTLV()
	if tlv.Length != ^uint8(0) {
		t.Errorf("Length = %d, want %d", tlv.Length, ^uint8(0))
	}
}

func TestParseRDNSSOption(t *testing.T) {
	servers := []net.IP{net.ParseIP("2001:db8::1")}
	opt := NewRDNSSOption(time.Minute, servers)
	tlv := opt.ToTLV()

	parsed, err := ParseRDNSSOption(tlv)
	if err != nil {
		t.Fatalf("ParseRDNSSOption failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("ParseRDNSSOption returned nil")
	}
	if parsed.Lifetime != 60 {
		t.Errorf("Lifetime = %d, want 60", parsed.Lifetime)
	}

	tlv.Addresses[0][15] = 0xff
	if parsed.Servers[0][15] == 0xff {
		t.Fatal("ParseRDNSSOption aliased TLV address IP bytes")
	}
}

func TestRDNSSOptionToTLVCopiesAddresses(t *testing.T) {
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	tlv := opt.ToTLV()
	if tlv == nil {
		t.Fatal("ToTLV() returned nil")
	}
	if len(tlv.Addresses) != 1 {
		t.Fatalf("ToTLV() addresses len = %d, want 1", len(tlv.Addresses))
	}

	tlv.Addresses[0][15] = 0xff
	if opt.Servers[0][15] == 0xff {
		t.Fatal("ToTLV() aliased option server IP bytes")
	}
}

func TestParseRDNSSOptionInvalidType(t *testing.T) {
	tlv := &RDNSSOptionTLV{
		Type:      30, // Invalid
		Length:    3,
		Lifetime:  300,
		Addresses: []net.IP{net.ParseIP("2001:db8::1")},
	}
	_, err := ParseRDNSSOption(tlv)
	if err == nil {
		t.Error("ParseRDNSSOption with invalid type should fail")
	}

	if _, err := ParseRDNSSOption(nil); err == nil {
		t.Error("ParseRDNSSOption with nil TLV should fail")
	}
}

func TestParseRDNSSOptionInvalidLength(t *testing.T) {
	tlv := &RDNSSOptionTLV{
		Type:      31,
		Length:    10, // Invalid - doesn't match
		Lifetime:  300,
		Addresses: []net.IP{net.ParseIP("2001:db8::1")},
	}
	_, err := ParseRDNSSOption(tlv)
	if err == nil {
		t.Error("ParseRDNSSOption with invalid length should fail")
	}
}

func TestParseRDNSSOptionRejectsInvalidOption(t *testing.T) {
	servers := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
		net.ParseIP("2001:db8::3"),
		net.ParseIP("2001:db8::4"),
	}
	tlv := &RDNSSOptionTLV{
		Type:      31,
		Length:    uint8((1 + 1 + 4 + (16 * len(servers))) / 8),
		Lifetime:  300,
		Addresses: servers,
	}
	_, err := ParseRDNSSOption(tlv)
	if err == nil {
		t.Error("ParseRDNSSOption should reject an invalid RDNSS option")
	}
}

// DNSSL TLV tests

func TestDNSSLToTLV(t *testing.T) {
	domains := []string{"example.com", "test.com"}
	opt := NewDNSSLOption(time.Minute, domains)
	tlv := opt.ToTLV()

	if tlv.Type != 32 {
		t.Errorf("Type = %d, want 32", tlv.Type)
	}
	if tlv.Length == 0 {
		t.Error("Length should not be 0")
	}
	if len(tlv.SearchDomains) != 2 {
		t.Errorf("SearchDomains len = %d, want 2", len(tlv.SearchDomains))
	}

	var nilOpt *DNSSLOption
	if got := nilOpt.ToTLV(); got != nil {
		t.Errorf("nil DNSSL ToTLV() = %#v, want nil", got)
	}
}

func TestParseDNSSLOption(t *testing.T) {
	domains := []string{"example.com"}
	opt := NewDNSSLOption(time.Minute, domains)
	tlv := opt.ToTLV()

	parsed, err := ParseDNSSLOption(tlv)
	if err != nil {
		t.Fatalf("ParseDNSSLOption failed: %v", err)
	}
	if parsed == nil {
		t.Fatal("ParseDNSSLOption returned nil")
	}
	if parsed.Lifetime != 60 {
		t.Errorf("Lifetime = %d, want 60", parsed.Lifetime)
	}
}

func TestParseDNSSLOptionInvalidType(t *testing.T) {
	tlv := &DNSSLTLV{
		Type:          31, // Invalid
		Length:        2,
		Lifetime:      300,
		SearchDomains: []string{"example.com"},
	}
	_, err := ParseDNSSLOption(tlv)
	if err == nil {
		t.Error("ParseDNSSLOption with invalid type should fail")
	}

	if _, err := ParseDNSSLOption(nil); err == nil {
		t.Error("ParseDNSSLOption with nil TLV should fail")
	}
}

func TestParseDNSSLOptionInvalidLength(t *testing.T) {
	tlv := &DNSSLTLV{
		Type:          32,
		Length:        1,
		Lifetime:      300,
		SearchDomains: []string{"example.com"},
	}
	_, err := ParseDNSSLOption(tlv)
	if err == nil {
		t.Error("ParseDNSSLOption with invalid length should fail")
	}
}

func TestParseDNSSLOptionRejectsInvalidOption(t *testing.T) {
	tlv := &DNSSLTLV{
		Type:          32,
		Length:        1,
		Lifetime:      300,
		SearchDomains: nil,
	}
	_, err := ParseDNSSLOption(tlv)
	if err == nil {
		t.Error("ParseDNSSLOption should reject an invalid DNSSL option")
	}
}

func TestEncodeDNSSLDomain(t *testing.T) {
	// Wire format per RFC 1035 §3.1: each label prefixed by its length.
	// Caller appends the trailing zero terminator separately.
	cases := []struct {
		in   string
		want int
	}{
		{"example", 8},      // [7]example
		{"example.com", 12}, // [7]example[3]com
		{"a.b.c.d", 8},      // [1]a[1]b[1]c[1]d
		{"", 0},
		{"trailing.dot.", 13}, // [8]trailing[3]dot (trailing root dot stripped)
	}
	for _, c := range cases {
		if n := encodeDNSSLDomain(c.in); n != c.want {
			t.Errorf("encodeDNSSLDomain(%q) = %d, want %d", c.in, n, c.want)
		}
	}
}
