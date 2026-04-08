package resolver

import (
	"net"
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
}

func TestResolverInfoString(t *testing.T) {
	info := BasicResolverInfo("test-resolver", []string{"dnssec"})
	s := info.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
	t.Logf("ResolverInfo.String() = %s", s)
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
	// Should be a copy
	opt.Servers[0] = net.ParseIP("::1")
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
}

func TestRDNSSString(t *testing.T) {
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	s := opt.String()
	if s == "" {
		t.Error("String() should not be empty")
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
}

func TestDNSSLString(t *testing.T) {
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	s := opt.String()
	if s == "" {
		t.Error("String() should not be empty")
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
}

func TestDNSConfigAddDNSSL(t *testing.T) {
	cfg := NewDNSConfig()
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	cfg.AddDNSSL(opt)

	if len(cfg.DNSSL) != 1 {
		t.Errorf("DNSSL len = %d, want 1", len(cfg.DNSSL))
	}
}

func TestDNSConfigGetServers(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::1")}))
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("2001:db8::2")}))

	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("GetServers() len = %d, want 2", len(servers))
	}
}

func TestDNSConfigGetSearchDomains(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"example.com"}))
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"test.com"}))

	domains := cfg.GetSearchDomains()
	if len(domains) != 2 {
		t.Errorf("GetSearchDomains() len = %d, want 2", len(domains))
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
}

func TestDNSConfigRemoveExpired(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddRDNSS(NewRDNSSOption(0, []net.IP{net.ParseIP("2001:db8::1")}))
	cfg.AddRDNSS(NewRDNSSOption(time.Hour, []net.IP{net.ParseIP("2001:db8::2")}))
	cfg.AddDNSSL(NewDNSSLOption(0, []string{"example.com"}))

	cfg.RemoveExpired()

	if len(cfg.RDNSS) != 1 {
		t.Errorf("RDNSS after RemoveExpired = %d, want 1", len(cfg.RDNSS))
	}
	if len(cfg.DNSSL) != 0 {
		t.Errorf("DNSSL after RemoveExpired = %d, want 0", len(cfg.DNSSL))
	}
}
