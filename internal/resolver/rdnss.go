// Package resolver provides DNS resolution functionality.
// This file implements RFC 8106 - IPv6 Router Advertisement Options for DNS Configuration.
// RDNSS (Recursive DNS Server) and DNSSL (DNS Search List) options allow
// IPv6 routers to advertise DNS configuration to clients.
package resolver

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RDNSSOption represents an RDNSS (Recursive DNS Server) option per RFC 8106.
// RDNSS is carried in Router Advertisement messages to advertise DNS server addresses.
type RDNSSOption struct {
	// Lifetime is how long the DNS server addresses remain valid (in seconds)
	Lifetime uint32

	// Servers is the list of IPv6 addresses of recursive DNS servers
	Servers []net.IP
}

// RDNSSOptionTLV represents the TLV format of an RDNSS option in Router Advertisements.
type RDNSSOptionTLV struct {
	// Type is the option type (31 for RDNSS)
	Type uint8

	// Length is the length of the option in 8-byte units
	Length uint8

	// Lifetime in seconds
	Lifetime uint32

	// Addresses of the DNS servers
	Addresses []net.IP
}

// NewRDNSSOption creates a new RDNSS option.
func NewRDNSSOption(lifetime time.Duration, servers []net.IP) *RDNSSOption {
	return &RDNSSOption{
		Lifetime: durationSeconds32(lifetime),
		Servers:  cloneIPList(servers),
	}
}

// Validate checks if the RDNSS option is valid per RFC 8106.
func (r *RDNSSOption) Validate() error {
	if r == nil {
		return fmt.Errorf("RDNSS: nil option")
	}
	if len(r.Servers) == 0 {
		return fmt.Errorf("RDNSS: at least one server address required")
	}

	if len(r.Servers) > 3 {
		return fmt.Errorf("RDNSS: too many servers (max 3): %d", len(r.Servers))
	}

	for _, server := range r.Servers {
		if server.To4() != nil {
			return fmt.Errorf("RDNSS: server must be IPv6 address: %s", server)
		}
		if server.IsUnspecified() {
			return fmt.Errorf("RDNSS: server address cannot be unspecified")
		}
		if server.IsLoopback() {
			return fmt.Errorf("RDNSS: server address cannot be loopback")
		}
	}

	return nil
}

// ToTLV converts RDNSS option to TLV format for Router Advertisements.
func (r *RDNSSOption) ToTLV() *RDNSSOptionTLV {
	if r == nil {
		return nil
	}
	lengthUnits := rdnssOptionLengthUnits(len(r.Servers))
	if lengthUnits > 0xff {
		lengthUnits = 0xff
	}

	return &RDNSSOptionTLV{
		Type:      31, // RDNSS option type
		Length:    uint8(lengthUnits),
		Lifetime:  r.Lifetime,
		Addresses: cloneIPList(r.Servers),
	}
}

// ParseRDNSSOption parses an RDNSS option from TLV format.
func ParseRDNSSOption(tlv *RDNSSOptionTLV) (*RDNSSOption, error) {
	if tlv == nil {
		return nil, fmt.Errorf("RDNSS: nil option")
	}
	if tlv.Type != 31 {
		return nil, fmt.Errorf("RDNSS: invalid option type: %d", tlv.Type)
	}

	// Calculate expected length
	numAddrs := len(tlv.Addresses)
	expectedLength := rdnssOptionLengthUnits(numAddrs)
	if expectedLength > 0xff {
		return nil, fmt.Errorf("RDNSS: option too long: %d 8-byte units (max 255)", expectedLength)
	}
	if tlv.Length != uint8(expectedLength) {
		return nil, fmt.Errorf("RDNSS: invalid length: expected %d, got %d", expectedLength, tlv.Length)
	}

	opt := &RDNSSOption{
		Lifetime: tlv.Lifetime,
		Servers:  cloneIPList(tlv.Addresses),
	}
	if err := opt.Validate(); err != nil {
		return nil, err
	}
	return opt, nil
}

func cloneIPList(ips []net.IP) []net.IP {
	if ips == nil {
		return nil
	}
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

func rdnssOptionLengthUnits(numAddrs int) int {
	// RFC 8106 §5.1: OPTION-LENGTH counts the option DATA — everything after
	// OPTION-LENGTH itself — namely RESERVED (2) + LIFETIME (4), which is
	// 6 octets and is padded with zeroes up to the next 8-byte boundary, then
	// the validator addresses (16 octets each; Validate only admits IPv6).
	// Since 16n is always a multiple of 8 the padding collapses to a fixed
	// 8-octet header, so the encoded length is (8 + 16n)/8.
	//
	// The previous formula counted "1 (type) + 1 (length) + 4 (lifetime)":
	// OPTION-CODE is 2 octets, and the RESERVED octets were dropped entirely,
	// so every result was one 8-byte unit short and ParseRDNSSOption rejected
	// conformant RAs (n=1 encodes Length=3, not 2). This matches the sibling
	// dnsslOptionLengthUnits, which already pads its header to 8.
	length := 8 + (16 * numAddrs)
	return length / 8
}

// IsExpired returns true if the RDNSS option has expired.
func (r *RDNSSOption) IsExpired() bool {
	if r == nil {
		return true
	}
	return r.Lifetime == 0
}

// RemainingLifetime returns the remaining lifetime based on when the option was received.
func (r *RDNSSOption) RemainingLifetime(receivedAt time.Time) time.Duration {
	if r == nil {
		return 0
	}
	return remainingLifetimeAt(r.Lifetime, receivedAt, time.Now())
}

// String returns a human-readable representation.
func (r *RDNSSOption) String() string {
	if r == nil {
		return "RDNSS{}"
	}
	return fmt.Sprintf("RDNSS{lifetime=%d servers=%v}", r.Lifetime, r.Servers)
}

// ============================================================================
// DNSSL (DNS Search List) per RFC 8106
// ============================================================================

// DNSSLOption represents a DNSSL (DNS Search List) option per RFC 8106.
// DNSSL is carried in Router Advertisement messages to advertise DNS search domains.
type DNSSLOption struct {
	// Lifetime is how long the search domains remain valid (in seconds)
	Lifetime uint32

	// SearchDomains is the list of DNS search domains
	SearchDomains []string
}

// NewDNSSLOption creates a new DNSSL option.
func NewDNSSLOption(lifetime time.Duration, domains []string) *DNSSLOption {
	return &DNSSLOption{
		Lifetime:      durationSeconds32(lifetime),
		SearchDomains: append([]string(nil), domains...),
	}
}

func durationSeconds32(d time.Duration) uint32 {
	seconds := int64(d / time.Second)
	if seconds <= 0 {
		return 0
	}
	if seconds > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(seconds)
}

func remainingLifetimeAt(lifetime uint32, receivedAt, now time.Time) time.Duration {
	if lifetime == 0 {
		return 0
	}
	if lifetime == 0xFFFFFFFF {
		return time.Duration(1<<32-1) * time.Second
	}
	remaining := time.Duration(lifetime)*time.Second - now.Sub(receivedAt)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

// Validate checks if the DNSSL option is valid per RFC 8106.
func (d *DNSSLOption) Validate() error {
	if d == nil {
		return fmt.Errorf("DNSSL: nil option")
	}
	if len(d.SearchDomains) == 0 {
		return fmt.Errorf("DNSSL: at least one search domain required")
	}

	if len(d.SearchDomains) > 64 {
		return fmt.Errorf("DNSSL: too many domains (max 64): %d", len(d.SearchDomains))
	}

	for _, domain := range d.SearchDomains {
		if len(domain) == 0 {
			return fmt.Errorf("DNSSL: domain cannot be empty")
		}
		if len(domain) > 255 {
			return fmt.Errorf("DNSSL: domain too long: %d", len(domain))
		}
	}

	if units := dnsslOptionLengthUnits(d.SearchDomains); units > 0xff {
		return fmt.Errorf("DNSSL: option too long: %d 8-byte units (max 255)", units)
	}

	return nil
}

// ToTLV converts DNSSL option to TLV format for Router Advertisements
// (RFC 8106 §5.2). Each search domain is encoded as a wire-format DNS
// name (length-prefixed labels) with a trailing zero terminator. The
// Length field reports the entire option size in 8-byte units, padded
// to a multiple of 8 per RFC 8106.
func (d *DNSSLOption) ToTLV() *DNSSLTLV {
	if d == nil {
		return nil
	}
	lengthUnits := dnsslOptionLengthUnits(d.SearchDomains)
	if lengthUnits > 0xff {
		lengthUnits = 0xff
	}

	return &DNSSLTLV{
		Type:          32, // DNSSL option type
		Length:        uint8(lengthUnits),
		Lifetime:      d.Lifetime,
		SearchDomains: d.SearchDomains,
	}
}

// DNSSLTLV represents the TLV format of a DNSSL option.
type DNSSLTLV struct {
	Type          uint8
	Length        uint8
	Lifetime      uint32
	SearchDomains []string
}

// ParseDNSSLOption parses a DNSSL option from TLV format.
func ParseDNSSLOption(tlv *DNSSLTLV) (*DNSSLOption, error) {
	if tlv == nil {
		return nil, fmt.Errorf("DNSSL: nil option")
	}
	if tlv.Type != 32 {
		return nil, fmt.Errorf("DNSSL: invalid option type: %d", tlv.Type)
	}

	expectedLength := dnsslOptionLengthUnits(tlv.SearchDomains)
	if expectedLength > 0xff {
		return nil, fmt.Errorf("DNSSL: option too long: %d 8-byte units (max 255)", expectedLength)
	}
	if tlv.Length != uint8(expectedLength) {
		return nil, fmt.Errorf("DNSSL: invalid length: expected %d, got %d", expectedLength, tlv.Length)
	}

	opt := &DNSSLOption{
		Lifetime:      tlv.Lifetime,
		SearchDomains: tlv.SearchDomains,
	}
	if err := opt.Validate(); err != nil {
		return nil, err
	}
	return opt, nil
}

// encodeDNSSLDomain returns the wire-format byte count of a DNS domain
// encoded for DNSSL: each label prefixed by its length per RFC 1035
// §3.1. The caller appends a single 0 terminator byte per domain.
//
// "example"      → 8  (1+7)
// "example.com"  → 12 (1+7 + 1+3)
// ""             → 0  (caller still appends terminator)
func encodeDNSSLDomain(domain string) int {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return 0
	}
	n := 0
	for _, label := range strings.Split(domain, ".") {
		n += 1 + len(label)
	}
	return n
}

func dnsslOptionLengthUnits(domains []string) int {
	// 2 bytes (type+length) + 2 reserved + 4 (lifetime) + encoded domains
	// (per RFC 8106 §5.2 the option header is type+length+reserved+lifetime
	// = 8 bytes before the domain list).
	encodedLen := 0
	for _, domain := range domains {
		encodedLen += encodeDNSSLDomain(domain)
		encodedLen += 1 // per-domain zero terminator (RFC 1035 §3.1)
	}

	totalBytes := 8 + encodedLen
	// Pad to 8-byte boundary.
	if pad := totalBytes % 8; pad != 0 {
		totalBytes += 8 - pad
	}
	return totalBytes / 8
}

// IsExpired returns true if the DNSSL option has expired.
func (d *DNSSLOption) IsExpired() bool {
	if d == nil {
		return true
	}
	return d.Lifetime == 0
}

// RemainingLifetime returns the remaining lifetime.
func (d *DNSSLOption) RemainingLifetime(receivedAt time.Time) time.Duration {
	if d == nil {
		return 0
	}
	return remainingLifetimeAt(d.Lifetime, receivedAt, time.Now())
}

// String returns a human-readable representation.
func (d *DNSSLOption) String() string {
	if d == nil {
		return "DNSSL{}"
	}
	return fmt.Sprintf("DNSSL{lifetime=%d domains=%v}", d.Lifetime, d.SearchDomains)
}

// ============================================================================
// DNS Configuration Container
// ============================================================================

// DNSConfig holds complete DNS configuration from router advertisements.
type DNSConfig struct {
	// RDNSS contains RDNSS options
	RDNSS []*RDNSSOption

	// DNSSL contains DNSSL options
	DNSSL []*DNSSLOption

	// SourcedAt is when this configuration was received
	SourcedAt time.Time
}

// NewDNSConfig creates a new DNS configuration.
func NewDNSConfig() *DNSConfig {
	return &DNSConfig{
		RDNSS:     make([]*RDNSSOption, 0),
		DNSSL:     make([]*DNSSLOption, 0),
		SourcedAt: time.Now(),
	}
}

// AddRDNSS adds an RDNSS option.
func (dc *DNSConfig) AddRDNSS(opt *RDNSSOption) {
	if dc == nil {
		return
	}
	dc.RDNSS = append(dc.RDNSS, opt)
}

// AddDNSSL adds a DNSSL option.
func (dc *DNSConfig) AddDNSSL(opt *DNSSLOption) {
	if dc == nil {
		return
	}
	dc.DNSSL = append(dc.DNSSL, opt)
}

// GetServers returns all unique DNS servers from RDNSS options.
func (dc *DNSConfig) GetServers() []net.IP {
	if dc == nil {
		return nil
	}
	seen := make(map[string]bool)
	var servers []net.IP

	for _, rdnss := range dc.RDNSS {
		if rdnss == nil {
			continue
		}
		for _, server := range rdnss.Servers {
			addrStr := server.String()
			if !seen[addrStr] {
				seen[addrStr] = true
				servers = append(servers, append(net.IP(nil), server...))
			}
		}
	}

	return servers
}

// GetSearchDomains returns all unique search domains from DNSSL options.
func (dc *DNSConfig) GetSearchDomains() []string {
	if dc == nil {
		return nil
	}
	seen := make(map[string]bool)
	var domains []string

	for _, dnssl := range dc.DNSSL {
		if dnssl == nil {
			continue
		}
		for _, domain := range dnssl.SearchDomains {
			if !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// IsEmpty returns true if no DNS configuration is present.
func (dc *DNSConfig) IsEmpty() bool {
	if dc == nil {
		return true
	}
	return len(dc.RDNSS) == 0 && len(dc.DNSSL) == 0
}

// RemoveExpired removes expired options.
func (dc *DNSConfig) RemoveExpired() {
	if dc == nil {
		return
	}
	// Filter RDNSS
	var validRDNSS []*RDNSSOption
	for _, r := range dc.RDNSS {
		if !r.IsExpired() {
			validRDNSS = append(validRDNSS, r)
		}
	}
	dc.RDNSS = validRDNSS

	// Filter DNSSL
	var validDNSSL []*DNSSLOption
	for _, d := range dc.DNSSL {
		if !d.IsExpired() {
			validDNSSL = append(validDNSSL, d)
		}
	}
	dc.DNSSL = validDNSSL
}
