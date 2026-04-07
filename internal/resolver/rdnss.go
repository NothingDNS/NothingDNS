// Package resolver provides DNS resolution functionality.
// This file implements RFC 8106 - IPv6 Router Advertisement Options for DNS Configuration.
// RDNSS (Recursive DNS Server) and DNSSL (DNS Search List) options allow
// IPv6 routers to advertise DNS configuration to clients.
package resolver

import (
	"fmt"
	"net"
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
		Lifetime: uint32(lifetime.Seconds()),
		Servers:  append([]net.IP(nil), servers...),
	}
}

// Validate checks if the RDNSS option is valid per RFC 8106.
func (r *RDNSSOption) Validate() error {
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
	// Calculate length: 1 (type) + 1 (length) + 4 (lifetime) + (16 * num_addrs)
	numAddrs := len(r.Servers)
	length := 1 + 1 + 4 + (16 * numAddrs)

	return &RDNSSOptionTLV{
		Type:      31, // RDNSS option type
		Length:    uint8(length / 8), // Length is in 8-byte units
		Lifetime:  r.Lifetime,
		Addresses: r.Servers,
	}
}

// ParseRDNSSOption parses an RDNSS option from TLV format.
func ParseRDNSSOption(tlv *RDNSSOptionTLV) (*RDNSSOption, error) {
	if tlv.Type != 31 {
		return nil, fmt.Errorf("RDNSS: invalid option type: %d", tlv.Type)
	}

	// Calculate expected length
	numAddrs := len(tlv.Addresses)
	expectedLength := uint8((1 + 1 + 4 + (16 * numAddrs)) / 8)
	if tlv.Length != expectedLength {
		return nil, fmt.Errorf("RDNSS: invalid length: expected %d, got %d", expectedLength, tlv.Length)
	}

	return &RDNSSOption{
		Lifetime: tlv.Lifetime,
		Servers:  tlv.Addresses,
	}, nil
}

// IsExpired returns true if the RDNSS option has expired.
func (r *RDNSSOption) IsExpired() bool {
	return r.Lifetime == 0
}

// RemainingLifetime returns the remaining lifetime based on when the option was received.
func (r *RDNSSOption) RemainingLifetime(receivedAt time.Time) time.Duration {
	if r.Lifetime == 0 {
		return 0
	}
	if r.Lifetime == 0xFFFFFFFF {
		return time.Duration(1<<32-1) * time.Second // Infinite
	}
	elapsed := time.Since(receivedAt)
	return time.Duration(r.Lifetime)*time.Second - elapsed
}

// String returns a human-readable representation.
func (r *RDNSSOption) String() string {
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
		Lifetime:     uint32(lifetime.Seconds()),
		SearchDomains: append([]string(nil), domains...),
	}
}

// Validate checks if the DNSSL option is valid per RFC 8106.
func (d *DNSSLOption) Validate() error {
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

	return nil
}

// ToTLV converts DNSSL option to TLV format for Router Advertisements.
func (d *DNSSLOption) ToTLV() *DNSSLTLV {
	// Calculate length: 1 (type) + 1 (length) + 4 (lifetime) + encoded_domains
	encodedLen := 0
	for _, domain := range d.SearchDomains {
		encodedLen += encodeDNSSLLabel(domain) // placeholder
	}
	encodedLen += 1 // null terminator

	length := 1 + 1 + 4 + encodedLen

	return &DNSSLTLV{
		Type:          32, // DNSSL option type
		Length:        uint8(length / 8),
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
	if tlv.Type != 32 {
		return nil, fmt.Errorf("DNSSL: invalid option type: %d", tlv.Type)
	}

	return &DNSSLOption{
		Lifetime:     tlv.Lifetime,
		SearchDomains: tlv.SearchDomains,
	}, nil
}

// encodeDNSSLLabel encodes a single domain label for DNSSL.
func encodeDNSSLLabel(label string) int {
	// Labels are encoded as: length byte + label bytes
	// Each label ends with a length byte, except the last which is 0
	return 1 + len(label)
}

// IsExpired returns true if the DNSSL option has expired.
func (d *DNSSLOption) IsExpired() bool {
	return d.Lifetime == 0
}

// RemainingLifetime returns the remaining lifetime.
func (d *DNSSLOption) RemainingLifetime(receivedAt time.Time) time.Duration {
	if d.Lifetime == 0 {
		return 0
	}
	if d.Lifetime == 0xFFFFFFFF {
		return time.Duration(1<<32-1) * time.Second
	}
	elapsed := time.Since(receivedAt)
	return time.Duration(d.Lifetime)*time.Second - elapsed
}

// String returns a human-readable representation.
func (d *DNSSLOption) String() string {
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
		RDNSS:    make([]*RDNSSOption, 0),
		DNSSL:    make([]*DNSSLOption, 0),
		SourcedAt: time.Now(),
	}
}

// AddRDNSS adds an RDNSS option.
func (dc *DNSConfig) AddRDNSS(opt *RDNSSOption) {
	dc.RDNSS = append(dc.RDNSS, opt)
}

// AddDNSSL adds a DNSSL option.
func (dc *DNSConfig) AddDNSSL(opt *DNSSLOption) {
	dc.DNSSL = append(dc.DNSSL, opt)
}

// GetServers returns all unique DNS servers from RDNSS options.
func (dc *DNSConfig) GetServers() []net.IP {
	seen := make(map[string]bool)
	var servers []net.IP

	for _, rdnss := range dc.RDNSS {
		for _, server := range rdnss.Servers {
			addrStr := server.String()
			if !seen[addrStr] {
				seen[addrStr] = true
				servers = append(servers, server)
			}
		}
	}

	return servers
}

// GetSearchDomains returns all unique search domains from DNSSL options.
func (dc *DNSConfig) GetSearchDomains() []string {
	seen := make(map[string]bool)
	var domains []string

	for _, dnssl := range dc.DNSSL {
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
	return len(dc.RDNSS) == 0 && len(dc.DNSSL) == 0
}

// RemoveExpired removes expired options.
func (dc *DNSConfig) RemoveExpired() {
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
