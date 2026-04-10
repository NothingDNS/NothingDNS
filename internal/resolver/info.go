// Package resolver provides DNS resolution functionality.
// This file implements RFC 9606 - Resolver Information (RESPInfo).
// RESPInfo provides a mechanism for DNS resolvers to advertise their
// capabilities and configuration to clients.
package resolver

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ResolverInfoType represents the type of resolver information.
type ResolverInfoType uint8

const (
	ResolverInfoTypeBasic    ResolverInfoType = 0
	ResolverInfoTypeExtended ResolverInfoType = 1
)

// ResolverInfoOption represents a resolver information option.
type ResolverInfoOption struct {
	// Type is the type of resolver information
	Type ResolverInfoType

	// TTL is the time-to-live for this information
	TTL time.Duration

	// Information about the resolver
	ResolverInfo *ResolverInfo
}

// ResolverInfo contains basic information about a DNS resolver.
type ResolverInfo struct {
	// Version is the version of the resolver
	Version string

	// ID is an identifier for this resolver (e.g., hostname)
	ID string

	// Capabilities describes what the resolver supports
	Capabilities []string

	// DNSSecValidation indicates if DNSSEC validation is enabled
	DNSSecValidation bool

	// FilteringEnabled indicates if filtering is enabled
	FilteringEnabled bool

	// CacheSize is the cache size in entries (0 = unknown)
	CacheSize uint32

	// Upstreams is the list of upstream resolvers
	Upstreams []string
}

// BasicResolverInfo creates a basic resolver info structure.
func BasicResolverInfo(id string, capabilities []string) *ResolverInfo {
	return &ResolverInfo{
		Version:      "1.0",
		ID:           id,
		Capabilities: append([]string(nil), capabilities...),
	}
}

// ExtendedResolverInfo creates an extended resolver info structure.
func ExtendedResolverInfo(id string, version string, dnssec bool, filtering bool, cacheSize uint32, upstreams []string) *ResolverInfo {
	return &ResolverInfo{
		Version:          version,
		ID:               id,
		Capabilities:     nil,
		DNSSecValidation: dnssec,
		FilteringEnabled: filtering,
		CacheSize:        cacheSize,
		Upstreams:        append([]string(nil), upstreams...),
	}
}

// AddCapability adds a capability to the resolver info.
func (ri *ResolverInfo) AddCapability(cap string) {
	for _, c := range ri.Capabilities {
		if c == cap {
			return // Already present
		}
	}
	ri.Capabilities = append(ri.Capabilities, cap)
}

// HasCapability checks if a capability is present.
func (ri *ResolverInfo) HasCapability(cap string) bool {
	for _, c := range ri.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// Validate checks if the resolver info is valid.
func (ri *ResolverInfo) Validate() error {
	if ri == nil {
		return fmt.Errorf("nil resolver info")
	}

	if ri.ID == "" {
		return fmt.Errorf("missing resolver ID")
	}

	return nil
}

// ResolverInfoOptionCodes for RESPInfo.
const (
	ResponderOptionCodeResolverInfo = 1
	ResponderOptionCodeExtendedInfo = 2
	ResponderOptionCodeCacheInfo    = 3
	ResponderOptionCodeUpstreamInfo = 4
)

// RESPInfoWireFormat represents RESPInfo in wire format.
type RESPInfoWireFormat struct {
	// Information Type
	InfoType uint8

	// TTL
	TTL uint32

	// The resolver information data
	Data []byte
}

// ToWire converts RESPInfo to wire format.
func (ri *ResolverInfo) ToWire(infoType uint8, ttl uint32) (*RESPInfoWireFormat, error) {
	var data []byte

	switch infoType {
	case ResponderOptionCodeResolverInfo:
		data = ri.serializeBasic()
	case ResponderOptionCodeExtendedInfo:
		data = ri.serializeExtended()
	default:
		return nil, fmt.Errorf("unknown info type: %d", infoType)
	}

	return &RESPInfoWireFormat{
		InfoType: infoType,
		TTL:      ttl,
		Data:     data,
	}, nil
}

// serializeBasic serializes basic resolver info.
func (ri *ResolverInfo) serializeBasic() []byte {
	var data []byte

	// ID as length-prefixed string
	idBytes := []byte(ri.ID)
	data = append(data, byte(len(idBytes)))
	data = append(data, idBytes...)

	// Version as length-prefixed string
	versionBytes := []byte(ri.Version)
	data = append(data, byte(len(versionBytes)))
	data = append(data, versionBytes...)

	return data
}

// serializeExtended serializes extended resolver info.
func (ri *ResolverInfo) serializeExtended() []byte {
	var data []byte

	// ID
	idBytes := []byte(ri.ID)
	data = append(data, byte(len(idBytes)))
	data = append(data, idBytes...)

	// Version
	versionBytes := []byte(ri.Version)
	data = append(data, byte(len(versionBytes)))
	data = append(data, versionBytes...)

	// DNSSEC validation flag
	if ri.DNSSecValidation {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	// Filtering enabled flag
	if ri.FilteringEnabled {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	// Cache size (4 bytes)
	data = append(data, byte(ri.CacheSize>>24))
	data = append(data, byte(ri.CacheSize>>16))
	data = append(data, byte(ri.CacheSize>>8))
	data = append(data, byte(ri.CacheSize))

	// Number of upstreams
	data = append(data, byte(len(ri.Upstreams)))

	// Upstream addresses
	for _, upstream := range ri.Upstreams {
		// Check if it's an IP or hostname
		if ip := net.ParseIP(upstream); ip != nil {
			// IP address - mark with prefix
			if ip.To4() != nil {
				data = append(data, 4) // IPv4 marker
				data = append(data, ip.To4()...)
			} else {
				data = append(data, 6) // IPv6 marker
				data = append(data, ip.To16()...)
			}
		} else {
			// Hostname - length-prefixed
			data = append(data, byte(len(upstream)))
			data = append(data, []byte(upstream)...)
		}
	}

	return data
}

// ParseRESPInfo parses RESPInfo from wire format.
func ParseRESPInfo(infoType uint8, data []byte) (*ResolverInfo, error) {
	switch infoType {
	case ResponderOptionCodeResolverInfo:
		return parseBasicRESPInfo(data)
	case ResponderOptionCodeExtendedInfo:
		return parseExtendedRESPInfo(data)
	default:
		return nil, fmt.Errorf("unknown info type: %d", infoType)
	}
}

// parseBasicRESPInfo parses basic resolver info from wire format.
func parseBasicRESPInfo(data []byte) (*ResolverInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short for basic respinfo")
	}

	offset := 0

	// ID
	idLen := int(data[offset])
	offset++
	if offset+idLen > len(data) {
		return nil, fmt.Errorf("truncated ID")
	}
	id := string(data[offset : offset+idLen])
	offset += idLen

	// Version
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated version")
	}
	versionLen := int(data[offset])
	offset++
	if offset+versionLen > len(data) {
		return nil, fmt.Errorf("truncated version")
	}
	version := string(data[offset : offset+versionLen])
	offset += versionLen

	return &ResolverInfo{
		ID:      id,
		Version: version,
	}, nil
}

// parseExtendedRESPInfo parses extended resolver info from wire format.
func parseExtendedRESPInfo(data []byte) (*ResolverInfo, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for extended respinfo")
	}

	offset := 0

	// ID
	idLen := int(data[offset])
	offset++
	if offset+idLen > len(data) {
		return nil, fmt.Errorf("truncated ID")
	}
	id := string(data[offset : offset+idLen])
	offset += idLen

	// Version
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated version")
	}
	versionLen := int(data[offset])
	offset++
	if offset+versionLen > len(data) {
		return nil, fmt.Errorf("truncated version")
	}
	version := string(data[offset : offset+versionLen])
	offset += versionLen

	// DNSSEC flag
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated DNSSEC flag")
	}
	dnssec := data[offset] != 0
	offset++

	// Filtering flag
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated filtering flag")
	}
	filtering := data[offset] != 0
	offset++

	// Cache size
	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated cache size")
	}
	cacheSize := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4

	// Number of upstreams
	if offset >= len(data) {
		return nil, fmt.Errorf("truncated upstream count")
	}
	upstreamCount := int(data[offset])
	offset++

	// Upstreams
	upstreams := make([]string, 0, upstreamCount)
	for i := 0; i < upstreamCount; i++ {
		if offset >= len(data) {
			break
		}
		marker := data[offset]
		offset++

		if marker == 4 {
			// IPv4
			if offset+4 > len(data) {
				break
			}
			ip := net.IP(data[offset : offset+4])
			upstreams = append(upstreams, ip.String())
			offset += 4
		} else if marker == 6 {
			// IPv6
			if offset+16 > len(data) {
				break
			}
			ip := net.IP(data[offset : offset+16])
			upstreams = append(upstreams, ip.String())
			offset += 16
		} else {
			// Hostname
			hostnameLen := int(marker)
			if offset+hostnameLen > len(data) {
				break
			}
			hostname := string(data[offset : offset+hostnameLen])
			upstreams = append(upstreams, hostname)
			offset += hostnameLen
		}
	}

	return &ResolverInfo{
		ID:               id,
		Version:          version,
		DNSSecValidation: dnssec,
		FilteringEnabled: filtering,
		CacheSize:        cacheSize,
		Upstreams:        upstreams,
	}, nil
}

// String returns a human-readable representation.
func (ri *ResolverInfo) String() string {
	var parts []string
	if ri.ID != "" {
		parts = append(parts, fmt.Sprintf("id=%s", ri.ID))
	}
	if ri.Version != "" {
		parts = append(parts, fmt.Sprintf("version=%s", ri.Version))
	}
	if ri.DNSSecValidation {
		parts = append(parts, "dnssec")
	}
	if ri.FilteringEnabled {
		parts = append(parts, "filtering")
	}
	if len(ri.Capabilities) > 0 {
		parts = append(parts, fmt.Sprintf("caps=%v", ri.Capabilities))
	}
	if len(ri.Upstreams) > 0 {
		parts = append(parts, fmt.Sprintf("upstreams=%v", ri.Upstreams))
	}
	return "ResolverInfo{" + strings.Join(parts, " ") + "}"
}

// ResolverInfoFromCapabilities creates resolver info from a capabilities list.
func ResolverInfoFromCapabilities(id string, caps []string) *ResolverInfo {
	return &ResolverInfo{
		ID:           id,
		Version:      "1.0",
		Capabilities: caps,
	}
}
