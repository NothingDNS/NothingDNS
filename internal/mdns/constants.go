// Package mdns implements Multicast DNS (mDNS) as specified in RFC 6762.
// mDNS is used for service discovery on the local network (.local domain).
package mdns

import (
	"net"
	"time"
)

// mDNS constants per RFC 6762.
const (
	// MDNSIPv4Address is the IPv4 multicast address for mDNS (224.0.0.251).
	MDNSIPv4Address = "224.0.0.251"
	// MDNSIPv6Address is the IPv6 multicast address for mDNS (ff02::fb).
	MDNSIPv6Address = "ff02::fb"
	// MDNSPort is the UDP port for mDNS (5353).
	MDNSPort = 5353
	// MDNSIPv4Group is the IPv4 multicast address as net.UDPAddr.
	MDNSIPv4Group = "224.0.0.251:5353"
	// MDNSIPv6Group is the IPv6 multicast address as net.UDPAddr.
	MDNSIPv6Group = "[ff02::fb]:5353"

	// Default TTL for mDNS records (RFC 6762 Section 10).
	DefaultTTL = 120 * time.Second
	// GoodbyeTTL is the TTL used for goodbye messages (0).
	GoodbyeTTL = 0

	// ProbeInterval is the interval between probes during conflict resolution.
	ProbeInterval = 250 * time.Millisecond
	// ProbeCount is the number of probes to send before claiming a name.
	ProbeCount = 3
	// AnnounceInterval is the interval between announcements.
	AnnounceInterval = 250 * time.Millisecond
	// AnnounceCount is the number of announcements to send.
	AnnounceCount = 3

	// Shared flag constants from RFC 6762.
	CacheFlushFlag = 0x8000 // Set in the cache flush bit of the TTL field
)

// Known service types per RFC 6763.
var KnownServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_dns._udp",
	"_dns._tcp",
	"_ssh._tcp",
	"_sftp._ssh",
	"_smb._tcp",
	"_afpovertcp._tcp",
	"_nfs._tcp",
	"_ipp._tcp",
	"_printer._tcp",
	"_pdl-datastream._tcp",
	"_daap._tcp",
	"_dacp._tcp",
	"_afportrait._tcp",
	"_touch-able._tcp",
	"_airplay._tcp",
	"_raop._tcp",
	"_device-info._tcp",
	"_companion-link._tcp",
	"_sleep-proxy._udp",
}

// Error definitions for mDNS operations.
var (
	ErrNoSuchService    = &mdnsError{"no such service"}
	ErrNameConflict      = &mdnsError{"name conflict"}
	ErrProbeTimeout      = &mdnsError{"probe timeout"}
	ErrInvalidPacket     = &mdnsError{"invalid packet"}
	ErrInvalidName       = &mdnsError{"invalid name"}
	ErrInvalidTTL        = &mdnsError{"invalid TTL"}
	ErrInvalidPort       = &mdnsError{"invalid port"}
)

type mdnsError struct{ msg string }

func (e *mdnsError) Error() string { return e.msg }

// MessageType represents the type of mDNS message.
type MessageType uint8

const (
	MessageTypeQuery     MessageType = iota // Standard query
	MessageTypeResponse                     // Response (answer)
	MessageTypeProbe                        // Probe (conflict detection)
	MessageTypeAnnounce                     // Announcement (claiming name)
)

// ServiceInstance represents a discovered mDNS service instance.
type ServiceInstance struct {
	Name       string            // Full service instance name (e.g., "My Printer._printer._tcp.local.")
	HostName   string            // Host providing the service
	Port       int               // Port number
	TXTRecords []string          // TXT record strings
	Priority   int               // SRV priority
	Weight     int               // SRV weight
	TTL        time.Duration     // Record TTL
	IPv4       []net.IP          // A records (IPv4 addresses)
	IPv6       []net.IP          // AAAA records (IPv6 addresses)
}

// ResolvedService contains all information about a resolved service.
type ResolvedService struct {
	Instance ServiceInstance
	IPv4     []net.IP           // A records
	IPv6     []net.IP           // AAAA records
}

// Question represents an mDNS question.
type Question struct {
	Name string
	Type uint16 // Queried record type
}

// ResourceRecord represents an mDNS resource record.
type ResourceRecord struct {
	Name    string
	Type    uint16
	Class   uint16
	TTL     time.Duration
	RDLength uint16
	RData   []byte
}

// Query represents an mDNS query message.
type Query struct {
	ID       uint16
 Questions []Question
}

// Response represents an mDNS response message.
type Response struct {
	ID       uint16
Answers   []ResourceRecord
Authority []ResourceRecord
}