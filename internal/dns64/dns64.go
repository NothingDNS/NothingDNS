// Package dns64 implements DNS64 per RFC 6147 — synthesizing AAAA records
// from A records for IPv6-only clients behind a NAT64 gateway.
package dns64

import (
	"fmt"
	"net"
	"sync"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// validPrefixLengths contains the well-known prefix lengths from RFC 6052.
var validPrefixLengths = map[int]bool{
	32: true,
	40: true,
	48: true,
	56: true,
	64: true,
	96: true,
}

// Synthesizer creates synthetic AAAA records by embedding IPv4 addresses
// into a configurable NAT64 IPv6 prefix per RFC 6052.
type Synthesizer struct {
	prefix      net.IP
	prefixLen   int
	excludeNets []*net.IPNet
	enabled     bool
	mu          sync.RWMutex
}

// NewSynthesizer creates a DNS64 synthesizer with the given NAT64 prefix and
// prefix length. If prefix is empty, defaults to "64:ff9b::" with length 96.
// The prefixLen must be one of: 32, 40, 48, 56, 64, 96 (RFC 6052).
func NewSynthesizer(prefix string, prefixLen int) (*Synthesizer, error) {
	if prefix == "" {
		prefix = "64:ff9b::"
	}
	if prefixLen == 0 {
		prefixLen = 96
	}

	if !validPrefixLengths[prefixLen] {
		return nil, fmt.Errorf("invalid prefix length %d: must be one of 32, 40, 48, 56, 64, 96", prefixLen)
	}

	ip := net.ParseIP(prefix)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("prefix is not a valid IPv6 address: %q", prefix)
	}
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("prefix is not a valid IPv6 address: %q", prefix)
	}

	return &Synthesizer{
		prefix:    ip,
		prefixLen: prefixLen,
		enabled:   true,
	}, nil
}

// SynthesizeAAAA embeds an IPv4 address into the NAT64 prefix per RFC 6052.
// Returns nil if ipv4 is not a valid 4-byte IPv4 address.
func (s *Synthesizer) SynthesizeAAAA(ipv4 net.IP) net.IP {
	if s == nil {
		return nil
	}

	v4 := ipv4.To4()
	if v4 == nil {
		return nil
	}

	s.mu.RLock()
	pfx := s.prefix
	pfxLen := s.prefixLen
	s.mu.RUnlock()

	result := make(net.IP, 16)
	copy(result, pfx)

	switch pfxLen {
	case 96:
		// bytes 0-11 from prefix, bytes 12-15 from IPv4
		result[12] = v4[0]
		result[13] = v4[1]
		result[14] = v4[2]
		result[15] = v4[3]
	case 64:
		// bytes 0-7 from prefix, byte 8 = 0, bytes 9-12 from IPv4, bytes 13-15 = 0
		result[8] = 0
		result[9] = v4[0]
		result[10] = v4[1]
		result[11] = v4[2]
		result[12] = v4[3]
		result[13] = 0
		result[14] = 0
		result[15] = 0
	case 56:
		// bytes 0-6 from prefix, byte 7 = IPv4[0], byte 8 = 0,
		// bytes 9-11 = IPv4[1:4], bytes 12-15 = 0
		result[7] = v4[0]
		result[8] = 0
		result[9] = v4[1]
		result[10] = v4[2]
		result[11] = v4[3]
		result[12] = 0
		result[13] = 0
		result[14] = 0
		result[15] = 0
	case 48:
		// bytes 0-5 from prefix, bytes 6-7 = IPv4[0:2], byte 8 = 0,
		// bytes 9-10 = IPv4[2:4], bytes 11-15 = 0
		result[6] = v4[0]
		result[7] = v4[1]
		result[8] = 0
		result[9] = v4[2]
		result[10] = v4[3]
		result[11] = 0
		result[12] = 0
		result[13] = 0
		result[14] = 0
		result[15] = 0
	case 40:
		// bytes 0-4 from prefix, bytes 5-7 = IPv4[0:3], byte 8 = 0,
		// byte 9 = IPv4[3], bytes 10-15 = 0
		result[5] = v4[0]
		result[6] = v4[1]
		result[7] = v4[2]
		result[8] = 0
		result[9] = v4[3]
		result[10] = 0
		result[11] = 0
		result[12] = 0
		result[13] = 0
		result[14] = 0
		result[15] = 0
	case 32:
		// bytes 0-3 from prefix, bytes 4-7 = IPv4, byte 8 = 0, bytes 9-15 = 0
		result[4] = v4[0]
		result[5] = v4[1]
		result[6] = v4[2]
		result[7] = v4[3]
		result[8] = 0
		result[9] = 0
		result[10] = 0
		result[11] = 0
		result[12] = 0
		result[13] = 0
		result[14] = 0
		result[15] = 0
	}

	return result
}

// ExtractIPv4 reverses SynthesizeAAAA: it extracts the embedded IPv4 address
// from a synthesized IPv6 address. Returns nil if ipv6 does not match the
// configured prefix.
func (s *Synthesizer) ExtractIPv4(ipv6 net.IP) net.IP {
	if s == nil {
		return nil
	}

	v6 := ipv6.To16()
	if v6 == nil {
		return nil
	}

	s.mu.RLock()
	pfx := s.prefix
	pfxLen := s.prefixLen
	s.mu.RUnlock()

	// Verify the prefix bytes match.
	prefixBytes := pfxLen / 8
	for i := 0; i < prefixBytes; i++ {
		if v6[i] != pfx[i] {
			return nil
		}
	}

	v4 := make(net.IP, 4)

	switch pfxLen {
	case 96:
		v4[0] = v6[12]
		v4[1] = v6[13]
		v4[2] = v6[14]
		v4[3] = v6[15]
	case 64:
		v4[0] = v6[9]
		v4[1] = v6[10]
		v4[2] = v6[11]
		v4[3] = v6[12]
	case 56:
		v4[0] = v6[7]
		v4[1] = v6[9]
		v4[2] = v6[10]
		v4[3] = v6[11]
	case 48:
		v4[0] = v6[6]
		v4[1] = v6[7]
		v4[2] = v6[9]
		v4[3] = v6[10]
	case 40:
		v4[0] = v6[5]
		v4[1] = v6[6]
		v4[2] = v6[7]
		v4[3] = v6[9]
	case 32:
		v4[0] = v6[4]
		v4[1] = v6[5]
		v4[2] = v6[6]
		v4[3] = v6[7]
	}

	return v4
}

// ShouldSynthesize reports whether a DNS64 synthesis should be performed.
// It returns true when all of the following hold:
//   - DNS64 is enabled
//   - The question asks for AAAA records
//   - The response contains no AAAA answers (or is NXDOMAIN / NOERROR without AAAA)
func (s *Synthesizer) ShouldSynthesize(question *protocol.Question, response *protocol.Message) bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	enabled := s.enabled
	s.mu.RUnlock()

	if !enabled {
		return false
	}

	if question == nil || response == nil {
		return false
	}

	// Only synthesize for AAAA queries.
	if question.QType != protocol.TypeAAAA {
		return false
	}

	// If the response already contains AAAA answers, no synthesis needed.
	for _, rr := range response.Answers {
		if rr == nil {
			continue
		}
		if rr.Type == protocol.TypeAAAA {
			return false
		}
	}

	// Synthesis is appropriate only for a NOERROR/NODATA AAAA response (the name
	// exists but has no AAAA). An NXDOMAIN means the name has NO records of any
	// type, so there is nothing to synthesize from and turning it into a
	// NOERROR + synthetic AAAA would contradict the authoritative answer
	// (RFC 6147 §5.1.7). Return NXDOMAIN as-is.
	return response.Header.Flags.RCODE == protocol.RcodeSuccess
}

// SynthesizeResponse creates a synthetic AAAA response from an A record response.
// It copies the header, converts each A answer to a synthesized AAAA answer,
// preserves TTLs, and sets the question type to AAAA.
func (s *Synthesizer) SynthesizeResponse(originalQuestion *protocol.Question, aResponse *protocol.Message) *protocol.Message {
	if s == nil || originalQuestion == nil || originalQuestion.Name == nil || aResponse == nil {
		return nil
	}

	// RFC 6147 §5.5: a DNS64 synthesiser MUST NOT set AD on the synthesised
	// AAAA, because it cannot validate the synthesised record — only the
	// source A. Carry over the RCODE/RA/RD/QR/Opcode but clear AD.
	flags := aResponse.Header.Flags
	flags.AD = false
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    aResponse.Header.ID,
			Flags: flags,
		},
		Questions:   make([]*protocol.Question, 0, 1),
		Answers:     make([]*protocol.ResourceRecord, 0, len(aResponse.Answers)),
		Authorities: make([]*protocol.ResourceRecord, 0),
		Additionals: make([]*protocol.ResourceRecord, 0),
	}

	// Set the question section with AAAA type.
	msg.Questions = append(msg.Questions, &protocol.Question{
		Name:   originalQuestion.Name.Copy(),
		QType:  protocol.TypeAAAA,
		QClass: originalQuestion.QClass,
	})
	msg.Header.QDCount = 1

	// Synthesize AAAA records from A records, preserving the CNAME/DNAME
	// chain. RFC 6147 §5.3.1: when the A response was reached through a
	// CNAME (or DNAME) chain, the chain MUST appear in the synthesized
	// answer — without it the synthesized AAAAs are owned by the canonical
	// name and strict stub resolvers cannot link them to the queried name.
	for _, rr := range aResponse.Answers {
		if rr == nil || rr.Name == nil {
			continue
		}
		if rr.Type == protocol.TypeCNAME || rr.Type == protocol.TypeDNAME {
			msg.Answers = append(msg.Answers, rr.Copy())
			continue
		}
		if rr.Type != protocol.TypeA {
			continue
		}
		aData, ok := rr.Data.(*protocol.RDataA)
		if !ok || aData == nil {
			continue
		}

		ipv4 := net.IP(aData.Address[:])
		// RFC 6147 §5.1.4: never synthesize for an A record whose address is in
		// a configured exclusion range. The exclusion list was configurable but
		// never consulted, so every A record got synthesized regardless.
		if s.IsExcluded(ipv4) {
			continue
		}
		synthesized := s.SynthesizeAAAA(ipv4)
		if synthesized == nil {
			continue
		}

		var addr [16]byte
		copy(addr[:], synthesized.To16())

		synRR := &protocol.ResourceRecord{
			Name:  rr.Name.Copy(),
			Type:  protocol.TypeAAAA,
			Class: protocol.ClassIN,
			TTL:   rr.TTL,
			Data:  &protocol.RDataAAAA{Address: addr},
		}
		msg.Answers = append(msg.Answers, synRR)
	}

	msg.Header.ANCount = uint16(len(msg.Answers))
	return msg
}

// AddExcludeNet adds a CIDR network to the exclusion list. AAAA responses with
// addresses in excluded networks pass through without synthesis.
func (s *Synthesizer) AddExcludeNet(cidr string) error {
	if s == nil {
		return fmt.Errorf("nil DNS64 synthesizer")
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	s.mu.Lock()
	s.excludeNets = append(s.excludeNets, ipnet)
	s.mu.Unlock()
	return nil
}

// IsExcluded reports whether ip falls within any of the configured exclusion
// networks.
func (s *Synthesizer) IsExcluded(ip net.IP) bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ipnet := range s.excludeNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// SetEnabled enables or disables DNS64 synthesis.
func (s *Synthesizer) SetEnabled(enabled bool) {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.enabled = enabled
	s.mu.Unlock()
}

// IsEnabled reports whether DNS64 synthesis is currently enabled.
func (s *Synthesizer) IsEnabled() bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}
