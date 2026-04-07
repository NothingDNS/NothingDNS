// Package mdns implements Multicast DNS (mDNS) as specified in RFC 6762.
package mdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Querier sends mDNS queries and handles responses.
type Querier struct {
	iface     *net.Interface
	conn      *net.UDPConn
	handlers  map[uint16][]ResponseHandler
	mu        sync.RWMutex
	closed    bool
}

// ResponseHandler is called when an mDNS response is received.
type ResponseHandler func(*Response)

// NewQuerier creates a new mDNS querier on the specified interface.
func NewQuerier(iface *net.Interface) (*Querier, error) {
	q := &Querier{
		iface:    iface,
		handlers: make(map[uint16][]ResponseHandler),
	}

	// Create UDP connection for mDNS
	addr := &net.UDPAddr{
		IP:   net.ParseIP(MDNSIPv4Address),
		Port: MDNSPort,
	}

	conn, err := net.ListenMulticastUDP("udp4", iface, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on mDNS multicast: %w", err)
	}
	q.conn = conn

	return q, nil
}

// Close closes the querier and releases resources.
func (q *Querier) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true
	return q.conn.Close()
}

// Query sends an mDNS query and waits for responses.
func (q *Querier) Query(ctx context.Context, name string, qtype uint16) ([]*Response, error) {
	if qtype == 0 {
		qtype = TypePTR // Default to PTR for service discovery
	}

	query := &Query{
		ID:       generateQueryID(),
		Questions: []Question{{Name: name, Type: qtype}},
	}

	packet, err := q.buildQueryPacket(query)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	// Send query
	if err := q.sendQuery(packet); err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Collect responses
	var responses []*Response
	respCh := make(chan *Response, 10)

	handler := func(resp *Response) {
		select {
		case respCh <- resp:
		default:
		}
	}

	q.addHandler(query.ID, handler)
	defer q.removeHandler(query.ID, handler)

	// Wait for responses with timeout
	for {
		select {
		case <-ctx.Done():
			return responses, nil
		case resp := <-respCh:
			responses = append(responses, resp)
		}
	}
}

// QueryService discovers services of a given type.
// For example, "_printer._tcp.local" for DNS-SD browsing (RFC 6763).
func (q *Querier) QueryService(ctx context.Context, serviceType string) ([]*ServiceInstance, error) {
	// Send PTR query for service type
	responses, err := q.Query(ctx, serviceType, TypePTR)
	if err != nil {
		return nil, err
	}

	var instances []*ServiceInstance
	for _, resp := range responses {
		for _, rr := range resp.Answers {
			if rr.Type == TypePTR {
				instanceName := extractNameFromPTR(rr.RData)
				if instanceName != "" {
					// Resolve the service instance
					instance, err := q.ResolveServiceInstance(ctx, instanceName, 5*time.Second)
					if err == nil {
						instances = append(instances, instance)
					}
				}
			}
		}
	}

	return instances, nil
}

// ResolveServiceInstance resolves a service instance to get SRV and TXT records.
func (q *Querier) ResolveServiceInstance(ctx context.Context, instanceName string, timeout time.Duration) (*ServiceInstance, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}

	queryCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Query for SRV record
	srvResponses, err := q.Query(queryCtx, instanceName, TypeSRV)
	if err != nil {
		return nil, fmt.Errorf("SRV query failed: %w", err)
	}

	if len(srvResponses) == 0 {
		return nil, ErrNoSuchService
	}

	// Parse SRV record
	var instance ServiceInstance
	instance.Name = instanceName

	for _, resp := range srvResponses {
		for _, rr := range resp.Answers {
			if rr.Type == TypeSRV {
				host, port := extractSRVData(rr.RData)
				instance.HostName = host
				instance.Port = int(port)
			}
		}
	}

	// Query for TXT record
	txtResponses, err := q.Query(queryCtx, instanceName, TypeTXT)
	if err == nil && len(txtResponses) > 0 {
		for _, resp := range txtResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeTXT {
					instance.TXTRecords = extractTXTData(rr.RData)
				}
			}
		}
	}

	// Query for A/AAAA records to get IP addresses
	if instance.HostName != "" {
		_ = q.resolveHostIPs(queryCtx, &instance)
	}

	return &instance, nil
}

// resolveHostIPs resolves host name to A and AAAA records.
func (q *Querier) resolveHostIPs(ctx context.Context, instance *ServiceInstance) error {
	// Query A record
	aResponses, err := q.Query(ctx, instance.HostName, TypeA)
	if err == nil && len(aResponses) > 0 {
		for _, resp := range aResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeA && len(rr.RData) == 4 {
					instance.IPv4 = append(instance.IPv4, net.IP(rr.RData))
				}
			}
		}
	}

	// Query AAAA record
	aaaaResponses, err := q.Query(ctx, instance.HostName, TypeAAAA)
	if err == nil && len(aaaaResponses) > 0 {
		for _, resp := range aaaaResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeAAAA && len(rr.RData) == 16 {
					instance.IPv6 = append(instance.IPv6, net.IP(rr.RData))
				}
			}
		}
	}

	return nil
}

// QueryHost resolves a host name to IP addresses using mDNS.
func (q *Querier) QueryHost(ctx context.Context, hostName string) ([]net.IP, error) {
	var ips []net.IP

	// Query A records
	aResponses, err := q.Query(ctx, hostName, TypeA)
	if err == nil {
		for _, resp := range aResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeA && len(rr.RData) == 4 {
					ips = append(ips, net.IP(rr.RData))
				}
			}
		}
	}

	// Query AAAA records
	aaaaResponses, err := q.Query(ctx, hostName, TypeAAAA)
	if err == nil {
		for _, resp := range aaaaResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeAAAA && len(rr.RData) == 16 {
					ips = append(ips, net.IP(rr.RData))
				}
			}
		}
	}

	return ips, nil
}

// AddHandler adds a response handler for a query ID.
func (q *Querier) addHandler(id uint16, handler ResponseHandler) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handlers[id] = append(q.handlers[id], handler)
}

// removeHandler removes a response handler.
func (q *Querier) removeHandler(id uint16, handler ResponseHandler) {
	q.mu.Lock()
	defer q.mu.Unlock()
	handlers := q.handlers[id]
	for i, h := range handlers {
		if fmt.Sprintf("%p", h) == fmt.Sprintf("%p", handler) {
			q.handlers[id] = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}
}

// buildQueryPacket builds the wire format of an mDNS query.
func (q *Querier) buildQueryPacket(query *Query) ([]byte, error) {
	var buf bytes.Buffer

	// Header (12 bytes)
	// ID (2 bytes) - 0 for mDNS queries
	buf.Write([]byte{0, 0})
	// Flags (2 bytes) - standard query
	buf.Write([]byte{0, 0})
	// Question count (2 bytes)
	binary.Write(&buf, binary.BigEndian, uint16(len(query.Questions)))
	// Answer count (2 bytes) - 0 for queries
	buf.Write([]byte{0, 0})
	// Authority count (2 bytes) - 0
	buf.Write([]byte{0, 0})
	// Additional count (2 bytes) - 0
	buf.Write([]byte{0, 0})

	// Questions
	for _, q := range query.Questions {
		name := q.Name
		if !hasLocalSuffix(name) {
			name = name + ".local"
		}
		if err := writeLabelSequence(&buf, name); err != nil {
			return nil, err
		}
		buf.WriteByte(0) // End label

		// QType (2 bytes)
		binary.Write(&buf, binary.BigEndian, q.Type)
		// QClass (2 bytes) - IN class with QU flag (0x8000)
		binary.Write(&buf, binary.BigEndian, uint16(ClassIN|0x8000))
	}

	return buf.Bytes(), nil
}

// sendQuery sends an mDNS query packet.
func (q *Querier) sendQuery(packet []byte) error {
	_, err := q.conn.WriteToUDP(packet, &net.UDPAddr{
		IP:   net.ParseIP(MDNSIPv4Address),
		Port: MDNSPort,
	})
	return err
}

// hasLocalSuffix checks if a name ends with .local.
func hasLocalSuffix(name string) bool {
	return len(name) > 6 && name[len(name)-6:] == ".local"
}

// generateQueryID generates a pseudo-random query ID.
func generateQueryID() uint16 {
	return uint16(time.Now().UnixNano() & 0xFFFF)
}

// writeLabelSequence writes a domain name in label format.
func writeLabelSequence(buf *bytes.Buffer, name string) error {
	labels := splitDomain(name)
	for _, label := range labels {
		if len(label) > 63 {
			return ErrLabelTooLong
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	return nil
}

// splitDomain splits a domain into labels.
func splitDomain(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

// extractNameFromPTR extracts the name from a PTR record's rdata.
func extractNameFromPTR(rdata []byte) string {
	if len(rdata) == 0 {
		return ""
	}
	// Parse wire format name from rdata
	name, _, err := unpackName(rdata, 0)
	if err != nil {
		return ""
	}
	return name
}

// extractSRVData extracts hostname and port from SRV rdata.
func extractSRVData(rdata []byte) (string, uint16) {
	if len(rdata) < 4 {
		return "", 0
	}
	// Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target
	port := binary.BigEndian.Uint16(rdata[4:6])

	// Target starts at offset 6
	target, _, err := unpackName(rdata, 6)
	if err != nil {
		return "", port
	}

	return target, port
}

// extractTXTData extracts TXT record strings from rdata.
func extractTXTData(rdata []byte) []string {
	var txts []string
	offset := 0
	for offset < len(rdata) {
		if offset >= len(rdata) {
			break
		}
		length := int(rdata[offset])
		offset++
		if offset+length > len(rdata) {
			break
		}
		txts = append(txts, string(rdata[offset:offset+length]))
		offset += length
	}
	return txts
}

// unpackName unpacks a wire format domain name.
func unpackName(buf []byte, offset int) (string, int, error) {
	if offset >= len(buf) {
		return "", 0, ErrInvalidPacket
	}

	var labels []string
	originalOffset := offset
	ptrCount := 0

	for {
		if offset >= len(buf) {
			return "", 0, ErrInvalidPacket
		}

		length := int(buf[offset])
		if length == 0 {
			offset++
			break
		}

		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(buf) {
				return "", 0, ErrInvalidPacket
			}
			ptr := int(buf[offset]&0x3F)<<8 | int(buf[offset+1])
			offset = ptr
			ptrCount++
			if ptrCount > 10 {
				return "", 0, errors.New("too many pointers")
			}
			continue
		}

		offset++
		if offset+length > len(buf) {
			return "", 0, ErrInvalidPacket
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}

	if len(labels) == 0 {
		return ".", offset - originalOffset, nil
	}

	return strings.Join(labels, "."), offset - originalOffset, nil
}

// Record type constants (matching DNS protocol types from protocol package).
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeHINFO = 13
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeOPT   = 41
	TypeNSEC  = 47
)

// Class constants.
const (
	ClassIN     = 1
	ClassCH     = 3
	ClassNONE   = 254
	ClassANY    = 255
)

// Error definitions.
var (
	ErrLabelTooLong = errors.New("label too long")
)