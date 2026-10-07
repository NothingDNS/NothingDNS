// Package mdns implements mDNS (RFC 6762) and DNS-SD (RFC 6763).
// Provides multicast DNS resolution for .local domains and service discovery.
package mdns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

const (
	// Default multicast address for IPv4 mDNS
	DefaultMulticastIP = "224.0.0.251"

	// Default mDNS port
	DefaultPort = 5353

	// mDNS TTL values per RFC 6762
	DefaultTTL  = 120  // seconds - for most records
	HostnameTTL = 120  // seconds - for hostnames
	ServiceTTL  = 4500 // seconds - for service instances (75 minutes)
	PtrTTL      = 4500 // seconds - for PTR records

	// Probe interval and timeouts
	ProbeInterval = 250 * time.Millisecond
	ProbeTimeout  = 3 * time.Second
	AnnounceDelay = 1 * time.Second
)

// Service represents an mDNS service instance (DNS-SD).
type Service struct {
	InstanceName string            // Human-readable name (e.g., "My Printer")
	ServiceType  string            // Service type (e.g., "_http._tcp")
	Domain       string            // Usually "local"
	HostName     string            // Target hostname (e.g., "myprinter.local")
	Port         int               // Service port
	TXT          map[string]string // TXT record key-value pairs
	TTL          uint32
}

// FullServiceName returns the full DNS-SD service instance name.
func (s *Service) FullServiceName() string {
	return fmt.Sprintf("%s.%s.%s.", s.InstanceName, s.ServiceType, s.Domain)
}

// ServiceTypeName returns the service type enumeration name.
func (s *Service) ServiceTypeName() string {
	return fmt.Sprintf("%s.%s.", s.ServiceType, s.Domain)
}

func cloneService(s *Service) *Service {
	if s == nil {
		return nil
	}
	clone := *s
	if s.TXT != nil {
		clone.TXT = make(map[string]string, len(s.TXT))
		for k, v := range s.TXT {
			clone.TXT[k] = v
		}
	}
	return &clone
}

// Responder implements an mDNS responder for .local domains.
type Responder struct {
	// Configuration
	config Config

	// UDP connection for multicast
	conn *net.UDPConn

	// Services we advertise
	services   map[string]*Service
	servicesMu sync.RWMutex

	// Local hostnames we respond for
	hostnames   map[string]net.IP
	hostnamesMu sync.RWMutex

	// Cache for discovered services (browser mode)
	cache   *Cache
	cacheMu sync.RWMutex

	// Logger
	logger *util.Logger

	// Control channels
	lifecycleMu sync.Mutex
	stopCh      chan struct{}
	running     bool
	wg          sync.WaitGroup

	// Probe state for hostname claiming
	probedHostnames map[string]bool
	probeMu         sync.Mutex

	// Per-source response rate limiter (anti-reflection/amplification).
	respLimiter *mdnsResponseRateLimiter
}

// Config holds mDNS responder configuration.
type Config struct {
	Enabled     bool
	MulticastIP string
	Port        int
	HostName    string
	Browser     bool // Enable service discovery
	Interface   *net.Interface
}

// DefaultConfig returns default mDNS configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		MulticastIP: DefaultMulticastIP,
		Port:        DefaultPort,
		HostName:    "",
		Browser:     false,
	}
}

// NewResponder creates a new mDNS responder.
func NewResponder(config Config, logger *util.Logger) *Responder {
	if config.MulticastIP == "" {
		config.MulticastIP = DefaultMulticastIP
	}
	if config.Port == 0 {
		config.Port = DefaultPort
	}

	return &Responder{
		config:          config,
		services:        make(map[string]*Service),
		hostnames:       make(map[string]net.IP),
		cache:           NewCache(),
		logger:          logger,
		probedHostnames: make(map[string]bool),
		// 20 responses/sec per source with a burst of 40, up to 4096 tracked
		// sources — ample for legitimate link-local discovery, throttles a
		// spoofed-source reflection attempt.
		respLimiter: newMDNSResponseRateLimiter(20, 40, 4096),
	}
}

// Start starts the mDNS responder.
func (r *Responder) Start() error {
	if !r.config.Enabled {
		return nil
	}

	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	if r.running {
		return nil
	}

	// Join multicast group
	addr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}

	var (
		conn *net.UDPConn
		err  error
	)
	if r.config.Interface != nil {
		conn, err = net.ListenMulticastUDP("udp4", r.config.Interface, addr)
	} else {
		conn, err = net.ListenMulticastUDP("udp4", nil, addr)
	}
	if err != nil {
		return fmt.Errorf("failed to join multicast group: %w", err)
	}

	// Socket buffer tuning is best-effort; the responder can run with OS defaults.
	if err := conn.SetReadBuffer(65536); err != nil {
		util.Warnf("mDNS: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(65536); err != nil {
		util.Warnf("mDNS: failed to set write buffer: %v", err)
	}

	stopCh := make(chan struct{})
	r.conn = conn
	r.stopCh = stopCh
	r.running = true

	// Start listeners
	r.wg.Add(2)
	go r.receiveLoop(conn, stopCh)
	go r.maintenanceLoop(stopCh)

	if r.logger != nil {
		r.logger.Infof("mDNS responder started on %s:%d", r.config.MulticastIP, r.config.Port)
	}

	return nil
}

// Stop stops the mDNS responder.
func (r *Responder) Stop() {
	r.lifecycleMu.Lock()
	if !r.running {
		r.lifecycleMu.Unlock()
		return
	}

	stopCh := r.stopCh
	conn := r.conn
	r.stopCh = nil
	r.running = false

	close(stopCh)
	// Wait for every wg-tracked goroutine to exit BEFORE clearing or closing
	// the conn field. The send* path (sendMulticast and friends) reads r.conn
	// without taking lifecycleMu, so nil-ing it here raced with those readers.
	// sendMulticast cannot grab lifecycleMu itself to fix that: Stop holds the
	// mutex across this wg.Wait(), so a reader acquiring it here would
	// deadlock against the Wait. Clearing the field after the Wait orders every
	// reader (which lives inside a wg goroutine) before the write.
	r.wg.Wait()
	r.conn = nil
	if conn != nil {
		r.closeUDPConn(conn)
	}
	r.lifecycleMu.Unlock()

	if r.logger != nil {
		r.logger.Info("mDNS responder stopped")
	}
}

// RegisterService registers a service for advertisement.
func (r *Responder) RegisterService(svc *Service) error {
	if svc.Domain == "" {
		svc.Domain = "local"
	}
	if svc.TTL == 0 {
		svc.TTL = ServiceTTL
	}

	// Probe for hostname conflicts
	if err := r.probeHostname(svc.HostName); err != nil {
		return fmt.Errorf("hostname probe failed: %w", err)
	}

	r.servicesMu.Lock()
	r.services[svc.FullServiceName()] = svc
	r.servicesMu.Unlock()

	// Send announcement
	r.announceService(svc)

	if r.logger != nil {
		r.logger.Infof("mDNS: registered service %s", svc.FullServiceName())
	}

	return nil
}

// UnregisterService removes a service from advertisement.
func (r *Responder) UnregisterService(fullName string) {
	r.servicesMu.Lock()
	svc := r.services[fullName]
	delete(r.services, fullName)
	r.servicesMu.Unlock()

	// Send goodbye packet (TTL=0)
	r.sendGoodbye(fullName, svc)

	if r.logger != nil {
		r.logger.Infof("mDNS: unregistered service %s", fullName)
	}
}

// RegisterHostname registers a local hostname with its IP address.
func (r *Responder) RegisterHostname(hostname string, ip net.IP) error {
	// Ensure hostname ends with .local
	if !strings.HasSuffix(hostname, ".local") && !strings.HasSuffix(hostname, ".local.") {
		hostname = hostname + ".local."
	}

	// Probe for conflicts
	if err := r.probeHostname(hostname); err != nil {
		return fmt.Errorf("hostname probe failed: %w", err)
	}

	r.hostnamesMu.Lock()
	r.hostnames[hostname] = ip
	r.hostnamesMu.Unlock()

	// Announce hostname
	r.announceHostname(hostname, ip)

	return nil
}

// BrowseServices initiates a service discovery browse for a service type.
func (r *Responder) BrowseServices(serviceType string) ([]*Service, error) {
	if !r.config.Browser {
		return nil, fmt.Errorf("browser mode not enabled")
	}

	// Send PTR query for service type
	query := fmt.Sprintf("%s.local.", serviceType)
	r.sendQuery(query, protocol.TypePTR)

	// Return cached results
	return r.cache.GetServices(serviceType), nil
}

// GetCachedService returns a cached service by full name.
func (r *Responder) GetCachedService(fullName string) *Service {
	return r.cache.Get(fullName)
}

// receiveLoop handles incoming mDNS packets.
func (r *Responder) receiveLoop(conn *net.UDPConn, stopCh <-chan struct{}) {
	defer r.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		if !r.setReceiveDeadline(conn, time.Now().Add(100*time.Millisecond)) {
			return
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if r.logger != nil {
				r.logger.Debugf("mDNS receive error: %v", err)
			}
			continue
		}

		r.handlePacket(buf[:n], src)
	}
}

type mdnsDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type mdnsCloser interface {
	Close() error
}

func (r *Responder) setReceiveDeadline(conn mdnsDeadlineSetter, deadline time.Time) bool {
	if err := conn.SetReadDeadline(deadline); err != nil {
		if r.logger != nil {
			r.logger.Debugf("mDNS receive deadline error: %v", err)
		}
		return false
	}
	return true
}

func (r *Responder) closeUDPConn(conn mdnsCloser) {
	if err := conn.Close(); err != nil && r.logger != nil {
		r.logger.Warnf("mDNS UDP close error: %v", err)
	}
}

// handlePacket processes an mDNS packet.
func (r *Responder) handlePacket(data []byte, src *net.UDPAddr) {
	// Parse DNS message
	if len(data) < 12 {
		return
	}

	// Check if query or response using header flags
	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags & 0x8000) != 0

	if isResponse && r.config.Browser {
		// Process response for service discovery
		r.handleResponse(data, src)
	} else if !isResponse {
		// Process query and send response
		r.handleQuery(data, src)
	}
}

// handleQuery processes an mDNS query and sends a response if applicable.
// Per RFC 6762 §6 the responder matches a query against its records by
// comparing each Question's owner name (case-insensitive, RFC 1035 §2.3.3)
// against the registered hostname/service. Earlier code did a raw byte-level
// substring match on the wire bytes — that produced coincidental matches on
// crafted payloads and could be spoofed by an off-link attacker.
func (r *Responder) handleQuery(data []byte, src *net.UDPAddr) {
	// Anti-reflection: throttle responses per source IP so a spoofed query
	// source can't turn the responder into an amplifier.
	if r.respLimiter != nil && src != nil && !r.respLimiter.allow(src.IP.String(), time.Now()) {
		return
	}

	msg, err := protocol.UnpackMessage(data)
	if err != nil {
		return
	}
	defer msg.Release()
	if len(msg.Questions) == 0 {
		return
	}

	// Collect the question names once, lower-cased and stripped of any
	// trailing dot, so the inner loops do not repeat the work.
	qNames := make([]string, 0, len(msg.Questions))
	for _, q := range msg.Questions {
		if q == nil || q.Name == nil {
			continue
		}
		qNames = append(qNames, strings.ToLower(strings.TrimSuffix(q.Name.String(), ".")))
	}
	if len(qNames) == 0 {
		return
	}

	// RFC 6762 §6.7: a query whose source port is not the mDNS port comes
	// from a legacy (one-shot) resolver, which matches the reply by ID and
	// Question. Such replies MUST echo the query ID and repeat the Question.
	var lq *legacyQuery
	if src != nil && src.Port != r.config.Port {
		lq = &legacyQuery{id: msg.Header.ID, questions: msg.Questions}
	}

	// Hostname queries: exact match on (lower-case, no trailing dot).
	r.hostnamesMu.RLock()
	for hostname, ip := range r.hostnames {
		host := strings.ToLower(strings.TrimSuffix(hostname, "."))
		for _, qn := range qNames {
			if qn == host {
				r.sendHostnameResponse(hostname, ip, src, lq)
				break
			}
		}
	}
	r.hostnamesMu.RUnlock()

	// Service queries: match either the service type
	// (e.g. "_http._tcp.local") or the full service instance name.
	// The wire name for the type is ServiceTypeName() — the enumeration name
	// built from ServiceType plus Domain (RFC 6763 §9.1). Matching the bare
	// ServiceType instead compared against a non-resolvable "_http._tcp", so
	// the standard service-type browse never matched anything.
	r.servicesMu.RLock()
	for _, svc := range r.services {
		stype := strings.ToLower(strings.TrimSuffix(svc.ServiceTypeName(), "."))
		full := strings.ToLower(strings.TrimSuffix(svc.FullServiceName(), "."))
		for _, qn := range qNames {
			if qn == stype || qn == full {
				r.sendServiceResponse(svc, src, lq)
				break
			}
		}
	}
	r.servicesMu.RUnlock()
}

// handleResponse processes an mDNS response for service discovery.
func (r *Responder) handleResponse(data []byte, src *net.UDPAddr) {
	// Parse response and cache discovered services
	if !r.config.Browser {
		return
	}

	// Extract and cache service info
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	// Simplified: parse SRV, TXT, A, AAAA records from response
	// and update cache
}

// queryMatches and queryMatchesService were removed in favour of full
// wire-format parsing inside handleQuery. The old implementations ran
// strings.Contains over raw wire bytes, which produced coincidental
// matches and could be spoofed by an off-link attacker who knew the
// hostname/service string. Keep no shim — call sites have been updated.

// legacyQuery carries what a legacy unicast reply must echo (RFC 6762 §6.7).
// nil means an ordinary mDNS response or announcement.
type legacyQuery struct {
	id        uint16
	questions []*protocol.Question
}

// sendReply sends msg to dst, first echoing the legacy query's ID and
// Question section when lq is non-nil (RFC 6762 §6.7).
func (r *Responder) sendReply(msg *protocol.Message, dst *net.UDPAddr, lq *legacyQuery) {
	if lq != nil {
		msg.Header.ID = lq.id
		for _, q := range lq.questions {
			if q != nil && q.Name != nil {
				msg.Questions = append(msg.Questions, q)
			}
		}
		msg.Header.QDCount = uint16(len(msg.Questions))
	}
	r.sendMulticast(msg, dst)
}

// sendHostnameResponse sends an A/AAAA record response for a hostname query.
func (r *Responder) sendHostnameResponse(hostname string, ip net.IP, dst *net.UDPAddr, lq *legacyQuery) {
	// For IPv4, send A record
	if ip4 := ip.To4(); ip4 != nil {
		r.sendARecord(hostname, ip4, dst, lq)
	} else {
		// For IPv6, send AAAA record
		r.sendAAAARecord(hostname, ip, dst, lq)
	}
}

// sendServiceResponse sends SRV, TXT, and PTR records for a service.
func (r *Responder) sendServiceResponse(svc *Service, dst *net.UDPAddr, lq *legacyQuery) {
	// The PTR (<type>.<domain> -> instance) is what a DNS-SD browse asks
	// for (RFC 6763 §4.1); SRV and TXT then resolve the instance.
	r.sendPTRRecord(svc, dst, lq)
	r.sendSRVRecord(svc, dst, lq)
	r.sendTXTRecord(svc, dst, lq)
}

// sendPTRRecord sends the service-type PTR record for a service instance.
func (r *Responder) sendPTRRecord(svc *Service, dst *net.UDPAddr, lq *legacyQuery) {
	rr, err := servicePTRRecord(svc, svc.TTL)
	if err != nil {
		return
	}
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 1,
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA
	msg.Answers = append(msg.Answers, rr)
	r.sendReply(msg, dst, lq)
}

// servicePTRRecord builds "<type>.<domain>. PTR <instance full name>".
func servicePTRRecord(svc *Service, ttl uint32) (*protocol.ResourceRecord, error) {
	target, err := protocol.ParseName(svc.FullServiceName())
	if err != nil {
		return nil, err
	}
	return protocol.NewResourceRecord(svc.ServiceTypeName(), protocol.TypePTR, protocol.ClassIN, ttl,
		&protocol.RDataPTR{PtrDName: target})
}

// sendARecord sends an A record response.
func (r *Responder) sendARecord(name string, ip net.IP, dst *net.UDPAddr, lq *legacyQuery) {
	// Build DNS response message
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 1,
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA

	// Create A record data
	ip4 := ip.To4()
	if ip4 == nil {
		return // Not an IPv4 address
	}

	// Copy IPv4 bytes to [4]byte
	var addr4 [4]byte
	copy(addr4[:], ip4)

	rdata := &protocol.RDataA{Address: addr4}
	rr, err := protocol.NewResourceRecord(name, protocol.TypeA, protocol.ClassIN, DefaultTTL, rdata)
	if err != nil {
		return
	}
	msg.Answers = append(msg.Answers, rr)

	// Send the response
	r.sendReply(msg, dst, lq)
}

// sendAAAARecord sends an AAAA record response.
func (r *Responder) sendAAAARecord(name string, ip net.IP, dst *net.UDPAddr, lq *legacyQuery) {
	// Build DNS response message
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 1,
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA

	// Create AAAA record data
	var addr16 [16]byte
	copy(addr16[:], ip)

	rdata := &protocol.RDataAAAA{Address: addr16}
	rr, err := protocol.NewResourceRecord(name, protocol.TypeAAAA, protocol.ClassIN, DefaultTTL, rdata)
	if err != nil {
		return
	}
	msg.Answers = append(msg.Answers, rr)

	// Send the response
	r.sendReply(msg, dst, lq)
}

// sendSRVRecord sends an SRV record response.
func (r *Responder) sendSRVRecord(svc *Service, dst *net.UDPAddr, lq *legacyQuery) {
	// Build DNS response message
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 1,
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA

	// Parse target hostname
	targetName, err := protocol.ParseName(svc.HostName)
	if err != nil {
		return
	}

	// Create SRV record data (RFC 2782)
	rdata := &protocol.RDataSRV{
		Priority: 0,
		Weight:   0,
		Port:     uint16(svc.Port),
		Target:   targetName,
	}
	rr, err := protocol.NewResourceRecord(svc.FullServiceName(), protocol.TypeSRV, protocol.ClassIN, svc.TTL, rdata)
	if err != nil {
		return
	}
	msg.Answers = append(msg.Answers, rr)

	// Send the response
	r.sendReply(msg, dst, lq)
}

// sendTXTRecord sends a TXT record response.
func (r *Responder) sendTXTRecord(svc *Service, dst *net.UDPAddr, lq *legacyQuery) {
	// Build DNS response message
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 1,
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA

	// Create TXT record data from service TXT map
	var txtStrings []string
	for k, v := range svc.TXT {
		txtStrings = append(txtStrings, k+"="+v)
	}
	// Ensure non-empty TXT (RFC 6763 requires at least one string)
	if len(txtStrings) == 0 {
		txtStrings = []string{""}
	}

	rdata := &protocol.RDataTXT{Strings: txtStrings}
	rr, err := protocol.NewResourceRecord(svc.FullServiceName(), protocol.TypeTXT, protocol.ClassIN, svc.TTL, rdata)
	if err != nil {
		return
	}
	msg.Answers = append(msg.Answers, rr)

	// Send the response
	r.sendReply(msg, dst, lq)
}

// sendQuery sends an mDNS query.
func (r *Responder) sendQuery(name string, qtype uint16) {
	// Build mDNS query message
	q, err := protocol.NewQuestion(name, qtype, protocol.ClassIN)
	if err != nil {
		if r.logger != nil {
			r.logger.Debugf("mDNS: failed to create question for %s: %v", name, err)
		}
		return
	}

	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewQueryFlags(),
		QDCount: 1,
	})
	msg.Questions = append(msg.Questions, q)

	// Send to multicast address
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendMulticast(msg, multicastAddr)
}

// sendGoodbye sends a goodbye packet (TTL=0) for a service. svc, when known,
// adds the TTL=0 PTR that DNS-SD browsers key their instance lists on.
func (r *Responder) sendGoodbye(fullName string, svc *Service) {
	// Build DNS response message with TTL=0 to indicate removal
	msg := protocol.NewMessage(protocol.Header{
		ID:      r.generateTransactionID(),
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 0,
		ANCount: 2, // SRV and TXT
	})
	msg.Header.Flags.AA = true // RFC 6762 §18.4: mDNS responses MUST set AA

	// Parse empty target for SRV
	emptyName, _ := protocol.ParseName("")

	// Add SRV record with TTL=0 (RFC 6762 Section 7.1)
	srvRR, err := protocol.NewResourceRecord(fullName, protocol.TypeSRV, protocol.ClassIN, 0,
		&protocol.RDataSRV{Priority: 0, Weight: 0, Port: 0, Target: emptyName})
	if err == nil {
		msg.Answers = append(msg.Answers, srvRR)
	}

	// Add TXT record with TTL=0
	txtRR, err := protocol.NewResourceRecord(fullName, protocol.TypeTXT, protocol.ClassIN, 0,
		&protocol.RDataTXT{Strings: []string{""}})
	if err == nil {
		msg.Answers = append(msg.Answers, txtRR)
	}

	// Add PTR record with TTL=0 so browsers drop the instance (RFC 6762 §10.1)
	if svc != nil {
		if ptrRR, err := servicePTRRecord(svc, 0); err == nil {
			msg.Answers = append(msg.Answers, ptrRR)
		}
	}
	msg.Header.ANCount = uint16(len(msg.Answers))

	// Send to multicast address
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendMulticast(msg, multicastAddr)
}

// sendMulticast sends a DNS message to the specified UDP address.
func (r *Responder) sendMulticast(msg *protocol.Message, dst *net.UDPAddr) {
	if r.conn == nil {
		return
	}

	// Pack the message to wire format
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		if r.logger != nil {
			r.logger.Debugf("mDNS: failed to pack message: %v", err)
		}
		return
	}

	// Write to multicast socket
	if _, err = writeUDPPacket(r.conn, buf[:n], dst); err != nil {
		if r.logger != nil {
			r.logger.Debugf("mDNS: failed to send multicast: %v", err)
		}
	}
}

type udpPacketWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

func writeUDPPacket(conn udpPacketWriter, data []byte, dst *net.UDPAddr) (int, error) {
	n, err := conn.WriteToUDP(data, dst)
	if err != nil {
		return n, err
	}
	if n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// generateTransactionID generates a random transaction ID for mDNS messages.
// RFC 6762 recommends using random IDs to avoid collisions.
func (r *Responder) generateTransactionID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based if crypto/rand fails
		return uint16(time.Now().UnixNano() >> 16)
	}
	return binary.BigEndian.Uint16(b[:])
}

// announceService sends service announcement (unsolicited response).
func (r *Responder) announceService(svc *Service) {
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendServiceResponse(svc, multicastAddr, nil)
}

// announceHostname sends hostname announcement.
func (r *Responder) announceHostname(hostname string, ip net.IP) {
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendHostnameResponse(hostname, ip, multicastAddr, nil)
}

// probeHostname probes for hostname conflicts (RFC 6762 Section 8.1).
func (r *Responder) probeHostname(hostname string) error {
	r.probeMu.Lock()
	defer r.probeMu.Unlock()

	if r.probedHostnames[hostname] {
		return nil // Already probed
	}

	// Send probe queries
	for i := 0; i < 3; i++ {
		r.sendQuery(hostname, protocol.TypeANY)
		time.Sleep(ProbeInterval)
	}

	r.probedHostnames[hostname] = true
	return nil
}

// maintenanceLoop handles periodic maintenance tasks.
func (r *Responder) maintenanceLoop(stopCh <-chan struct{}) {
	defer r.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			r.announceAll()
			r.cache.Expire()
		}
	}
}

// announceAll re-announces all registered services and hostnames.
func (r *Responder) announceAll() {
	r.servicesMu.RLock()
	for _, svc := range r.services {
		r.announceService(svc)
	}
	r.servicesMu.RUnlock()

	r.hostnamesMu.RLock()
	for hostname, ip := range r.hostnames {
		r.announceHostname(hostname, ip)
	}
	r.hostnamesMu.RUnlock()
}

// Cache implements a cache for discovered mDNS services.
type Cache struct {
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

type cacheEntry struct {
	service   *Service
	expiresAt time.Time
}

func mdnsCacheExpiredAt(now, expiresAt time.Time) bool {
	return !now.Before(expiresAt)
}

// NewCache creates a new service cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*cacheEntry),
	}
}

// Add adds a service to the cache.
func (c *Cache) Add(svc *Service) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[svc.FullServiceName()] = &cacheEntry{
		service:   cloneService(svc),
		expiresAt: time.Now().Add(time.Duration(svc.TTL) * time.Second),
	}
}

// Get retrieves a service from the cache.
func (c *Cache) Get(fullName string) *Service {
	return c.getAt(fullName, time.Now())
}

func (c *Cache) getAt(fullName string, now time.Time) *Service {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[fullName]
	if !ok || mdnsCacheExpiredAt(now, entry.expiresAt) {
		return nil
	}
	return cloneService(entry.service)
}

// GetServices returns all cached services of a given type.
func (c *Cache) GetServices(serviceType string) []*Service {
	return c.getServicesAt(serviceType, time.Now())
}

func (c *Cache) getServicesAt(serviceType string, now time.Time) []*Service {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*Service
	for _, entry := range c.entries {
		if entry.service.ServiceType == serviceType && !mdnsCacheExpiredAt(now, entry.expiresAt) {
			result = append(result, cloneService(entry.service))
		}
	}
	return result
}

// Expire removes expired entries from the cache.
func (c *Cache) Expire() {
	c.expireAt(time.Now())
}

func (c *Cache) expireAt(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for name, entry := range c.entries {
		if mdnsCacheExpiredAt(now, entry.expiresAt) {
			delete(c.entries, name)
		}
	}
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
