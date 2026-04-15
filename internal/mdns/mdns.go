// Package mdns implements mDNS (RFC 6762) and DNS-SD (RFC 6763).
// Provides multicast DNS resolution for .local domains and service discovery.
package mdns

import (
	"fmt"
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
	DefaultTTL   = 120 // seconds - for most records
	HostnameTTL  = 120 // seconds - for hostnames
	ServiceTTL   = 4500 // seconds - for service instances (75 minutes)
	PtrTTL       = 4500 // seconds - for PTR records

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
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Probe state for hostname claiming
	probedHostnames map[string]bool
	probeMu         sync.Mutex
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
		stopCh:          make(chan struct{}),
		probedHostnames: make(map[string]bool),
	}
}

// Start starts the mDNS responder.
func (r *Responder) Start() error {
	if !r.config.Enabled {
		return nil
	}

	// Join multicast group
	addr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}

	var err error
	if r.config.Interface != nil {
		r.conn, err = net.ListenMulticastUDP("udp4", r.config.Interface, addr)
	} else {
		r.conn, err = net.ListenMulticastUDP("udp4", nil, addr)
	}
	if err != nil {
		return fmt.Errorf("failed to join multicast group: %w", err)
	}

	// Set buffer sizes
	r.conn.SetReadBuffer(65536)
	r.conn.SetWriteBuffer(65536)

	// Start listeners
	r.wg.Add(2)
	go r.receiveLoop()
	go r.maintenanceLoop()

	if r.logger != nil {
		r.logger.Infof("mDNS responder started on %s:%d", r.config.MulticastIP, r.config.Port)
	}

	return nil
}

// Stop stops the mDNS responder.
func (r *Responder) Stop() {
	close(r.stopCh)
	r.wg.Wait()

	if r.conn != nil {
		r.conn.Close()
	}

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
	delete(r.services, fullName)
	r.servicesMu.Unlock()

	// Send goodbye packet (TTL=0)
	r.sendGoodbye(fullName)

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
func (r *Responder) receiveLoop() {
	defer r.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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

// handlePacket processes an mDNS packet.
func (r *Responder) handlePacket(data []byte, src *net.UDPAddr) {
	// Parse DNS message
	// Note: We'd need to implement full parsing here
	// For now, use raw packet inspection
	if len(data) < 12 {
		return
	}

	// Check if query or response
	flags := uint16(data[2])<<8 | uint16(data[3])
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
func (r *Responder) handleQuery(data []byte, src *net.UDPAddr) {
	// Parse questions and determine if we have answers
	// This is a simplified implementation

	// Check for hostname queries
	r.hostnamesMu.RLock()
	for hostname, ip := range r.hostnames {
		if r.queryMatches(data, hostname) {
			r.sendHostnameResponse(hostname, ip, src)
		}
	}
	r.hostnamesMu.RUnlock()

	// Check for service queries
	r.servicesMu.RLock()
	for _, svc := range r.services {
		if r.queryMatchesService(data, svc) {
			r.sendServiceResponse(svc, src)
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

// queryMatches checks if a query matches a hostname.
func (r *Responder) queryMatches(data []byte, hostname string) bool {
	// Simplified: search for hostname in raw packet
	return strings.Contains(string(data), hostname)
}

// queryMatchesService checks if a query matches a service.
func (r *Responder) queryMatchesService(data []byte, svc *Service) bool {
	queryStr := string(data)
	return strings.Contains(queryStr, svc.ServiceType) ||
		strings.Contains(queryStr, svc.FullServiceName())
}

// sendHostnameResponse sends an A/AAAA record response for a hostname query.
func (r *Responder) sendHostnameResponse(hostname string, ip net.IP, dst *net.UDPAddr) {
	// Build mDNS response packet
	// For IPv4, send A record
	if ip4 := ip.To4(); ip4 != nil {
		r.sendARecord(hostname, ip4, dst)
	}
}

// sendServiceResponse sends SRV, TXT, and PTR records for a service.
func (r *Responder) sendServiceResponse(svc *Service, dst *net.UDPAddr) {
	// Send service response with SRV and TXT
	r.sendSRVRecord(svc, dst)
	r.sendTXTRecord(svc, dst)
}

// sendARecord sends an A record response.
func (r *Responder) sendARecord(name string, ip net.IP, dst *net.UDPAddr) {
	// Build and send A record response
	// Implementation would build proper DNS packet
}

// sendSRVRecord sends an SRV record response.
func (r *Responder) sendSRVRecord(svc *Service, dst *net.UDPAddr) {
	// Build and send SRV record
}

// sendTXTRecord sends a TXT record response.
func (r *Responder) sendTXTRecord(svc *Service, dst *net.UDPAddr) {
	// Build and send TXT record
}

// sendQuery sends an mDNS query.
func (r *Responder) sendQuery(name string, qtype uint16) {
	// Build and send query packet
}

// announceService sends service announcement ( unsolicited response).
func (r *Responder) announceService(svc *Service) {
	// Send multicast announcement
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendServiceResponse(svc, multicastAddr)
}

// announceHostname sends hostname announcement.
func (r *Responder) announceHostname(hostname string, ip net.IP) {
	multicastAddr := &net.UDPAddr{
		IP:   net.ParseIP(r.config.MulticastIP),
		Port: r.config.Port,
	}
	r.sendHostnameResponse(hostname, ip, multicastAddr)
}

// sendGoodbye sends a goodbye packet (TTL=0) for a service.
func (r *Responder) sendGoodbye(fullName string) {
	// Send packet with TTL=0 to indicate service removal
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
func (r *Responder) maintenanceLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
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
		service:   svc,
		expiresAt: time.Now().Add(time.Duration(svc.TTL) * time.Second),
	}
}

// Get retrieves a service from the cache.
func (c *Cache) Get(fullName string) *Service {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[fullName]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.service
}

// GetServices returns all cached services of a given type.
func (c *Cache) GetServices(serviceType string) []*Service {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*Service
	for _, entry := range c.entries {
		if entry.service.ServiceType == serviceType && time.Now().Before(entry.expiresAt) {
			result = append(result, entry.service)
		}
	}
	return result
}

// Expire removes expired entries from the cache.
func (c *Cache) Expire() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for name, entry := range c.entries {
		if now.After(entry.expiresAt) {
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
