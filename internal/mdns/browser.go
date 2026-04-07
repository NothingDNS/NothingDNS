// Package mdns implements Multicast DNS (mDNS) and DNS Service Discovery (DNS-SD)
// as specified in RFC 6762 and RFC 6763.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// BrowseServiceType represents a service type to browse for.
type BrowseServiceType struct {
	Service string // e.g., "_http", "_ssh"
	Proto   string // e.g., "_tcp", "_udp"
}

// FullName returns the full service type name for PTR queries.
func (b *BrowseServiceType) FullName() string {
	return b.Service + "." + b.Proto + ".local."
}

// BrowseResult represents a discovered service instance during browsing.
type BrowseResult struct {
	InstanceName string // e.g., "My Printer._printer._tcp.local."
	ServiceType  string // e.g., "_printer._tcp.local"
	AdditionTime time.Time
}

// Browser discovers services using DNS-SD (RFC 6763).
type Browser struct {
	querier     *Querier
	serviceType BrowseServiceType
	results     map[string]*BrowseResult // instance name -> result
	mu          sync.RWMutex
	stopCh      chan struct{}
	onResult    func(*BrowseResult) // callback for new results
	onRemove    func(string)        // callback for removed results
}

// NewBrowser creates a new DNS-SD browser for the specified service type.
func NewBrowser(iface *net.Interface, serviceType string) (*Browser, error) {
	// Parse service type into service and protocol
	parts := strings.Split(serviceType, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid service type: %s", serviceType)
	}

	proto := parts[len(parts)-1]
	service := strings.Join(parts[:len(parts)-1], ".")

	// Check for known service types
	if !isKnownServiceType(service + "." + proto) {
		// Still allow, just log
	}

	querier, err := NewQuerier(iface)
	if err != nil {
		return nil, err
	}

	b := &Browser{
		querier: querier,
		serviceType: BrowseServiceType{
			Service: service,
			Proto:   proto,
		},
		results: make(map[string]*BrowseResult),
		stopCh:  make(chan struct{}),
	}

	return b, nil
}

// Browse starts browsing for services and calls callback for each result.
// It runs until the context is cancelled or Stop() is called.
func (b *Browser) Browse(ctx context.Context, onResult func(*BrowseResult), onRemove func(string)) error {
	b.mu.Lock()
	b.onResult = onResult
	b.onRemove = onRemove
	b.mu.Unlock()

	// Initial browsing query
	if err := b.queryServices(ctx); err != nil {
		return err
	}

	// Set up continuous browsing with refresh interval
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Also set up multicast listener for incoming responses
	go b.listenForResponses(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-b.stopCh:
			return nil
		case <-ticker.C:
			// Refresh service browsing periodically
			if err := b.queryServices(ctx); err != nil {
				// Log but continue
				continue
			}
		}
	}
}

// queryServices sends a PTR query for the service type.
func (b *Browser) queryServices(ctx context.Context) error {
	// RFC 6763 Section 4.1: Service Instance Enumeration
	// Query: PTR -> service type domain (e.g., _http._tcp.local.)
	queryName := b.serviceType.FullName()

	responses, err := b.querier.Query(ctx, queryName, TypePTR)
	if err != nil {
		return fmt.Errorf("browse query failed: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	for _, resp := range responses {
		for _, rr := range resp.Answers {
			if rr.Type != TypePTR {
				continue
			}

			// Extract instance name from PTR RDATA
			instanceName := extractNameFromPTR(rr.RData)
			if instanceName == "" {
				continue
			}

			// Check if this is a new result
			if _, exists := b.results[instanceName]; !exists {
				result := &BrowseResult{
					InstanceName: instanceName,
					ServiceType:  b.serviceType.Service + "." + b.serviceType.Proto + ".local",
					AdditionTime: now,
				}
				b.results[instanceName] = result

				// Notify callback
				if b.onResult != nil {
					b.onResult(result)
				}
			} else {
				// Update timestamp
				b.results[instanceName].AdditionTime = now
			}
		}
	}

	return nil
}

// listenForResponses listens for incoming mDNS responses on the query socket.
// This allows us to receive unsolicited announcements.
func (b *Browser) listenForResponses(ctx context.Context) {
	// This would require setting up a response handler on the querier
	// For now, we rely on periodic queries
}

// Stop stops the browser.
func (b *Browser) Stop() {
	close(b.stopCh)
	b.querier.Close()
}

// Results returns the current list of discovered service instances.
func (b *Browser) Results() []*BrowseResult {
	b.mu.RLock()
	defer b.mu.RUnlock()

	results := make([]*BrowseResult, 0, len(b.results))
	for _, r := range b.results {
		results = append(results, r)
	}
	return results
}

// RemoveStale removes service instances that haven't been seen recently.
func (b *Browser) RemoveStale(maxAge time.Duration) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var removed int

	for name, result := range b.results {
		if result.AdditionTime.Before(cutoff) {
			delete(b.results, name)
			removed++
			if b.onRemove != nil {
				b.onRemove(name)
			}
		}
	}

	return removed
}

// isKnownServiceType checks if a service type is in the known list.
func isKnownServiceType(serviceType string) bool {
	for _, known := range KnownServiceTypes {
		if known == serviceType {
			return true
		}
	}
	return false
}

// ServiceResolver resolves a service instance to get all its details.
type ServiceResolver struct {
	querier *Querier
}

// NewServiceResolver creates a new service resolver.
func NewServiceResolver(iface *net.Interface) (*ServiceResolver, error) {
	querier, err := NewQuerier(iface)
	if err != nil {
		return nil, err
	}
	return &ServiceResolver{querier: querier}, nil
}

// Resolve resolves a service instance name to get SRV, TXT, and address records.
func (r *ServiceResolver) Resolve(ctx context.Context, instanceName string, timeout time.Duration) (*ResolvedService, error) {
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	resolved := &ResolvedService{
		Instance: ServiceInstance{
			Name: instanceName,
		},
	}

	// Query for SRV record to get hostname and port
	srvResponses, err := r.querier.Query(ctx, instanceName, TypeSRV)
	if err != nil {
		return nil, fmt.Errorf("SRV query failed: %w", err)
	}

	for _, resp := range srvResponses {
		for _, rr := range resp.Answers {
			if rr.Type == TypeSRV {
				host, port := extractSRVData(rr.RData)
				resolved.Instance.HostName = host
				resolved.Instance.Port = int(port)
				if rr.TTL > 0 {
					resolved.Instance.TTL = rr.TTL
				}
			}
		}
	}

	if resolved.Instance.HostName == "" {
		return nil, ErrNoSuchService
	}

	// Query for TXT record
	txtResponses, err := r.querier.Query(ctx, instanceName, TypeTXT)
	if err == nil {
		for _, resp := range txtResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeTXT {
					resolved.Instance.TXTRecords = extractTXTData(rr.RData)
				}
			}
		}
	}

	// Query for A records (IPv4)
	aResponses, err := r.querier.Query(ctx, resolved.Instance.HostName, TypeA)
	if err == nil {
		for _, resp := range aResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeA && len(rr.RData) == 4 {
					resolved.IPv4 = append(resolved.IPv4, net.IP(rr.RData))
				}
			}
		}
	}

	// Query for AAAA records (IPv6)
	aaaaResponses, err := r.querier.Query(ctx, resolved.Instance.HostName, TypeAAAA)
	if err == nil {
		for _, resp := range aaaaResponses {
			for _, rr := range resp.Answers {
				if rr.Type == TypeAAAA && len(rr.RData) == 16 {
					resolved.IPv6 = append(resolved.IPv6, net.IP(rr.RData))
				}
			}
		}
	}

	return resolved, nil
}

// Close closes the service resolver.
func (r *ServiceResolver) Close() error {
	return r.querier.Close()
}

// ResolveService is a convenience function to browse and resolve a service in one step.
func ResolveService(ctx context.Context, iface *net.Interface, serviceType string) ([]*ServiceInstance, error) {
	// Create browser
	browser, err := NewBrowser(iface, serviceType)
	if err != nil {
		return nil, err
	}
	defer browser.Stop()

	// Browse for services
	var instances []*ServiceInstance

	err = browser.Browse(ctx, func(result *BrowseResult) {
		// Resolve each discovered instance
		resolver, err := NewServiceResolver(iface)
		if err != nil {
			return
		}
		defer resolver.Close()

		resolved, err := resolver.Resolve(ctx, result.InstanceName, 3*time.Second)
		if err != nil {
			return
		}

		instances = append(instances, &resolved.Instance)
	}, nil)

	if err != nil {
		return nil, err
	}

	return instances, nil
}

// ListServiceTypes returns the list of known service types.
func ListServiceTypes() []string {
	result := make([]string, len(KnownServiceTypes))
	copy(result, KnownServiceTypes)
	return result
}