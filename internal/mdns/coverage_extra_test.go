package mdns

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ---------------------------------------------------------------------------
// Service method edge cases
// ---------------------------------------------------------------------------

func TestService_FullServiceName_EmptyFields(t *testing.T) {
	svc := &Service{
		InstanceName: "",
		ServiceType:  "_http._tcp",
		Domain:       "local",
	}
	got := svc.FullServiceName()
	want := "._http._tcp.local."
	if got != want {
		t.Errorf("FullServiceName with empty InstanceName = %q, want %q", got, want)
	}
}

func TestService_ServiceTypeName_EmptyDomain(t *testing.T) {
	svc := &Service{
		ServiceType: "_printer._tcp",
		Domain:      "",
	}
	got := svc.ServiceTypeName()
	want := "_printer._tcp.."
	if got != want {
		t.Errorf("ServiceTypeName with empty Domain = %q, want %q", got, want)
	}
}

func TestService_FullServiceName_MatchesServiceTypeName(t *testing.T) {
	svc := &Service{
		InstanceName: "My Device",
		ServiceType:  "_http._tcp",
		Domain:       "local",
	}
	full := svc.FullServiceName()
	stype := svc.ServiceTypeName()
	if full != "My Device."+stype {
		t.Errorf("FullServiceName %q should be InstanceName + ServiceTypeName %q", full, stype)
	}
}

// ---------------------------------------------------------------------------
// Config and NewResponder edge cases
// ---------------------------------------------------------------------------

func TestNewResponder_ZeroConfigFields(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := Config{} // All zero values

	r := NewResponder(cfg, logger)
	if r == nil {
		t.Fatal("NewResponder returned nil")
	}
	// Should fill in defaults for MulticastIP and Port
	if r.config.MulticastIP != DefaultMulticastIP {
		t.Errorf("MulticastIP = %q, want default %q", r.config.MulticastIP, DefaultMulticastIP)
	}
	if r.config.Port != DefaultPort {
		t.Errorf("Port = %d, want default %d", r.config.Port, DefaultPort)
	}
}

func TestNewResponder_CustomConfig(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := Config{
		Enabled:     true,
		MulticastIP: "224.0.0.252",
		Port:        5354,
		HostName:    "custom.local",
		Browser:     true,
	}

	r := NewResponder(cfg, logger)
	if !r.config.Enabled {
		t.Error("Enabled should be true")
	}
	if r.config.MulticastIP != "224.0.0.252" {
		t.Errorf("MulticastIP = %q, want %q", r.config.MulticastIP, "224.0.0.252")
	}
	if r.config.Port != 5354 {
		t.Errorf("Port = %d, want 5354", r.config.Port)
	}
	if !r.config.Browser {
		t.Error("Browser should be true")
	}
}

func TestNewResponder_NilLogger(t *testing.T) {
	cfg := DefaultConfig()
	r := NewResponder(cfg, nil)
	if r == nil {
		t.Fatal("NewResponder with nil logger should not return nil")
	}
}

// ---------------------------------------------------------------------------
// Responder.Start / Stop (disabled by default)
// ---------------------------------------------------------------------------

func TestResponder_Start_Disabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := Config{Enabled: false}
	r := NewResponder(cfg, logger)

	err := r.Start()
	if err != nil {
		t.Errorf("Start() with disabled config should return nil, got %v", err)
	}
	// Stop should be safe even if never truly started
	r.Stop()
}

// ---------------------------------------------------------------------------
// RegisterService - domain default and TTL default
// ---------------------------------------------------------------------------

func TestResponder_RegisterService_SetsDefaults(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	svc := &Service{
		InstanceName: "TestSvc",
		ServiceType:  "_http._tcp",
		HostName:     "testhost.local",
		Port:         8080,
		// Domain and TTL left empty
	}

	// RegisterService will attempt probeHostname which calls sendQuery on nil conn,
	// but sendQuery is a no-op stub, so this should succeed.
	err := r.RegisterService(svc)
	// probeHostname sends queries via nil conn (no-op), so no error expected
	if err != nil {
		t.Fatalf("RegisterService failed: %v", err)
	}

	// Domain should be set to "local"
	if svc.Domain != "local" {
		t.Errorf("Domain = %q, want %q", svc.Domain, "local")
	}

	// TTL should be set to ServiceTTL
	if svc.TTL != ServiceTTL {
		t.Errorf("TTL = %d, want %d", svc.TTL, ServiceTTL)
	}

	// Service should be in the services map
	r.servicesMu.RLock()
	registered, ok := r.services[svc.FullServiceName()]
	r.servicesMu.RUnlock()
	if !ok {
		t.Fatal("Service not found in services map")
	}
	if registered.InstanceName != "TestSvc" {
		t.Errorf("Registered InstanceName = %q, want %q", registered.InstanceName, "TestSvc")
	}
}

func TestResponder_RegisterService_PreservesExistingDomain(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	svc := &Service{
		InstanceName: "Custom",
		ServiceType:  "_ssh._tcp",
		Domain:       "example.com",
		HostName:     "host.example.com",
		Port:         22,
		TTL:          300,
	}

	err := r.RegisterService(svc)
	if err != nil {
		t.Fatalf("RegisterService failed: %v", err)
	}

	if svc.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", svc.Domain, "example.com")
	}
	if svc.TTL != 300 {
		t.Errorf("TTL = %d, want 300", svc.TTL)
	}
}

// ---------------------------------------------------------------------------
// UnregisterService - removes from map
// ---------------------------------------------------------------------------

func TestResponder_UnregisterService_NonExistent(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	// Unregistering a service that doesn't exist should not panic
	r.UnregisterService("nonexistent._http._tcp.local.")

	r.servicesMu.RLock()
	count := len(r.services)
	r.servicesMu.RUnlock()
	if count != 0 {
		t.Errorf("Services count = %d, want 0", count)
	}
}

// ---------------------------------------------------------------------------
// RegisterHostname - suffix handling edge cases
// ---------------------------------------------------------------------------

func TestResponder_RegisterHostname_WithDotLocalSuffix(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	ip := net.ParseIP("10.0.0.1")

	// Already has .local suffix (without trailing dot) - stored as-is
	err := r.RegisterHostname("myhost.local", ip)
	if err != nil {
		t.Errorf("RegisterHostname failed: %v", err)
	}

	r.hostnamesMu.RLock()
	_, ok := r.hostnames["myhost.local"]
	r.hostnamesMu.RUnlock()
	if !ok {
		t.Error("Hostname 'myhost.local' not found in hostnames map")
	}
}

func TestResponder_RegisterHostname_WithTrailingDot(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	ip := net.ParseIP("10.0.0.2")

	// Already has .local. with trailing dot
	err := r.RegisterHostname("myhost.local.", ip)
	if err != nil {
		t.Errorf("RegisterHostname failed: %v", err)
	}

	r.hostnamesMu.RLock()
	_, ok := r.hostnames["myhost.local."]
	r.hostnamesMu.RUnlock()
	if !ok {
		t.Error("Hostname 'myhost.local.' not found in hostnames map")
	}
}

func TestResponder_RegisterHostname_WithoutSuffix(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	ip := net.ParseIP("10.0.0.3")

	err := r.RegisterHostname("barehost", ip)
	if err != nil {
		t.Errorf("RegisterHostname failed: %v", err)
	}

	r.hostnamesMu.RLock()
	_, ok := r.hostnames["barehost.local."]
	r.hostnamesMu.RUnlock()
	if !ok {
		t.Error("Hostname 'barehost.local.' not found in hostnames map")
	}
}

func TestResponder_RegisterHostname_MultipleHostnames(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("192.168.1.3"),
	}
	hostnames := []string{"host-a", "host-b", "host-c"}

	for i, hn := range hostnames {
		err := r.RegisterHostname(hn, ips[i])
		if err != nil {
			t.Errorf("RegisterHostname(%s) failed: %v", hn, err)
		}
	}

	r.hostnamesMu.RLock()
	count := len(r.hostnames)
	r.hostnamesMu.RUnlock()
	if count != 3 {
		t.Errorf("Expected 3 hostnames, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// BrowseServices
// ---------------------------------------------------------------------------

func TestResponder_BrowseServices_BrowserDisabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig() // Browser = false
	r := NewResponder(cfg, logger)

	_, err := r.BrowseServices("_http._tcp")
	if err == nil {
		t.Error("BrowseServices should return error when browser is disabled")
	}
}

func TestResponder_BrowseServices_ReturnsCachedResults(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Browser = true
	r := NewResponder(cfg, logger)

	// Manually populate cache
	svc := &Service{
		InstanceName: "Cached Printer",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
		TTL:          120,
	}
	r.cache.Add(svc)

	results, err := r.BrowseServices("_ipp._tcp")
	if err != nil {
		t.Fatalf("BrowseServices failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 cached service, got %d", len(results))
	}
	if results[0].InstanceName != "Cached Printer" {
		t.Errorf("InstanceName = %q, want %q", results[0].InstanceName, "Cached Printer")
	}
}

func TestResponder_BrowseServices_NoCachedResults(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Browser = true
	r := NewResponder(cfg, logger)

	results, err := r.BrowseServices("_nonexistent._tcp")
	if err != nil {
		t.Fatalf("BrowseServices failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 cached services, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// GetCachedService
// ---------------------------------------------------------------------------

func TestResponder_GetCachedService_Found(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	svc := &Service{
		InstanceName: "MyService",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          120,
	}
	r.cache.Add(svc)

	got := r.GetCachedService(svc.FullServiceName())
	if got == nil {
		t.Fatal("GetCachedService returned nil")
	}
	if got.InstanceName != "MyService" {
		t.Errorf("InstanceName = %q, want %q", got.InstanceName, "MyService")
	}
}

func TestResponder_GetCachedService_NotFound(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	got := r.GetCachedService("nonexistent._http._tcp.local.")
	if got != nil {
		t.Error("GetCachedService should return nil for unknown service")
	}
}

// ---------------------------------------------------------------------------
// handlePacket - query/response routing
// ---------------------------------------------------------------------------

func TestResponder_HandlePacket_TooShort(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	// Packets < 12 bytes should be silently dropped
	r.handlePacket([]byte{0, 1, 2}, nil)
	// No panic = pass
}

func TestResponder_HandlePacket_Query(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	r := NewResponder(cfg, logger)

	// Register a hostname so handleQuery has something to match
	ip := net.ParseIP("192.168.1.50")
	r.hostnamesMu.Lock()
	r.hostnames["test.local."] = ip
	r.hostnamesMu.Unlock()

	// Build a minimal DNS query packet (flags=0x0000 = standard query)
	data := make([]byte, 12)
	// bytes 2-3 = flags = 0x0000 (query, not response)
	data[2] = 0x00
	data[3] = 0x00

	// handleQuery searches for hostname in raw data, so append it
	data = append(data, []byte("test.local.")...)

	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.99"), Port: 5353}
	r.handlePacket(data, src)
	// No panic = pass; actual response sending is a no-op stub
}

func TestResponder_HandlePacket_Response_BrowserMode(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Browser = true
	r := NewResponder(cfg, logger)

	// Build a minimal DNS response packet (flags=0x8000 = response)
	data := make([]byte, 12)
	data[2] = 0x80
	data[3] = 0x00

	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.99"), Port: 5353}
	r.handlePacket(data, src)
	// No panic = pass; handleResponse is a simplified stub
}

func TestResponder_HandlePacket_Response_BrowserDisabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Browser = false
	r := NewResponder(cfg, logger)

	// Response packet, but browser is disabled -- should be ignored
	data := make([]byte, 12)
	data[2] = 0x80
	data[3] = 0x00

	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.99"), Port: 5353}
	r.handlePacket(data, src)
	// No panic = pass
}

// ---------------------------------------------------------------------------
// queryMatches / queryMatchesService
// ---------------------------------------------------------------------------

func TestResponder_QueryMatches_Positive(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	data := []byte("some preamble myprinter.local. trailing")
	if !r.queryMatches(data, "myprinter.local.") {
		t.Error("queryMatches should return true when hostname is in data")
	}
}

func TestResponder_QueryMatches_Negative(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	data := []byte("some other data that does not match")
	if r.queryMatches(data, "myprinter.local.") {
		t.Error("queryMatches should return false when hostname is not in data")
	}
}

func TestResponder_QueryMatchesService_ByServiceType(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	svc := &Service{
		InstanceName: "MyPrinter",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
	}
	data := []byte("looking for _ipp._tcp services")

	if !r.queryMatchesService(data, svc) {
		t.Error("queryMatchesService should match by ServiceType")
	}
}

func TestResponder_QueryMatchesService_ByFullName(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	svc := &Service{
		InstanceName: "MyPrinter",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
	}
	data := []byte("query for MyPrinter._ipp._tcp.local.")

	if !r.queryMatchesService(data, svc) {
		t.Error("queryMatchesService should match by FullServiceName")
	}
}

func TestResponder_QueryMatchesService_NoMatch(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	svc := &Service{
		InstanceName: "MyPrinter",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
	}
	data := []byte("completely unrelated query data")

	if r.queryMatchesService(data, svc) {
		t.Error("queryMatchesService should return false for non-matching data")
	}
}

// ---------------------------------------------------------------------------
// sendHostnameResponse - IPv4 path
// ---------------------------------------------------------------------------

func TestResponder_SendHostnameResponse_IPv4(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	ip := net.ParseIP("192.168.1.100") // IPv4
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	// sendARecord is a no-op stub, so this just verifies no panic
	r.sendHostnameResponse("test.local.", ip, dst)
}

func TestResponder_SendHostnameResponse_IPv6Only(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	ip := net.ParseIP("fe80::1") // IPv6-only (To4() returns nil)
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	// IPv6-only IP: To4() is nil, so sendARecord is never called
	r.sendHostnameResponse("test.local.", ip, dst)
	// No panic = pass
}

// ---------------------------------------------------------------------------
// sendServiceResponse / sendSRVRecord / sendTXTRecord (no-op stubs)
// ---------------------------------------------------------------------------

func TestResponder_SendServiceResponse(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	svc := &Service{
		InstanceName: "TestSvc",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "test.local",
		Port:         80,
		TXT:          map[string]string{"key": "value"},
	}
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	r.sendServiceResponse(svc, dst) // no-op stubs, verify no panic
}

// ---------------------------------------------------------------------------
// announceAll
// ---------------------------------------------------------------------------

func TestResponder_AnnounceAll(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	// Register some services and hostnames
	svc := &Service{
		InstanceName: "Announce",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "announce.local",
		Port:         80,
		TTL:          120,
	}
	r.servicesMu.Lock()
	r.services[svc.FullServiceName()] = svc
	r.servicesMu.Unlock()

	ip := net.ParseIP("10.0.0.1")
	r.hostnamesMu.Lock()
	r.hostnames["announce.local."] = ip
	r.hostnamesMu.Unlock()

	// announceAll iterates all services and hostnames, calling no-op stubs
	r.announceAll()
	// No panic = pass
}

func TestResponder_AnnounceAll_Empty(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	// No services or hostnames registered
	r.announceAll()
	// No panic = pass
}

// ---------------------------------------------------------------------------
// probeHostname - already probed shortcut
// ---------------------------------------------------------------------------

func TestResponder_ProbeHostname_AlreadyProbed(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	hostname := "already.local."

	// Mark as already probed
	r.probeMu.Lock()
	r.probedHostnames[hostname] = true
	r.probeMu.Unlock()

	start := time.Now()
	err := r.probeHostname(hostname)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("probeHostname for already-probed hostname failed: %v", err)
	}
	// Should return immediately without the 3x ProbeInterval sleep
	if elapsed > 100*time.Millisecond {
		t.Errorf("probeHostname took %v for already-probed hostname, should be instant", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Cache edge cases
// ---------------------------------------------------------------------------

func TestCache_AddOverwrite(t *testing.T) {
	cache := NewCache()

	svc1 := &Service{
		InstanceName: "SvcV1",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		Port:         80,
		TTL:          120,
	}
	svc2 := &Service{
		InstanceName: "SvcV1",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		Port:         8080,
		TTL:          120,
	}

	cache.Add(svc1)
	cache.Add(svc2)

	if cache.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after overwrite", cache.Len())
	}

	got := cache.Get(svc1.FullServiceName())
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (overwritten value)", got.Port)
	}
}

func TestCache_Get_ExpiredEntry(t *testing.T) {
	cache := NewCache()

	// Manually insert an already-expired entry
	cache.mu.Lock()
	cache.entries["expired._http._tcp.local."] = &cacheEntry{
		service: &Service{
			InstanceName: "expired",
			ServiceType:  "_http._tcp",
			Domain:       "local",
			TTL:          10,
		},
		expiresAt: time.Now().Add(-1 * time.Hour),
	}
	cache.mu.Unlock()

	got := cache.Get("expired._http._tcp.local.")
	if got != nil {
		t.Error("Get should return nil for expired entry")
	}
}

func TestCache_GetServices_ExcludesExpired(t *testing.T) {
	cache := NewCache()

	// Add a valid service
	valid := &Service{
		InstanceName: "Valid",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          120,
	}
	cache.Add(valid)

	// Manually insert an expired entry of the same type
	cache.mu.Lock()
	cache.entries["Expired._http._tcp.local."] = &cacheEntry{
		service: &Service{
			InstanceName: "Expired",
			ServiceType:  "_http._tcp",
			Domain:       "local",
			TTL:          10,
		},
		expiresAt: time.Now().Add(-1 * time.Hour),
	}
	cache.mu.Unlock()

	results := cache.GetServices("_http._tcp")
	if len(results) != 1 {
		t.Fatalf("GetServices should return 1 valid service, got %d", len(results))
	}
	if results[0].InstanceName != "Valid" {
		t.Errorf("InstanceName = %q, want %q", results[0].InstanceName, "Valid")
	}
}

func TestCache_GetServices_NoMatch(t *testing.T) {
	cache := NewCache()

	svc := &Service{
		InstanceName: "Svc",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          120,
	}
	cache.Add(svc)

	results := cache.GetServices("_ssh._tcp")
	if len(results) != 0 {
		t.Errorf("GetServices for unregistered type should return 0, got %d", len(results))
	}
}

func TestCache_Expire_AllExpired(t *testing.T) {
	cache := NewCache()

	for i := 0; i < 5; i++ {
		cache.mu.Lock()
		cache.entries[fmt.Sprintf("svc%d._http._tcp.local.", i)] = &cacheEntry{
			service: &Service{
				InstanceName: fmt.Sprintf("svc%d", i),
				ServiceType:  "_http._tcp",
				Domain:       "local",
				TTL:          10,
			},
			expiresAt: time.Now().Add(-1 * time.Second),
		}
		cache.mu.Unlock()
	}

	if cache.Len() != 5 {
		t.Fatalf("Len before expire = %d, want 5", cache.Len())
	}

	cache.Expire()

	if cache.Len() != 0 {
		t.Errorf("Len after expire = %d, want 0", cache.Len())
	}
}

func TestCache_Expire_NoneExpired(t *testing.T) {
	cache := NewCache()

	svc := &Service{
		InstanceName: "Alive",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          3600,
	}
	cache.Add(svc)

	cache.Expire()

	if cache.Len() != 1 {
		t.Errorf("Len after expire = %d, want 1 (none expired)", cache.Len())
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewCache()
	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			svc := &Service{
				InstanceName: fmt.Sprintf("concurrent-%d", idx),
				ServiceType:  "_http._tcp",
				Domain:       "local",
				TTL:          120,
			}
			cache.Add(svc)
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-%d._http._tcp.local.", idx)
			cache.Get(name)
			cache.GetServices("_http._tcp")
		}(i)
	}

	wg.Wait()

	if cache.Len() != 50 {
		t.Errorf("Len() = %d, want 50 after concurrent adds", cache.Len())
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestConstants_Values(t *testing.T) {
	if DefaultMulticastIP != "224.0.0.251" {
		t.Errorf("DefaultMulticastIP = %q, want %q", DefaultMulticastIP, "224.0.0.251")
	}
	if DefaultPort != 5353 {
		t.Errorf("DefaultPort = %d, want 5353", DefaultPort)
	}
	if DefaultTTL != 120 {
		t.Errorf("DefaultTTL = %d, want 120", DefaultTTL)
	}
	if ServiceTTL != 4500 {
		t.Errorf("ServiceTTL = %d, want 4500", ServiceTTL)
	}
	if PtrTTL != 4500 {
		t.Errorf("PtrTTL = %d, want 4500", PtrTTL)
	}
	if HostnameTTL != 120 {
		t.Errorf("HostnameTTL = %d, want 120", HostnameTTL)
	}
	if ProbeInterval != 250*time.Millisecond {
		t.Errorf("ProbeInterval = %v, want 250ms", ProbeInterval)
	}
	if ProbeTimeout != 3*time.Second {
		t.Errorf("ProbeTimeout = %v, want 3s", ProbeTimeout)
	}
	if AnnounceDelay != 1*time.Second {
		t.Errorf("AnnounceDelay = %v, want 1s", AnnounceDelay)
	}
}

// ---------------------------------------------------------------------------
// handleQuery with registered services
// ---------------------------------------------------------------------------

func TestResponder_HandleQuery_WithRegisteredService(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	svc := &Service{
		InstanceName: "WebServer",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "web.local",
		Port:         80,
	}

	r.servicesMu.Lock()
	r.services[svc.FullServiceName()] = svc
	r.servicesMu.Unlock()

	// Build a query packet that contains the service type
	data := make([]byte, 12)
	data[2] = 0x00 // flags = query
	data[3] = 0x00
	data = append(data, []byte("_http._tcp")...)

	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5353}
	r.handlePacket(data, src)
	// No panic = pass
}

// ---------------------------------------------------------------------------
// handleResponse browser mode
// ---------------------------------------------------------------------------

func TestResponder_HandleResponse_BrowserDisabled(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Browser = false
	r := NewResponder(cfg, logger)

	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5353}
	// handleResponse should return immediately when browser is disabled
	r.handleResponse([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, src)
	// No panic = pass
}

// ---------------------------------------------------------------------------
// sendQuery (no-op stub, just verify no panic)
// ---------------------------------------------------------------------------

func TestResponder_SendQuery(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	// sendQuery is a no-op stub (conn is nil)
	r.sendQuery("test.local.", protocol.TypeA)
	r.sendQuery("_http._tcp.local.", protocol.TypePTR)
	r.sendQuery("host.local.", protocol.TypeANY)
}

// ---------------------------------------------------------------------------
// sendGoodbye (no-op stub)
// ---------------------------------------------------------------------------

func TestResponder_SendGoodbye(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	r.sendGoodbye("service._http._tcp.local.")
	// No panic = pass
}

// ---------------------------------------------------------------------------
// Multiple service registration and lookup
// ---------------------------------------------------------------------------

func TestResponder_RegisterMultipleServices(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	r := NewResponder(DefaultConfig(), logger)

	services := []*Service{
		{InstanceName: "HTTP", ServiceType: "_http._tcp", Domain: "local", HostName: "h1.local", Port: 80, TTL: 120},
		{InstanceName: "SSH", ServiceType: "_ssh._tcp", Domain: "local", HostName: "h2.local", Port: 22, TTL: 120},
		{InstanceName: "IPP", ServiceType: "_ipp._tcp", Domain: "local", HostName: "h3.local", Port: 631, TTL: 120},
	}

	for _, svc := range services {
		err := r.RegisterService(svc)
		if err != nil {
			t.Errorf("RegisterService(%s) failed: %v", svc.InstanceName, err)
		}
	}

	r.servicesMu.RLock()
	count := len(r.services)
	r.servicesMu.RUnlock()
	if count != 3 {
		t.Errorf("Expected 3 registered services, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Cache with TXT records
// ---------------------------------------------------------------------------

func TestCache_AddAndGet_WithTXTRecords(t *testing.T) {
	cache := NewCache()

	svc := &Service{
		InstanceName: "Printer",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
		HostName:     "printer.local",
		Port:         631,
		TTL:          300,
		TXT: map[string]string{
			"txtvers":  "1",
			"qtotal":  "1",
			"rp":      "text",
			"product": "(NothingDNS Virtual Printer)",
		},
	}

	cache.Add(svc)
	got := cache.Get(svc.FullServiceName())
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if len(got.TXT) != 4 {
		t.Errorf("TXT record count = %d, want 4", len(got.TXT))
	}
	if got.TXT["product"] != "(NothingDNS Virtual Printer)" {
		t.Errorf("TXT[product] = %q, want %q", got.TXT["product"], "(NothingDNS Virtual Printer)")
	}
}
