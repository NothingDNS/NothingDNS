package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func TestService_FullServiceName(t *testing.T) {
	svc := &Service{
		InstanceName: "My Printer",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "myprinter.local",
		Port:         80,
	}

	expected := "My Printer._http._tcp.local."
	if got := svc.FullServiceName(); got != expected {
		t.Errorf("FullServiceName() = %q, want %q", got, expected)
	}
}

func TestService_ServiceTypeName(t *testing.T) {
	svc := &Service{
		ServiceType: "_http._tcp",
		Domain:      "local",
	}

	expected := "_http._tcp.local."
	if got := svc.ServiceTypeName(); got != expected {
		t.Errorf("ServiceTypeName() = %q, want %q", got, expected)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default Enabled should be false")
	}
	if cfg.MulticastIP != DefaultMulticastIP {
		t.Errorf("Default MulticastIP = %q, want %q", cfg.MulticastIP, DefaultMulticastIP)
	}
	if cfg.Port != DefaultPort {
		t.Errorf("Default Port = %d, want %d", cfg.Port, DefaultPort)
	}
	if cfg.Browser {
		t.Error("Default Browser should be false")
	}
}

func TestNewResponder(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()
	cfg.Enabled = true

	r := NewResponder(cfg, logger)
	if r == nil {
		t.Fatal("NewResponder returned nil")
	}

	if r.config.MulticastIP != DefaultMulticastIP {
		t.Errorf("MulticastIP = %q, want %q", r.config.MulticastIP, DefaultMulticastIP)
	}
	if r.config.Port != DefaultPort {
		t.Errorf("Port = %d, want %d", r.config.Port, DefaultPort)
	}
}

func TestResponder_RegisterHostname(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()

	r := NewResponder(cfg, logger)

	// Test hostname registration (without .local suffix)
	ip := net.ParseIP("192.168.1.100")
	err := r.RegisterHostname("testhost", ip)
	if err != nil {
		t.Errorf("RegisterHostname failed: %v", err)
	}

	// Verify hostname was added
	r.hostnamesMu.RLock()
	_, ok := r.hostnames["testhost.local."]
	r.hostnamesMu.RUnlock()
	if !ok {
		t.Error("Hostname not registered")
	}

	// Test with .local suffix
	err = r.RegisterHostname("testhost2.local.", ip)
	if err != nil {
		t.Errorf("RegisterHostname with suffix failed: %v", err)
	}
}

func TestCache_AddAndGet(t *testing.T) {
	cache := NewCache()

	svc := &Service{
		InstanceName: "Test Service",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "test.local",
		Port:         8080,
		TXT:          map[string]string{"path": "/dns"},
		TTL:          120,
	}

	cache.Add(svc)
	svc.InstanceName = "Mutated Source"
	svc.TXT["path"] = "/mutated"

	got := cache.Get("Test Service._http._tcp.local.")
	if got == nil {
		t.Fatal("Get returned nil for added service")
	}
	if got.InstanceName != "Test Service" {
		t.Errorf("InstanceName = %q, want %q", got.InstanceName, "Test Service")
	}
	if got.TXT["path"] != "/dns" {
		t.Errorf("TXT path = %q, want /dns", got.TXT["path"])
	}

	got.InstanceName = "Mutated Result"
	got.TXT["path"] = "/changed"
	again := cache.Get("Test Service._http._tcp.local.")
	if again.InstanceName != "Test Service" {
		t.Fatal("Get returned internal service pointer")
	}
	if again.TXT["path"] != "/dns" {
		t.Fatal("Get returned internal TXT map")
	}
}

func TestCache_GetServices(t *testing.T) {
	cache := NewCache()

	services := []*Service{
		{InstanceName: "Svc1", ServiceType: "_http._tcp", Domain: "local", TXT: map[string]string{"id": "1"}, TTL: 120},
		{InstanceName: "Svc2", ServiceType: "_http._tcp", Domain: "local", TTL: 120},
		{InstanceName: "Svc3", ServiceType: "_ssh._tcp", Domain: "local", TTL: 120},
	}

	for _, svc := range services {
		cache.Add(svc)
	}

	httpServices := cache.GetServices("_http._tcp")
	if len(httpServices) != 2 {
		t.Errorf("GetServices(_http._tcp) returned %d services, want 2", len(httpServices))
	}
	for _, svc := range httpServices {
		svc.InstanceName = "Mutated List Result"
		if svc.TXT != nil {
			svc.TXT["id"] = "mutated"
		}
	}
	httpServices[0] = nil
	httpServices = cache.GetServices("_http._tcp")
	if len(httpServices) != 2 || httpServices[0] == nil {
		t.Fatal("GetServices returned internal result slice")
	}
	for _, svc := range httpServices {
		if svc.InstanceName == "Mutated List Result" {
			t.Fatal("GetServices returned internal service pointer")
		}
		if svc.TXT["id"] == "mutated" {
			t.Fatal("GetServices returned internal TXT map")
		}
	}

	sshServices := cache.GetServices("_ssh._tcp")
	if len(sshServices) != 1 {
		t.Errorf("GetServices(_ssh._tcp) returned %d services, want 1", len(sshServices))
	}
}

func TestCache_ExactExpiryBoundary(t *testing.T) {
	cache := NewCache()
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	key := "Svc1._http._tcp.local."

	cache.entries[key] = &cacheEntry{
		service: &Service{
			InstanceName: "Svc1",
			ServiceType:  "_http._tcp",
			Domain:       "local",
			TTL:          120,
		},
		expiresAt: now,
	}
	cache.entries["Svc2._http._tcp.local."] = &cacheEntry{
		service: &Service{
			InstanceName: "Svc2",
			ServiceType:  "_http._tcp",
			Domain:       "local",
			TTL:          120,
		},
		expiresAt: now.Add(time.Nanosecond),
	}

	if !mdnsCacheExpiredAt(now, now) {
		t.Fatal("mDNS cache entry should be expired exactly at expiresAt")
	}
	if cache.getAt(key, now) != nil {
		t.Fatal("Get should exclude service exactly at expiresAt")
	}
	services := cache.getServicesAt("_http._tcp", now)
	if len(services) != 1 || services[0].InstanceName != "Svc2" {
		t.Fatalf("GetServices at exact expiry returned %v, want only Svc2", services)
	}

	cache.expireAt(now)
	if _, exists := cache.entries[key]; exists {
		t.Fatal("Expire should remove service exactly at expiresAt")
	}
	if _, exists := cache.entries["Svc2._http._tcp.local."]; !exists {
		t.Fatal("Expire should keep service before expiresAt")
	}
}

func TestCache_Expire(t *testing.T) {
	cache := NewCache()

	// Add service with very short TTL
	svc := &Service{
		InstanceName: "Short Lived",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          1, // 1 second
	}
	cache.Add(svc)

	// Should exist initially
	if cache.Get(svc.FullServiceName()) == nil {
		t.Error("Service should exist before expiration")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Should be expired now
	if cache.Get(svc.FullServiceName()) != nil {
		t.Error("Service should be expired")
	}
}

func TestCache_Len(t *testing.T) {
	cache := NewCache()

	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want 0", cache.Len())
	}

	cache.Add(&Service{InstanceName: "Svc1", ServiceType: "_http._tcp", Domain: "local", TTL: 120})
	if cache.Len() != 1 {
		t.Errorf("Len() = %d, want 1", cache.Len())
	}

	cache.Add(&Service{InstanceName: "Svc2", ServiceType: "_ssh._tcp", Domain: "local", TTL: 120})
	if cache.Len() != 2 {
		t.Errorf("Len() = %d, want 2", cache.Len())
	}
}

func TestResponder_RegisterService(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()

	r := NewResponder(cfg, logger)

	svc := &Service{
		InstanceName: "Test Printer",
		ServiceType:  "_ipp._tcp",
		Domain:       "local",
		HostName:     "printer.local",
		Port:         631,
		TXT: map[string]string{
			"txtvers": "1",
			"qtotal":  "1",
		},
	}

	// Note: This will fail without a running multicast listener
	// but we can test the registration logic
	err := r.RegisterService(svc)
	if err != nil {
		// Expected without network
		t.Logf("RegisterService returned error (expected without network): %v", err)
	}
}

func TestResponderRegisterServiceDetachesCallerState(t *testing.T) {
	r := NewResponder(DefaultConfig(), nil)
	r.probedHostnames["host.local."] = true
	svc := &Service{
		InstanceName: "Printer", ServiceType: "_http._tcp", HostName: "host.local.",
		Port: 80, TXT: map[string]string{"path": "/original"},
	}
	if err := r.RegisterService(svc); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterService(nil); err == nil {
		t.Fatal("nil service registration succeeded")
	}

	svc.Port = 8080
	svc.TXT["path"] = "/mutated"
	stored := r.services["Printer._http._tcp.local."]
	if stored == nil || stored.Port != 80 || stored.TXT["path"] != "/original" {
		t.Fatalf("caller mutation changed registered service: %#v", stored)
	}
}

func TestResponderRegisterHostnameDetachesIP(t *testing.T) {
	r := NewResponder(DefaultConfig(), nil)
	r.probedHostnames["host.local."] = true
	ip := net.IPv4(192, 0, 2, 1)
	if err := r.RegisterHostname("host.local.", ip); err != nil {
		t.Fatal(err)
	}
	ip[len(ip)-1] = 99
	if got := r.hostnames["host.local."].String(); got != "192.0.2.1" {
		t.Fatalf("caller mutation changed registered address: %s", got)
	}
}

func TestResponder_UnregisterService(t *testing.T) {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	cfg := DefaultConfig()

	r := NewResponder(cfg, logger)

	svc := &Service{
		InstanceName: "Temp Service",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "temp.local",
		Port:         80,
	}

	// Manually add to services map (simulating registration)
	r.services[svc.FullServiceName()] = svc

	// Unregister
	r.UnregisterService(svc.FullServiceName())

	// Verify removed
	r.servicesMu.RLock()
	_, ok := r.services[svc.FullServiceName()]
	r.servicesMu.RUnlock()
	if ok {
		t.Error("Service should be unregistered")
	}
}

func TestCache_ExpireFunction(t *testing.T) {
	cache := NewCache()

	// Add expired entry
	cache.mu.Lock()
	cache.entries["expired.service."] = &cacheEntry{
		service: &Service{
			InstanceName: "Expired",
			ServiceType:  "_http._tcp",
			Domain:       "local",
			TTL:          1,
		},
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	cache.mu.Unlock()

	// Add valid entry
	cache.Add(&Service{
		InstanceName: "Valid",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		TTL:          120,
	})

	if cache.Len() != 2 {
		t.Errorf("Before expire: Len() = %d, want 2", cache.Len())
	}

	cache.Expire()

	if cache.Len() != 1 {
		t.Errorf("After expire: Len() = %d, want 1", cache.Len())
	}

	if cache.Get("Expired._http._tcp.local.") != nil {
		t.Error("Expired service should be removed")
	}
}
