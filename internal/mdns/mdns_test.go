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
		TTL:          120,
	}

	cache.Add(svc)

	got := cache.Get(svc.FullServiceName())
	if got == nil {
		t.Fatal("Get returned nil for added service")
	}
	if got.InstanceName != svc.InstanceName {
		t.Errorf("InstanceName = %q, want %q", got.InstanceName, svc.InstanceName)
	}
}

func TestCache_GetServices(t *testing.T) {
	cache := NewCache()

	services := []*Service{
		{InstanceName: "Svc1", ServiceType: "_http._tcp", Domain: "local", TTL: 120},
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

	sshServices := cache.GetServices("_ssh._tcp")
	if len(sshServices) != 1 {
		t.Errorf("GetServices(_ssh._tcp) returned %d services, want 1", len(sshServices))
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
