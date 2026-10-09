package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/util"
)

func TestNewSecurityManagerBlocklistLoadError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocklist.Enabled = true
	cfg.Blocklist.Files = []string{filepath.Join(t.TempDir(), "missing-blocklist.txt")}

	mgr, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err == nil {
		t.Fatal("expected blocklist load error")
	}
	if mgr != nil {
		t.Fatal("expected nil manager on blocklist load error")
	}
	if !strings.Contains(err.Error(), "loading blocklist") {
		t.Fatalf("error = %q, want blocklist context", err)
	}
}

func TestNewSecurityManagerRPZLoadError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RPZ.Enabled = true
	cfg.RPZ.Files = []string{filepath.Join(t.TempDir(), "missing-rpz.zone")}

	mgr, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err == nil {
		t.Fatal("expected RPZ load error")
	}
	if mgr != nil {
		t.Fatal("expected nil manager on RPZ load error")
	}
	if !strings.Contains(err.Error(), "loading RPZ zones") {
		t.Fatalf("error = %q, want RPZ context", err)
	}
}

func TestNewSecurityManagerDNS64ExcludeNetError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNS64.Enabled = true
	cfg.DNS64.ExcludeNets = []string{"not-a-cidr"}

	mgr, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err == nil {
		t.Fatal("expected DNS64 exclude network error")
	}
	if mgr != nil {
		t.Fatal("expected nil manager on DNS64 exclude network error")
	}
	if !strings.Contains(err.Error(), "adding DNS64 exclude network") {
		t.Fatalf("error = %q, want DNS64 exclude context", err)
	}
}

func TestNewSecurityManagerValidSecuritySources(t *testing.T) {
	tmpDir := t.TempDir()
	blocklistFile := filepath.Join(tmpDir, "blocklist.txt")
	if err := os.WriteFile(blocklistFile, []byte("blocked.example\n"), 0644); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}
	rpzFile := filepath.Join(tmpDir, "rpz.zone")
	if err := os.WriteFile(rpzFile, []byte("blocked.example.rpz-qname 300 IN CNAME .\n"), 0644); err != nil {
		t.Fatalf("write rpz: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Blocklist.Enabled = true
	cfg.Blocklist.Files = []string{blocklistFile}
	cfg.RPZ.Enabled = true
	cfg.RPZ.Files = []string{rpzFile}
	cfg.DNS64.Enabled = true
	cfg.DNS64.ExcludeNets = []string{"2001:db8::/32"}

	mgr, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewSecurityManager: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected security manager")
	}
	mgr.Stop()
}

// A disabled rate limiter must still exist so PUT /api/v1/config/rrl can
// enable it; a nil one makes that endpoint answer 503 forever (F634).
func TestNewSecurityManagerDisabledRateLimiterIsToggleable(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RRL.Enabled = false
	cfg.RRL.Rate = 1
	cfg.RRL.Burst = 1

	mgr, err := NewSecurityManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	rl := mgr.Result().RateLimiter
	if rl == nil {
		t.Fatal("RateLimiter is nil with rrl.enabled false")
	}
	ip := net.ParseIP("192.0.2.9")
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Fatal("disabled limiter dropped a query")
		}
	}
	rl.SetEnabled(true)
	rl.Allow(ip)
	if rl.Allow(ip) {
		t.Error("limiter not enforcing after runtime enable")
	}
}
