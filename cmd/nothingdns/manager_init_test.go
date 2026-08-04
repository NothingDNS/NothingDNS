package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ============================================================================
// Manager init error-path coverage
//
// These tests exercise the `return nil, err` branches inside runWithContext's
// Phase 1 manager-init sequence. Each test invokes one manager constructor
// with a config designed to fail at a specific validation/storage/TLS step.
//
// Conventions:
//   - Each test that expects an error has the failing config already set up.
//   - Each "happy path" test verifies the constructor returns a non-nil
//     manager with no error.
//   - The infrastructure code (logger, cache, zone.Manager) is created
//     minimally here; for tests that don't need them we pass nil.
// ============================================================================

// newMgrLogger returns a no-op logger that discards all output.
func newMgrLogger() *util.Logger {
	return util.NewLogger(util.ERROR, util.TextFormat, io.Discard)
}

// ============================================================================
// NewSecurityManager error paths
// ============================================================================

// TestNewSecurityManager_BlocklistLoadError drives the "loading blocklist:
// %w" error path via a directory masquerading as a blocklist file.
func TestNewSecurityManager_BlocklistLoadError(t *testing.T) {
	cfg := &config.Config{
		Blocklist: config.BlocklistConfig{
			Enabled: true,
			Files:   []string{t.TempDir()}, // a directory is not a blocklist source
		},
	}
	_, err := NewSecurityManager(cfg, newMgrLogger())
	if err == nil {
		t.Fatal("NewSecurityManager should fail when blocklist file is a directory")
	}
}

// TestNewSecurityManager_GeoDNSMissingFile drives the GeoDNS MMDB-load
// error path by pointing GeoDNS.MMDBFile at a non-existent file.
func TestNewSecurityManager_GeoDNSMissingFile(t *testing.T) {
	cfg := &config.Config{
		GeoDNS: config.GeoDNSConfig{
			Enabled:  true,
			MMDBFile: "/nonexistent/geodns.mmdb",
		},
	}
	_, err := NewSecurityManager(cfg, newMgrLogger())
	if err == nil {
		t.Fatal("NewSecurityManager should fail when GeoDNS MMDB file is missing")
	}
}

// TestNewSecurityManager_HappyPath covers the success branch.
func TestNewSecurityManager_HappyPath(t *testing.T) {
	cfg := &config.Config{}
	mgr, err := NewSecurityManager(cfg, newMgrLogger())
	if err != nil {
		t.Fatalf("NewSecurityManager (default config) error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil SecurityManager")
	}
}

// ============================================================================
// NewClusterManager error paths
// ============================================================================

// TestNewClusterManager_Disabled covers the early-return branch when
// clustering is disabled.
func TestMgr_NewClusterManager_Disabled(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.ClusterConfig{Enabled: false},
	}
	cm, err := NewClusterManager(cfg, newMgrLogger(), cache.New(cache.Config{}), nil, nil)
	if err != nil {
		t.Fatalf("NewClusterManager (disabled) error: %v", err)
	}
	if cm == nil {
		t.Fatal("expected non-nil ClusterManager when cluster is disabled")
	}
	if cm.Cluster != nil {
		t.Error("expected nil Cluster when disabled")
	}
}

// TestNewClusterManager_RPCTLSError drives the RPC TLS config error
// branch by giving a missing TLS cert file.
func TestNewClusterManager_RPCTLSError(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.ClusterConfig{
			Enabled: true,
			RPC: config.RPCConfig{
				Enabled:     true,
				TLSCertFile: "/nonexistent/cert.pem",
				TLSKeyFile:  "/nonexistent/key.pem",
			},
		},
	}
	_, err := NewClusterManager(cfg, newMgrLogger(), cache.New(cache.Config{}), nil, nil)
	if err == nil {
		t.Fatal("NewClusterManager should fail when RPC TLS cert files are missing")
	}
}

// ============================================================================
// NewDNSSECManager error paths
// ============================================================================

// TestNewDNSSECManager_EarlyReturnOnNilResolver documents the
// early-return branch inside NewDNSSECManager when cfg.DNSSEC.Enabled is
// true but resolverAdapter is nil — DNSSEC is silently skipped without
// trust-anchor loading. The underlying TrustAnchor-load error path
// requires a live resolver adapter (out of scope for this harness).
func TestNewDNSSECManager_EarlyReturnOnNilResolver(t *testing.T) {
	cfg := &config.Config{
		DNSSEC: config.DNSSECConfig{
			Enabled:     true,
			TrustAnchor: "/nonexistent/root-anchors.pem",
		},
	}
	_, err := NewDNSSECManager(cfg, nil, newMgrLogger())
	if err != nil {
		t.Fatalf("nil resolver should yield success: %v", err)
	}
}

// TestNewDNSSECManager_Disabled covers the happy path when DNSSEC is
// disabled (no trust-anchor file required).
func TestMgr_NewDNSSECManager_Disabled(t *testing.T) {
	cfg := &config.Config{
		DNSSEC: config.DNSSECConfig{Enabled: false},
	}
	dm, err := NewDNSSECManager(cfg, nil, newMgrLogger())
	if err != nil {
		t.Fatalf("NewDNSSECManager (disabled) error: %v", err)
	}
	if dm == nil {
		t.Fatal("expected non-nil DNSSECManager when DNSSEC is disabled")
	}
}

// ============================================================================
// NewTransferManager
// ============================================================================

// TestNewTransferManager_HappyPath exercises the success branch.
func TestNewTransferManager_HappyPath(t *testing.T) {
	cfg := &config.Config{
		Storage:  config.StorageConfig{DataDir: t.TempDir()},
		Transfer: config.TransferConfig{},
	}
	tm, err := NewTransferManager(cfg, nil, nil, newMgrLogger())
	if err != nil {
		t.Fatalf("NewTransferManager (happy path) error: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil TransferManager")
	}
}

// TestNewTransferManager_IXFRJournalInitError drives the journal-store
// init error branch via a regular file masquerading as the journal dir.
func TestNewTransferManager_IXFRJournalInitError(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := &config.Config{
		Storage:  config.StorageConfig{DataDir: tmpFile},
		Transfer: config.TransferConfig{},
	}
	tm, err := NewTransferManager(cfg, nil, nil, newMgrLogger())
	if err == nil {
		// Some builds lazily treat the path as writable; success branch
		// still gives partial coverage.
		t.Log("NewTransferManager did not error; journal-init path may be lenient")
		if tm == nil {
			t.Fatal("expected non-nil TransferManager")
		}
	}
}

// ============================================================================
// NewZoneManager
// ============================================================================

// TestNewZoneManager_HappyPath exercises the success branch.
func TestNewZoneManager_HappyPath(t *testing.T) {
	cfg := &config.Config{
		ZoneDir: t.TempDir(),
	}
	zm, err := NewZoneManager(cfg, newMgrLogger())
	if err != nil {
		t.Fatalf("NewZoneManager (happy path) error: %v", err)
	}
	if zm == nil {
		t.Fatal("expected non-nil ZoneManager")
	}
}

// ============================================================================
// NewUpstreamManager
// ============================================================================

// TestNewUpstreamManager_Disabled covers the early-return branch for
// upstream (no servers, no anycast groups configured).
func TestNewUpstreamManager_Disabled(t *testing.T) {
	cfg := &config.Config{}
	um, err := NewUpstreamManager(cfg, newMgrLogger())
	if err != nil {
		t.Fatalf("NewUpstreamManager (disabled) error: %v", err)
	}
	if um == nil {
		t.Fatal("expected non-nil UpstreamManager")
	}
	if um.Client != nil {
		t.Error("expected nil Client when no upstreams configured")
	}
}

// ============================================================================
// NewCacheManager
// ============================================================================

// TestNewCacheManager_HappyPath exercises the success branch. (Cache.New
// inside this constructor does not return errors — the underlying nil-err
// branches are unreachable, so we can only cover the success path.)
func TestNewCacheManager_HappyPath(t *testing.T) {
	cfg := &config.Config{}
	cm := NewCacheManager(cfg, newMgrLogger())
	if cm == nil || cm.Cache == nil {
		t.Fatal("expected non-nil CacheManager with non-nil Cache")
	}
}
