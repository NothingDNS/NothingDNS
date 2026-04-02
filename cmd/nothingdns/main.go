// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	Name = "NothingDNS"
)

var (
	configPath  = flag.String("config", "/etc/nothingdns/nothingdns.yaml", "Path to configuration file")
	showVersion = flag.Bool("version", false, "Show version and exit")
	showHelp    = flag.Bool("help", false, "Show help and exit")
)

// DNSServer wraps UDP and TCP servers.
type DNSServer struct {
	udpServer *server.UDPServer
	tcpServer *server.TCPServer
}

// dnssecResolverAdapter adapts upstream.Client or upstream.LoadBalancer to dnssec.Resolver interface
type dnssecResolverAdapter struct {
	upstream interface {
		Query(msg *protocol.Message) (*protocol.Message, error)
	}
}

// Query implements dnssec.Resolver interface
func (d *dnssecResolverAdapter) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	parsedName, err := protocol.ParseName(name)
	if err != nil {
		return nil, fmt.Errorf("parsing name %q: %w", name, err)
	}
	// Create a query message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   parsedName,
				QType:  qtype,
				QClass: protocol.ClassIN,
			},
		},
	}
	return d.upstream.Query(msg)
}

// integratedHandler is the DNS request handler that uses all components.
type integratedHandler struct {
	config        *config.Config
	logger        *util.Logger
	cache         *cache.Cache
	upstream      *upstream.Client
	loadBalancer  *upstream.LoadBalancer
	zones         map[string]*zone.Zone
	zonesMu       sync.RWMutex
	blocklist     *blocklist.Blocklist
	metrics       *metrics.MetricsCollector
	validator     *dnssec.Validator
	zoneSigners   map[string]*dnssec.Signer
	cluster       *cluster.Cluster
	axfrServer    *transfer.AXFRServer
	ixfrServer    *transfer.IXFRServer
	notifyHandler *transfer.NOTIFYSlaveHandler
	ddnsHandler   *transfer.DynamicDNSHandler
	slaveManager  *transfer.SlaveManager
	aclChecker    *filter.ACLChecker
	rateLimiter   *filter.RateLimiter
	auditLogger   *audit.AuditLogger

	notifyOnce sync.Once
	updateOnce sync.Once
}

func main() {
	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", Name, util.Version)
		os.Exit(0)
	}

	// Initialize and start server
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Initialize logger
	level := logLevelFromString(cfg.Logging.Level)
	format := logFormatFromString(cfg.Logging.Format)
	var output *os.File = os.Stdout
	if cfg.Logging.Output == "stderr" {
		output = os.Stderr
	}
	logger := util.NewLogger(level, format, output)
	logger.Infof("Starting %s v%s", Name, util.Version)

	// Initialize cache
	cacheConfig := cache.Config{
		Capacity:          cfg.Cache.Size,
		MinTTL:            time.Duration(cfg.Cache.MinTTL) * time.Second,
		MaxTTL:            time.Duration(cfg.Cache.MaxTTL) * time.Second,
		DefaultTTL:        time.Duration(cfg.Cache.DefaultTTL) * time.Second,
		NegativeTTL:       time.Duration(cfg.Cache.NegativeTTL) * time.Second,
		PrefetchEnabled:   cfg.Cache.Prefetch,
		PrefetchThreshold: time.Duration(cfg.Cache.PrefetchThreshold) * time.Second,
	}
	dnsCache := cache.New(cacheConfig)
	logger.Infof("Cache initialized with capacity %d", cfg.Cache.Size)

	// Initialize upstream client (with optional load balancer for anycast)
	var client *upstream.Client
	var loadBalancer *upstream.LoadBalancer
	if len(cfg.Upstream.Servers) > 0 || len(cfg.Upstream.AnycastGroups) > 0 {
		// Check if anycast groups are configured
		if len(cfg.Upstream.AnycastGroups) > 0 {
			// Use advanced load balancer with anycast support
			lbConfig := upstream.LoadBalancerConfig{
				Servers:         cfg.Upstream.Servers,
				Strategy:        cfg.Upstream.Strategy,
				HealthCheck:     parseDurationOrDefault(cfg.Upstream.HealthCheck, 30*time.Second),
				FailoverTimeout: parseDurationOrDefault(cfg.Upstream.FailoverTimeout, 5*time.Second),
				Region:          cfg.Upstream.Topology.Region,
				Zone:            cfg.Upstream.Topology.Zone,
				Weight:          cfg.Upstream.Topology.Weight,
			}

			// Convert anycast group configs
			for _, groupConfig := range cfg.Upstream.AnycastGroups {
				group := upstream.AnycastGroupConfig{
					AnycastIP:   groupConfig.AnycastIP,
					HealthCheck: groupConfig.HealthCheck,
				}
				for _, backendConfig := range groupConfig.Backends {
					group.Backends = append(group.Backends, upstream.AnycastBackendConfig{
						PhysicalIP: backendConfig.PhysicalIP,
						Port:       backendConfig.Port,
						Region:     backendConfig.Region,
						Zone:       backendConfig.Zone,
						Weight:     backendConfig.Weight,
					})
				}
				lbConfig.AnycastGroups = append(lbConfig.AnycastGroups, group)
			}

			var err error
			loadBalancer, err = upstream.NewLoadBalancer(lbConfig)
			if err != nil {
				logger.Warnf("Failed to initialize load balancer: %v", err)
			} else {
				totalBackends := 0
				for _, group := range loadBalancer.GetAnycastGroups() {
					total, _ := group.Stats()
					totalBackends += total
				}
				logger.Infof("Load balancer initialized with %d anycast groups (%d total backends)",
					len(lbConfig.AnycastGroups), totalBackends)
				if len(cfg.Upstream.Servers) > 0 {
					logger.Infof("Load balancer also has %d standalone servers", len(cfg.Upstream.Servers))
				}
			}
		} else {
			// Use standard upstream client
			upstreamConfig := upstream.Config{
				Servers:     cfg.Upstream.Servers,
				Strategy:    cfg.Upstream.Strategy,
				Timeout:     parseDurationOrDefault(cfg.Resolution.Timeout, 5*time.Second),
				HealthCheck: parseDurationOrDefault(cfg.Upstream.HealthCheck, 30*time.Second),
			}
			client, err = upstream.NewClient(upstreamConfig)
			if err != nil {
				logger.Warnf("Failed to initialize upstream client: %v", err)
			} else {
				logger.Infof("Upstream client initialized with %d servers", len(cfg.Upstream.Servers))
			}
		}
	}

	// Load zone files
	zones := make(map[string]*zone.Zone)
	zoneFiles := make(map[string]string) // origin -> file path mapping
	for _, zoneFile := range cfg.Zones {
		z, err := loadZoneFile(zoneFile)
		if err != nil {
			logger.Warnf("Failed to load zone file %s: %v", zoneFile, err)
			continue
		}
		zones[z.Origin] = z
		zoneFiles[z.Origin] = zoneFile
		logger.Infof("Loaded zone %s with %d records", z.Origin, len(z.Records))
	}

	// Initialize zone signers if DNSSEC signing is enabled
	zoneSigners := make(map[string]*dnssec.Signer)
	if cfg.DNSSEC.Enabled && cfg.DNSSEC.Signing.Enabled {
		for origin, z := range zones {
			signer, err := loadZoneSigner(z, cfg.DNSSEC.Signing)
			if err != nil {
				logger.Warnf("Failed to load zone signer for %s: %v", origin, err)
				continue
			}
			if signer != nil {
				zoneSigners[origin] = signer
				logger.Infof("Zone signer loaded for %s (%d keys)", origin, len(signer.GetKeys()))
			}
		}
	}

	// Initialize blocklist
	bl := blocklist.New(blocklist.Config{
		Enabled: cfg.Blocklist.Enabled,
		Files:   cfg.Blocklist.Files,
	})
	if err := bl.Load(); err != nil {
		logger.Warnf("Failed to load blocklist: %v", err)
	} else if cfg.Blocklist.Enabled {
		stats := bl.Stats()
		logger.Infof("Blocklist loaded with %d entries from %d files", stats.TotalBlocks, stats.Files)
	}

	// Initialize metrics collector
	metricsCollector := metrics.New(metrics.Config{
		Enabled: cfg.Metrics.Enabled,
		Bind:    cfg.Metrics.Bind,
		Path:    cfg.Metrics.Path,
	})
	if err := metricsCollector.Start(); err != nil {
		logger.Warnf("Failed to start metrics server: %v", err)
	} else if cfg.Metrics.Enabled {
		logger.Infof("Metrics server listening on %s%s", cfg.Metrics.Bind, cfg.Metrics.Path)
	}

	// Initialize DNSSEC validator if enabled
	var validator *dnssec.Validator
	if cfg.DNSSEC.Enabled && (client != nil || loadBalancer != nil) {
		trustAnchors := dnssec.NewTrustAnchorStoreWithBuiltIn()

		// Load custom trust anchors if specified
		if cfg.DNSSEC.TrustAnchor != "" {
			if err := trustAnchors.LoadFromFile(cfg.DNSSEC.TrustAnchor); err != nil {
				logger.Warnf("Failed to load trust anchor file: %v", err)
			} else {
				logger.Infof("Loaded trust anchors from %s", cfg.DNSSEC.TrustAnchor)
			}
		}

		// Create resolver adapter - prefer loadBalancer if available
		var resolverAdapter dnssec.Resolver
		if loadBalancer != nil {
			resolverAdapter = &dnssecResolverAdapter{upstream: loadBalancer}
		} else {
			resolverAdapter = &dnssecResolverAdapter{upstream: client}
		}

		validator = dnssec.NewValidator(dnssec.ValidatorConfig{
			Enabled:    cfg.DNSSEC.Enabled,
			IgnoreTime: cfg.DNSSEC.IgnoreTime,
		}, trustAnchors, resolverAdapter)

		logger.Info("DNSSEC validation enabled")
	}

	// Stop channel for graceful goroutine shutdown
	stopCh := make(chan struct{})

	// Initialize cluster manager if enabled
	var clusterMgr *cluster.Cluster
	if cfg.Cluster.Enabled {
		clusterConfig := cluster.Config{
			Enabled:   cfg.Cluster.Enabled,
			NodeID:    cfg.Cluster.NodeID,
			BindAddr:  cfg.Cluster.BindAddr,
			GossipPort: cfg.Cluster.GossipPort,
			Region:    cfg.Cluster.Region,
			Zone:      cfg.Cluster.Zone,
			Weight:    cfg.Cluster.Weight,
			SeedNodes: cfg.Cluster.SeedNodes,
			CacheSync: cfg.Cluster.CacheSync,
			HTTPAddr:  cfg.Server.HTTP.Bind,
		}

		clusterMgr, err = cluster.New(clusterConfig, logger, dnsCache)
		if err != nil {
			logger.Warnf("Failed to initialize cluster: %v", err)
		} else {
			if err := clusterMgr.Start(); err != nil {
				logger.Warnf("Failed to start cluster: %v", err)
				clusterMgr = nil
			} else {
				logger.Infof("Cluster initialized with node ID %s", clusterMgr.GetNodeID())
				logger.Infof("Cluster has %d nodes", clusterMgr.GetNodeCount())

				// Set up cache invalidation callback for cluster sync
				if cfg.Cluster.CacheSync {
					dnsCache.SetInvalidateFunc(func(key string) {
						if err := clusterMgr.InvalidateCache([]string{key}); err != nil {
							logger.Debugf("Failed to broadcast cache invalidation: %v", err)
						}
					})
					logger.Info("Cache synchronization enabled across cluster")
				}

				// Start cluster metrics updater
				go func() {
					ticker := time.NewTicker(30 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							if clusterMgr != nil && metricsCollector != nil {
								stats := clusterMgr.Stats()
								metricsCollector.SetClusterMetrics(
									stats.NodeCount,
									stats.AliveCount,
									stats.IsHealthy,
									stats.GossipStats.MessagesSent,
									stats.GossipStats.MessagesReceived,
								)
							}
						case <-stopCh:
							return
						}
					}
				}()
			}
		}
	}

	// Initialize zone manager (use already-loaded zones to avoid duplicate parsing)
	zoneManager := zone.NewManager()
	for origin, z := range zones {
		zoneManager.LoadZone(z, zoneFiles[origin])
	}

	// Initialize AXFR server for zone transfers
	// Note: zonesMu is set later after handler is created
	axfrServer := transfer.NewAXFRServer(zones)
	logger.Infof("AXFR server initialized with %d zones", len(zones))

	// Initialize IXFR server for incremental zone transfers
	ixfrServer := transfer.NewIXFRServer(axfrServer)
	logger.Infof("IXFR server initialized for incremental transfers")

	// Initialize NOTIFY handler for slave servers
	notifyHandler := transfer.NewNOTIFYSlaveHandler(zones)
	logger.Infof("NOTIFY handler initialized for %d zones", len(zones))

	// Initialize Dynamic DNS handler
	ddnsHandler := transfer.NewDynamicDNSHandler(zones)
	logger.Infof("Dynamic DNS handler initialized for %d zones", len(zones))

	// Initialize Slave Manager for automatic zone transfers
	keyStore := transfer.NewKeyStore()
	slaveManager := transfer.NewSlaveManager(keyStore)
	logger.Info("Slave manager initialized for automatic zone transfers")

	// Configure slave zones from config if available
	for _, slaveConfig := range cfg.SlaveZones {
		// Convert config.SlaveZoneConfig to transfer.SlaveZoneConfig
		transferConfig := transfer.SlaveZoneConfig{
			ZoneName:      slaveConfig.ZoneName,
			Masters:       slaveConfig.Masters,
			TransferType:  slaveConfig.TransferType,
			TSIGKeyName:   slaveConfig.TSIGKeyName,
			TSIGSecret:    slaveConfig.TSIGSecret,
			Timeout:       parseDurationOrDefault(slaveConfig.Timeout, 30*time.Second),
			RetryInterval: parseDurationOrDefault(slaveConfig.RetryInterval, 5*time.Minute),
			MaxRetries:    slaveConfig.MaxRetries,
		}

		if err := slaveManager.AddSlaveZone(transferConfig); err != nil {
			logger.Warnf("Failed to add slave zone %s: %v", slaveConfig.ZoneName, err)
		} else {
			logger.Infof("Added slave zone %s (masters: %v)", slaveConfig.ZoneName, slaveConfig.Masters)
		}
	}

	// Start the slave manager
	slaveManager.Start()
	logger.Info("Slave manager started")

	// Initialize ACL checker
	var aclChecker *filter.ACLChecker
	if len(cfg.ACL) > 0 {
		var err error
		aclChecker, err = filter.NewACLChecker(cfg.ACL)
		if err != nil {
			return fmt.Errorf("initializing ACL: %w", err)
		}
		logger.Infof("ACL loaded with %d rules", len(cfg.ACL))
	}

	// Initialize rate limiter
	var rateLimiter *filter.RateLimiter
	if cfg.RRL.Enabled {
		rateLimiter = filter.NewRateLimiter(cfg.RRL)
		logger.Infof("RRL enabled: %d qps/client, burst %d", cfg.RRL.Rate, cfg.RRL.Burst)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewAuditLogger(cfg.Logging.QueryLog, cfg.Logging.QueryLogFile)
	if err != nil {
		logger.Warnf("Failed to initialize audit logger: %v", err)
	} else if cfg.Logging.QueryLog {
		logger.Info("Query audit logging enabled")
	}

	// Create DNS handler (needed for API server DoH support)
	handler := &integratedHandler{
		config:        cfg,
		logger:        logger,
		cache:         dnsCache,
		upstream:      client,
		loadBalancer:  loadBalancer,
		zones:         zones,
		blocklist:     bl,
		metrics:       metricsCollector,
		validator:     validator,
		zoneSigners:   zoneSigners,
		cluster:       clusterMgr,
		axfrServer:    axfrServer,
		ixfrServer:    ixfrServer,
		notifyHandler: notifyHandler,
		ddnsHandler:   ddnsHandler,
		slaveManager:  slaveManager,
		aclChecker:    aclChecker,
		rateLimiter:   rateLimiter,
		auditLogger:   auditLogger,
	}

	// Share the zones mutex between handler, AXFR server, and DDNS handler
	// to prevent data races on the shared zones map
	axfrServer.SetZonesMu(&handler.zonesMu)
	ddnsHandler.SetZonesMu(&handler.zonesMu)

	// Initialize API server
	apiServer := api.NewServer(cfg.Server.HTTP, zoneManager, dnsCache, func() error {
		logger.Info("Reloading configuration via API...")
		// Reload zone files
		for _, zoneFile := range cfg.Zones {
			z, err := loadZoneFile(zoneFile)
			if err != nil {
				logger.Warnf("Failed to reload zone file %s: %v", zoneFile, err)
				continue
			}
			handler.zonesMu.Lock()
			zones[z.Origin] = z
			handler.zonesMu.Unlock()
			zoneFiles[z.Origin] = zoneFile
			zoneManager.LoadZone(z, zoneFile)
			logger.Infof("Reloaded zone %s", z.Origin)
		}
		// Reload blocklist
		if bl != nil {
			if err := bl.Reload(); err != nil {
				logger.Warnf("Failed to reload blocklist: %v", err)
			}
		}
		return nil
	}, handler, clusterMgr)
	if err := apiServer.Start(); err != nil {
		logger.Warnf("Failed to start API server: %v", err)
	} else if cfg.Server.HTTP.Enabled {
		logger.Infof("API server listening on %s", cfg.Server.HTTP.Bind)
		if cfg.Server.HTTP.DoHEnabled {
			logger.Infof("DoH endpoint enabled at %s", cfg.Server.HTTP.DoHPath)
		}
	}

	// Create and start DNS servers
	udpAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	tcpAddr := fmt.Sprintf(":%d", cfg.Server.Port)

	udpServer := server.NewUDPServer(udpAddr, handler)
	tcpServer := server.NewTCPServer(tcpAddr, handler)

	// Start UDP server
	if err := udpServer.Listen(); err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	go func() {
		if err := udpServer.Serve(); err != nil {
			logger.Errorf("UDP server error: %v", err)
		}
	}()
	logger.Infof("UDP server listening on %s", udpAddr)

	// Start TCP server
	if err := tcpServer.Listen(); err != nil {
		return fmt.Errorf("starting TCP server: %w", err)
	}
	go func() {
		if err := tcpServer.Serve(); err != nil {
			logger.Errorf("TCP server error: %v", err)
		}
	}()
	logger.Infof("TCP server listening on %s", tcpAddr)

	// Start TLS server if enabled
	var tlsServer *server.TLSServer
	if cfg.Server.TLS.Enabled {
		tlsAddr := cfg.Server.TLS.Bind
		if tlsAddr == "" {
			tlsAddr = fmt.Sprintf(":%d", server.DefaultTLSPort)
		}

		// Load TLS certificate
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		tlsServer = server.NewTLSServer(tlsAddr, handler, tlsConfig)
		if err := tlsServer.Listen(); err != nil {
			return fmt.Errorf("starting TLS server: %w", err)
		}
		go func() {
			if err := tlsServer.Serve(); err != nil {
				logger.Errorf("TLS server error: %v", err)
			}
		}()
		logger.Infof("TLS server listening on %s (DoT)", tlsAddr)
	}

	// Periodically collect transport stats
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if metricsCollector != nil {
					us := udpServer.Stats()
					ts := tcpServer.Stats()
					metricsCollector.SetTransportStats(
						us.PacketsReceived, us.PacketsSent, us.Errors,
						ts.ConnectionsAccepted, ts.ConnectionsClosed, ts.MessagesReceived, ts.Errors,
					)
				}
			}
		}
	}()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	logger.Info("Server started successfully")

	// Wait for signals
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("Shutting down gracefully...")

			// Signal goroutines to stop
			close(stopCh)

			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer shutdownCancel()

			done := make(chan struct{})
			go func() {
				defer close(done)

				// Stop servers
				udpServer.Stop()
				tcpServer.Stop()
				if tlsServer != nil {
					tlsServer.Stop()
				}

				// Close upstream client
				if client != nil {
					client.Close()
				}

				// Close load balancer
				if loadBalancer != nil {
					loadBalancer.Close()
				}

				// Stop metrics server
				if metricsCollector != nil {
					metricsCollector.Stop()
				}

				// Stop API server
				if apiServer != nil {
					apiServer.Stop()
				}

				// Stop cluster manager
				if clusterMgr != nil {
					clusterMgr.Stop()
				}

				// Stop slave manager
				if slaveManager != nil {
					slaveManager.Stop()
				}

				// Close notify handler so processNotifyEvents goroutine can exit
				if notifyHandler != nil {
					notifyHandler.Close()
				}

				// Close DDNS handler so processUpdateEvents goroutine can exit
				if ddnsHandler != nil {
					ddnsHandler.Close()
				}

				// Close audit logger
				if auditLogger != nil {
					auditLogger.Close()
				}
			}()

			select {
			case <-done:
				logger.Info("Server shutdown complete")
			case <-shutdownCtx.Done():
				logger.Warnf("Server shutdown timed out after 30s")
			}
			return nil

		case syscall.SIGHUP:
			logger.Info("Received SIGHUP, reloading configuration...")
			// Reload zone files
			for _, zoneFile := range cfg.Zones {
				z, err := loadZoneFile(zoneFile)
				if err != nil {
					logger.Warnf("Failed to reload zone file %s: %v", zoneFile, err)
					continue
				}
				handler.zonesMu.Lock()
				zones[z.Origin] = z
				handler.zonesMu.Unlock()
				zoneFiles[z.Origin] = zoneFile
				zoneManager.LoadZone(z, zoneFile)
				logger.Infof("Reloaded zone %s", z.Origin)
			}
			// Reload blocklist
			if bl != nil {
				if err := bl.Reload(); err != nil {
					logger.Warnf("Failed to reload blocklist: %v", err)
				} else {
					stats := bl.Stats()
					logger.Infof("Reloaded blocklist with %d entries from %d files", stats.TotalBlocks, stats.Files)
				}
			}
		}
	}
}

// loadConfig loads and validates the configuration file.
func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, use defaults
		if os.IsNotExist(err) {
			cfg := config.DefaultConfig()
			return cfg, nil
		}
		return nil, err
	}

	cfg, err := config.UnmarshalYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Validate configuration
	if errs := cfg.Validate(); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "Config validation error: %s\n", e)
		}
		return nil, fmt.Errorf("configuration validation failed: %d error(s)", len(errs))
	}

	return cfg, nil
}

// loadZoneFile loads a single zone file.
func loadZoneFile(path string) (*zone.Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	z, err := zone.ParseFile(path, f)
	if err != nil {
		return nil, err
	}

	if err := z.Validate(); err != nil {
		return nil, fmt.Errorf("zone validation: %w", err)
	}

	return z, nil
}

// loadZoneSigner creates a DNSSEC signer for a zone from config.
func loadZoneSigner(z *zone.Zone, signingCfg config.SigningConfig) (*dnssec.Signer, error) {
	if !signingCfg.Enabled {
		return nil, nil
	}

	signerCfg := dnssec.DefaultSignerConfig()

	if signingCfg.SignatureValidity != "" {
		if d, err := time.ParseDuration(signingCfg.SignatureValidity); err == nil {
			signerCfg.SignatureValidity = d
		}
	}

	if signingCfg.NSEC3 != nil {
		signerCfg.NSEC3Enabled = true
		signerCfg.NSEC3Iterations = signingCfg.NSEC3.Iterations
		if signingCfg.NSEC3.Salt != "" {
			salt, err := hex.DecodeString(signingCfg.NSEC3.Salt)
			if err != nil {
				return nil, fmt.Errorf("parsing NSEC3 salt: %w", err)
			}
			signerCfg.NSEC3Salt = salt
		}
	}

	signer := dnssec.NewSigner(z.Origin, signerCfg)

	// Generate key pairs from config
	for _, keyConfig := range signingCfg.Keys {
		if keyConfig.PrivateKey == "" {
			continue
		}

		isKSK := keyConfig.Type == "ksk"
		_, err := signer.GenerateKeyPair(keyConfig.Algorithm, isKSK)
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
	}

	return signer, nil
}

// ServeDNS implements the server.Handler interface.
func (h *integratedHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	start := time.Now()

	// Defer latency recording and audit logging
	var qtypeStr string
	var qnameAudit string
	var cacheHit bool
	defer func() {
		latency := time.Since(start)
		if h.metrics != nil && qtypeStr != "" {
			h.metrics.RecordQueryLatency(qtypeStr, latency)
		}
		if h.auditLogger != nil && qtypeStr != "" {
			clientIP := "-"
			if ci := w.ClientInfo(); ci != nil && ci.IP() != nil {
				clientIP = ci.IP().String()
			}
			h.auditLogger.LogQuery(audit.QueryAuditEntry{
				Timestamp: start.UTC().Format(time.RFC3339),
				ClientIP:  clientIP,
				QueryName: qnameAudit,
				QueryType: qtypeStr,
				Latency:    latency,
				CacheHit:   cacheHit,
			})
		}
	}()

	// Check if we have questions
	if len(r.Questions) == 0 {
		h.logger.Debug("Query with no questions")
		sendError(w, r, protocol.RcodeFormatError)
		return
	}

	q := r.Questions[0]
	qname := q.Name.String()
	qtype := q.QType
	qtypeStr = typeToString(qtype)
	qnameAudit = qname

	h.logger.Debugf("Query: %s %s", qname, typeToString(qtype))

	// Record query metric
	if h.metrics != nil {
		h.metrics.RecordQuery(typeToString(qtype))
	}

	// Check ACL
	clientIP := w.ClientInfo().IP()
	if h.aclChecker != nil && clientIP != nil {
		allowed, redirect := h.aclChecker.IsAllowed(clientIP, qtype)
		if !allowed {
			if redirect != "" {
				h.logger.Infof("ACL redirect: %s %s from %s -> %s", qname, typeToString(qtype), clientIP, redirect)
				h.handleACLRedirect(w, r, q, redirect)
			} else {
				h.logger.Infof("ACL denied: %s %s from %s", qname, typeToString(qtype), clientIP)
				sendError(w, r, protocol.RcodeRefused)
			}
			return
		}
	}

	// Check rate limit
	if h.rateLimiter != nil && clientIP != nil {
		if !h.rateLimiter.Allow(clientIP) {
			h.logger.Debugf("RRL dropped: %s %s from %s", qname, typeToString(qtype), clientIP)
			if h.metrics != nil {
				h.metrics.RecordRateLimited()
			}
			sendError(w, r, protocol.RcodeRefused)
			return
		}
	}

	// Handle AXFR (zone transfer) requests
	if qtype == protocol.TypeAXFR {
		h.handleAXFR(w, r, q)
		return
	}

	// Handle IXFR (incremental zone transfer) requests
	if qtype == protocol.TypeIXFR {
		h.handleIXFR(w, r, q)
		return
	}

	// Handle NOTIFY requests (RFC 1996)
	if transfer.IsNOTIFYRequest(r) {
		h.handleNOTIFY(w, r, q)
		return
	}

	// Handle Dynamic DNS UPDATE requests (RFC 2136)
	if transfer.IsUpdateRequest(r) {
		h.handleUPDATE(w, r, q)
		return
	}

	// Check blocklist
	if h.blocklist != nil && h.blocklist.IsBlocked(qname) {
		h.logger.Infof("Blocked query for %s", qname)
		if h.metrics != nil {
			h.metrics.RecordBlocklistBlock()
		}
		sendError(w, r, protocol.RcodeNameError)
		return
	}

	// Check cache first
	cacheKey := cache.MakeKey(qname, qtype)
	if entry := h.cache.Get(cacheKey); entry != nil {
		cacheHit = true
		if entry.IsNegative {
			h.logger.Debugf("Cache hit (negative) for %s", qname)
			if h.metrics != nil {
				h.metrics.RecordCacheHit()
				h.metrics.RecordResponse(entry.RCode)
			}
			sendError(w, r, entry.RCode)
			return
		}
		h.logger.Debugf("Cache hit for %s", qname)
		if h.metrics != nil {
			h.metrics.RecordCacheHit()
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		reply(w, r, entry.Message)
		return
	}

	// Record cache miss
	if h.metrics != nil {
		h.metrics.RecordCacheMiss()
	}

	// Check authoritative zones — try direct lookup first.
	// If no zone has a direct record, attempt CNAME chasing across zones,
	// then cache, then upstream.
	h.zonesMu.RLock()
	var matchedZone bool
	for origin, z := range h.zones {
		if isSubdomain(qname, origin) {
			matchedZone = true
			h.logger.Debugf("Checking zone %s for %s", origin, qname)
			if h.handleAuthoritative(z, w, r, q) {
				h.zonesMu.RUnlock()
				return
			}
		}
	}
	h.zonesMu.RUnlock()

	// If the query name falls within one of our zones but no direct record
	// was found, chase CNAME chains before falling through to upstream.
	if matchedZone {
		result := h.chaseCNAMEInZones(qname)
		if result.loopDetected {
			h.logger.Warnf("CNAME loop detected for %s", qname)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendError(w, r, protocol.RcodeServerFailure)
			return
		}
		if len(result.cnameRecords) > 0 {
			// We have a CNAME chain — resolve the target
			targetAnswers := h.resolveCNAMETarget(w, r, q, result.targetName, qtype)
			resp := h.buildCNAMEResponse(r, result.cnameRecords, targetAnswers)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(w, r, resp)
			return
		}
	}

	// Forward to upstream
	if h.upstream != nil || h.loadBalancer != nil {
		h.logger.Debugf("Forwarding query for %s to upstream", qname)
		if h.metrics != nil {
			if len(h.config.Upstream.Servers) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.Servers[0])
			} else if len(h.config.Upstream.AnycastGroups) > 0 {
				h.metrics.RecordUpstreamQuery(h.config.Upstream.AnycastGroups[0].AnycastIP + ":53")
			}
		}

		var resp *protocol.Message
		var err error
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(r)
		} else {
			resp, err = h.upstream.Query(r)
		}
		if err != nil {
			h.logger.Warnf("Upstream query failed for %s: %v", qname, err)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendError(w, r, protocol.RcodeServerFailure)
			return
		}

		// Validate DNSSEC if enabled and response has signatures
		if h.validator != nil && dnssec.HasSignature(resp) {
			ctx := context.Background()
			result, err := h.validator.ValidateResponse(ctx, resp, qname)
			if err != nil {
				h.logger.Warnf("DNSSEC validation error for %s: %v", qname, err)
			}

			switch result {
			case dnssec.ValidationSecure:
				h.logger.Debugf("DNSSEC validation secure for %s", qname)
				// Set AD bit if validation succeeded
				resp.Header.Flags.AD = true
			case dnssec.ValidationBogus:
				h.logger.Warnf("DNSSEC validation failed (bogus) for %s", qname)
				if h.config.DNSSEC.Enabled {
					// Return SERVFAIL if DNSSEC validation failed
					if h.metrics != nil {
						h.metrics.RecordResponse(protocol.RcodeServerFailure)
					}
					sendError(w, r, protocol.RcodeServerFailure)
					return
				}
			case dnssec.ValidationInsecure:
				h.logger.Debugf("DNSSEC insecure zone for %s", qname)
			case dnssec.ValidationIndeterminate:
				h.logger.Debugf("DNSSEC indeterminate for %s", qname)
			}
		}

		// Cache successful response
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			h.cache.Set(cacheKey, resp, ttl)
		}

		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(w, r, resp)
		return
	}

	// No upstream configured
	h.logger.Debugf("No upstream configured, returning NXDOMAIN for %s", qname)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeNameError)
	}
	sendError(w, r, protocol.RcodeNameError)
}

// handleAuthoritative handles queries for authoritative zones.
// It performs direct record lookup. If no records match the query type,
// CNAME chasing is deferred to the caller (ServeDNS) which can resolve
// across zones, cache, and upstream.
func (h *integratedHandler) handleAuthoritative(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question) bool {
	qname := q.Name.String()
	qtype := q.QType

	// Check if client wants DNSSEC (DO bit in OPT record)
	wantsDNSSEC := hasDOBit(r)

	// Look up records matching the requested type
	records := z.Lookup(qname, typeToString(qtype))
	if len(records) > 0 {
		var resp *protocol.Message
		if signer, ok := h.zoneSigners[z.Origin]; ok && wantsDNSSEC {
			resp = h.buildSignedResponse(r, records, signer, true)
		} else {
			resp = h.buildResponse(r, records)
		}
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeSuccess)
		}
		reply(w, r, resp)
		return true
	}

	// No direct records. Check for CNAME — but don't resolve it here.
	// Return false so ServeDNS can do full CNAME chasing (across zones,
	// cache, upstream).
	cnameRecords := z.Lookup(qname, "CNAME")
	if len(cnameRecords) > 0 {
		return false // signal to ServeDNS to chase the CNAME
	}

	return false
}

// cnameChainResult holds the result of chasing a CNAME chain.
type cnameChainResult struct {
	// cnameRecords are the collected CNAME records along the chain.
	cnameRecords []zone.Record
	// targetName is the final name the chain resolves to.
	targetName string
	// loopDetected is true if a CNAME loop was detected.
	loopDetected bool
}

// chaseCNAMEInZones follows a CNAME chain across all local zones starting
// from the given name. It collects every CNAME record encountered and
// stops when the target name is not a CNAME in any local zone, or when
// a loop is detected (max chain depth exceeded or revisited name).
//
// The caller must NOT hold zonesMu; this method acquires the read lock
// internally as needed.
func (h *integratedHandler) chaseCNAMEInZones(name string) cnameChainResult {
	const maxCNAMEDepth = 16

	visited := make(map[string]struct{}, maxCNAMEDepth)
	var result cnameChainResult
	current := canonicalize(name)

	for i := 0; i < maxCNAMEDepth; i++ {
		// Loop detection
		if _, seen := visited[current]; seen {
			result.loopDetected = true
			return result
		}
		visited[current] = struct{}{}

		// Look for a CNAME record in any authoritative zone
		h.zonesMu.RLock()
		cnameRec := h.findCNAMEInZonesLocked(current)
		h.zonesMu.RUnlock()

		if cnameRec == nil {
			// No CNAME found; the chain terminates at current.
			result.targetName = current
			return result
		}

		result.cnameRecords = append(result.cnameRecords, *cnameRec)
		target := canonicalize(cnameRec.RData)
		current = target
	}

	// Chain exceeded maximum depth — treat as loop.
	result.loopDetected = true
	result.targetName = current
	return result
}

// findCNAMEInZonesLocked searches all authoritative zones for a CNAME record
// for the given name. The caller must hold zonesMu (at least RLock).
// Returns nil if no CNAME is found.
func (h *integratedHandler) findCNAMEInZonesLocked(name string) *zone.Record {
	cname := canonicalize(name)
	for _, z := range h.zones {
		recs := z.Lookup(cname, "CNAME")
		if len(recs) > 0 {
			return &recs[0]
		}
	}
	return nil
}

// resolveCNAMETarget attempts to resolve a CNAME target using local zones,
// cache, and upstream. It returns answer records for the original query type
// at the CNAME target, or nil if resolution failed.
func (h *integratedHandler) resolveCNAMETarget(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, targetName string, qtype uint16) []*protocol.ResourceRecord {
	qtypeStr := typeToString(qtype)

	// 1. Try local zones first
	h.zonesMu.RLock()
	for _, z := range h.zones {
		recs := z.Lookup(targetName, qtypeStr)
		if len(recs) > 0 {
			h.zonesMu.RUnlock()
			var answers []*protocol.ResourceRecord
			for _, rec := range recs {
				data := parseRData(rec.Type, rec.RData)
				if data == nil {
					continue
				}
				targetNameParsed, err := protocol.ParseName(targetName)
				if err != nil {
					continue
				}
				answers = append(answers, &protocol.ResourceRecord{
					Name:  targetNameParsed,
					Type:  qtype,
					Class: protocol.ClassIN,
					TTL:   rec.TTL,
					Data:  data,
				})
			}
			return answers
		}
	}
	h.zonesMu.RUnlock()

	// 2. Check cache for the target
	cacheKey := cache.MakeKey(targetName, qtype)
	if entry := h.cache.Get(cacheKey); entry != nil && !entry.IsNegative && entry.Message != nil {
		var answers []*protocol.ResourceRecord
		for _, rr := range entry.Message.Answers {
			if rr.Type == qtype {
				answers = append(answers, rr.Copy())
			}
		}
		if len(answers) > 0 {
			return answers
		}
	}

	// 3. Forward to upstream
	if h.upstream != nil || h.loadBalancer != nil {
		targetNameParsed, err := protocol.ParseName(targetName)
		if err != nil {
			return nil
		}
		upstreamQuery := &protocol.Message{
			Header: protocol.Header{
				ID:      r.Header.ID,
				Flags:   protocol.NewQueryFlags(),
				QDCount: 1,
			},
			Questions: []*protocol.Question{
				{
					Name:   targetNameParsed,
					QType:  qtype,
					QClass: protocol.ClassIN,
				},
			},
		}

		var resp *protocol.Message
		if h.loadBalancer != nil {
			resp, err = h.loadBalancer.Query(upstreamQuery)
		} else {
			resp, err = h.upstream.Query(upstreamQuery)
		}
		if err != nil {
			h.logger.Warnf("Upstream CNAME target query failed for %s: %v", targetName, err)
			return nil
		}

		// Cache the upstream response
		if resp.Header.Flags.RCODE == protocol.RcodeSuccess && len(resp.Answers) > 0 {
			ttl := extractTTL(resp)
			h.cache.Set(cacheKey, resp, ttl)
		}

		// Extract matching answer records
		var answers []*protocol.ResourceRecord
		for _, rr := range resp.Answers {
			if rr.Type == qtype {
				answers = append(answers, rr.Copy())
			}
		}
		return answers
	}

	return nil
}

// buildCNAMEResponse constructs a complete DNS response with a CNAME chain
// and the resolved target records.
func (h *integratedHandler) buildCNAMEResponse(query *protocol.Message, cnameRecords []zone.Record, targetAnswers []*protocol.ResourceRecord) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}

	// Add all CNAME records in the chain
	for _, rec := range cnameRecords {
		data := parseRData("CNAME", rec.RData)
		if data == nil {
			continue
		}
		nameParsed, err := protocol.ParseName(rec.Name)
		if err != nil {
			continue
		}
		rr := &protocol.ResourceRecord{
			Name:  nameParsed,
			Type:  protocol.TypeCNAME,
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.AddAnswer(rr)
	}

	// Append the resolved target records
	for _, rr := range targetAnswers {
		resp.AddAnswer(rr)
	}

	return resp
}

// handleAXFR handles zone transfer (AXFR) requests.
// AXFR must use TCP (RFC 5936 Section 4.1).
func (h *integratedHandler) handleAXFR(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()

	// AXFR requires TCP per RFC 5936
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("AXFR request over UDP from %s - refusing", clientInfo.String())
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	qname := q.Name.String()
	h.logger.Infof("AXFR request for %s from %s", qname, clientInfo.String())

	// Get client IP for access control
	clientIP := clientInfo.IP()

	// Handle AXFR using the AXFR server
	records, tsigKey, err := h.axfrServer.HandleAXFR(r, clientIP)
	if err != nil {
		h.logger.Warnf("AXFR failed for %s: %v", qname, err)
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	// Send AXFR response as multiple messages
	// Per RFC 5936: SOA + all zone records + SOA
	// Each message is sent separately over TCP
	// Per RFC 2845: sign the first and last messages with TSIG if key was used

	for i, rr := range records {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers:   []*protocol.ResourceRecord{rr},
		}

		// Sign first and last messages per RFC 2845
		if tsigKey != nil && (i == 0 || i == len(records)-1) {
			tsigRR, signErr := transfer.SignMessage(resp, tsigKey, 300)
			if signErr != nil {
				h.logger.Warnf("Failed to sign AXFR response: %v", signErr)
			} else {
				resp.Additionals = append(resp.Additionals, tsigRR)
			}
		}

		if _, err := w.Write(resp); err != nil {
			h.logger.Warnf("Failed to write AXFR response: %v", err)
			return
		}
	}

	h.logger.Infof("AXFR completed for %s - sent %d records", qname, len(records))

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
}

// handleIXFR handles incremental zone transfer (IXFR) requests.
// IXFR must use TCP (RFC 1995).
func (h *integratedHandler) handleIXFR(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()

	// IXFR requires TCP per RFC 1995
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("IXFR request over UDP from %s - refusing", clientInfo.String())
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	qname := q.Name.String()
	h.logger.Infof("IXFR request for %s from %s", qname, clientInfo.String())

	// Get client IP for access control
	clientIP := clientInfo.IP()

	// Handle IXFR using the IXFR server
	records, err := h.ixfrServer.HandleIXFR(r, clientIP)
	if err != nil {
		h.logger.Warnf("IXFR failed for %s: %v", qname, err)
		// Check if the error indicates AXFR fallback is needed
		if errors.Is(err, transfer.ErrNoJournal) || errors.Is(err, transfer.ErrSerialNotInRange) {
			h.logger.Infof("Falling back to AXFR for %s", qname)
			h.handleAXFR(w, r, q)
			return
		}
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	// Send IXFR response as multiple messages
	// Per RFC 1995: The response format varies based on whether it's incremental or full AXFR
	for _, rr := range records {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers:   []*protocol.ResourceRecord{rr},
		}

		if _, err := w.Write(resp); err != nil {
			h.logger.Warnf("Failed to write IXFR response: %v", err)
			return
		}
	}

	h.logger.Infof("IXFR completed for %s - sent %d records", qname, len(records))

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
}

// handleNOTIFY handles NOTIFY requests from master servers (RFC 1996).
// NOTIFY informs slave servers that a zone has changed and should be refreshed.
func (h *integratedHandler) handleNOTIFY(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()

	h.logger.Infof("NOTIFY request for %s from %s", q.Name.String(), clientInfo.String())

	// Handle NOTIFY using the NOTIFY handler
	resp, err := h.notifyHandler.HandleNOTIFY(r, clientIP)
	if err != nil {
		h.logger.Warnf("NOTIFY handling failed for %s: %v", q.Name.String(), err)
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send NOTIFY response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write NOTIFY response: %v", err)
		return
	}

	h.logger.Infof("NOTIFY response sent for %s", q.Name.String())

	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}

	// Start a goroutine to listen for NOTIFY events and trigger zone transfers (once)
	h.notifyOnce.Do(func() { go h.processNotifyEvents() })
}

// processNotifyEvents listens for NOTIFY events and triggers zone transfers.
func (h *integratedHandler) processNotifyEvents() {
	notifyChan := h.notifyHandler.GetNotifyChannel()
	for req := range notifyChan {
		h.logger.Infof("Processing NOTIFY for zone %s (serial %d)", req.ZoneName, req.Serial)

		// Forward to slave manager if we have one
		if h.slaveManager != nil {
			select {
			case h.slaveManager.GetNotifyChannel() <- req:
				h.logger.Debugf("Forwarded NOTIFY for %s to slave manager", req.ZoneName)
			default:
				h.logger.Warnf("Slave manager notify channel full, dropping NOTIFY for %s", req.ZoneName)
			}
		}
	}
}

// handleUPDATE handles Dynamic DNS UPDATE requests (RFC 2136).
// UPDATE allows authenticated clients to dynamically modify DNS records.
func (h *integratedHandler) handleUPDATE(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()

	h.logger.Infof("UPDATE request for %s from %s", q.Name.String(), clientInfo.String())

	// Handle UPDATE using the Dynamic DNS handler
	resp, err := h.ddnsHandler.HandleUpdate(r, clientIP)
	if err != nil {
		h.logger.Warnf("UPDATE handling failed for %s: %v", q.Name.String(), err)
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send UPDATE response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write UPDATE response: %v", err)
		return
	}

	if resp.Header.Flags.RCODE == protocol.RcodeSuccess {
		h.logger.Infof("UPDATE successful for %s", q.Name.String())
	} else {
		h.logger.Warnf("UPDATE failed for %s with rcode %d", q.Name.String(), resp.Header.Flags.RCODE)
	}

	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}

	// Start a goroutine to listen for update events and apply changes (once)
	h.updateOnce.Do(func() { go h.processUpdateEvents() })
}

// processUpdateEvents listens for update events and applies changes to zones.
func (h *integratedHandler) processUpdateEvents() {
	updateChan := h.ddnsHandler.GetUpdateChannel()
	for req := range updateChan {
		h.logger.Infof("Processing UPDATE for zone %s", req.ZoneName)

		// Get the zone
		h.zonesMu.RLock()
		z, ok := h.zones[req.ZoneName]
		h.zonesMu.RUnlock()
		if !ok {
			h.logger.Warnf("Zone %s not found for UPDATE", req.ZoneName)
			continue
		}

		// Record old serial for IXFR journal
		var oldSerial uint32
		if z.SOA != nil {
			oldSerial = z.SOA.Serial
		}

		// Apply the update
		if err := transfer.ApplyUpdate(z, req); err != nil {
			h.logger.Warnf("Failed to apply UPDATE to zone %s: %v", req.ZoneName, err)
			continue
		}

		// Record the change in the IXFR journal
		if h.ixfrServer != nil && z.SOA != nil {
			newSerial := z.SOA.Serial
			var added, deleted []zone.RecordChange
			for _, op := range req.Updates {
				change := zone.RecordChange{
					Name:  op.Name,
					Type:  op.Type,
					TTL:   op.TTL,
					RData: op.RData,
				}
				switch op.Operation {
				case transfer.UpdateOpAdd:
					added = append(added, change)
				case transfer.UpdateOpDelete, transfer.UpdateOpDeleteRRSet, transfer.UpdateOpDeleteName:
					deleted = append(deleted, change)
				}
			}
			h.recordZoneChange(req.ZoneName, oldSerial, newSerial, added, deleted)
		}

		h.logger.Infof("UPDATE applied to zone %s", req.ZoneName)
	}
}

// recordZoneChange records a zone modification to the IXFR journal.
// This should be called whenever a zone is modified via dynamic updates.
func (h *integratedHandler) recordZoneChange(zoneName string, oldSerial, newSerial uint32, added, deleted []zone.RecordChange) {
	if h.ixfrServer == nil {
		return
	}

	h.ixfrServer.RecordChange(zoneName, oldSerial, newSerial, added, deleted)
	h.logger.Debugf("Recorded zone change for %s: serial %d -> %d (added: %d, deleted: %d)",
		zoneName, oldSerial, newSerial, len(added), len(deleted))
}

// buildResponse builds a DNS response from zone records.
func (h *integratedHandler) buildResponse(query *protocol.Message, records []zone.Record) *protocol.Message {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: query.Questions,
	}

	for _, rec := range records {
		data := parseRData(rec.Type, rec.RData)
		if data == nil {
			continue // Skip records with unparseable RData
		}
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  data,
		}
		resp.AddAnswer(rr)
	}

	return resp
}

// reply sends a response message.
func reply(w server.ResponseWriter, query, response *protocol.Message) {
	response.Header.ID = query.Header.ID
	response.Header.Flags.QR = true
	if len(response.Questions) == 0 {
		response.Questions = query.Questions
	}
	if _, err := w.Write(response); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write response: %v\n", err)
	}
}

// sendError sends an error response.
func sendError(w server.ResponseWriter, query *protocol.Message, rcode uint8) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(rcode),
		},
		Questions: query.Questions,
	}
	if _, err := w.Write(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write error response: %v\n", err)
	}
}

// handleACLRedirect sends a CNAME redirect response for ACL-redirected queries.
func (h *integratedHandler) handleACLRedirect(w server.ResponseWriter, r *protocol.Message, q *protocol.Question, target string) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    r.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: r.Questions,
	}

	targetName, err := protocol.ParseName(target)
	if err != nil {
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	rr := &protocol.ResourceRecord{
		Name:  q.Name,
		Type:  protocol.TypeCNAME,
		Class: protocol.ClassIN,
		TTL:   60,
		Data:  &protocol.RDataCNAME{CName: targetName},
	}
	resp.AddAnswer(rr)

	if _, err := w.Write(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write redirect response: %v\n", err)
	}
}

// isSubdomain checks if child is a subdomain of parent.
func isSubdomain(child, parent string) bool {
	child = canonicalize(child)
	parent = canonicalize(parent)
	return len(child) >= len(parent) && child[len(child)-len(parent):] == parent
}

// canonicalize ensures a domain name ends with a dot and is lowercase.
func canonicalize(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// typeToString converts a DNS type number to string.
func typeToString(qtype uint16) string {
	return protocol.TypeString(qtype)
}

// stringToType converts a type string to DNS type number.
func stringToType(s string) uint16 {
	if t, ok := protocol.StringToType[strings.ToUpper(s)]; ok {
		return t
	}
	return 0
}

// parseRData parses RData string based on record type.
func parseRData(rtype, rdata string) protocol.RData {
	switch strings.ToUpper(rtype) {
	case "A":
		ip := net.ParseIP(rdata)
		if ip != nil {
			ipv4 := ip.To4()
			if ipv4 == nil {
				return nil
			}
			var addr [4]byte
			copy(addr[:], ipv4)
			return &protocol.RDataA{Address: addr}
		}
	case "AAAA":
		ip := net.ParseIP(rdata)
		if ip != nil {
			var addr [16]byte
			copy(addr[:], ip.To16())
			return &protocol.RDataAAAA{Address: addr}
		}
	case "CNAME", "NS", "PTR":
		name, err := protocol.ParseName(rdata)
		if err == nil {
			return &protocol.RDataCNAME{CName: name}
		}
	case "MX":
		parts := strings.Fields(rdata)
		if len(parts) >= 2 {
			pref, _ := strconv.Atoi(parts[0])
			exchange, err := protocol.ParseName(parts[1])
			if err == nil {
				return &protocol.RDataMX{
					Preference: uint16(pref),
					Exchange:   exchange,
				}
			}
		}
	case "TXT":
		return &protocol.RDataTXT{Strings: []string{rdata}}
	case "SOA":
		return parseSOARData(rdata)
	case "SRV":
		return parseSRVRData(rdata)
	case "CAA":
		return parseCAARData(rdata)
	}
	return nil
}

// parseSOARData parses SOA RData: "mname rname serial refresh retry expire minimum"
func parseSOARData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 7 {
		return nil
	}
	mname, err := protocol.ParseName(fields[0])
	if err != nil {
		return nil
	}
	rname, err := protocol.ParseName(fields[1])
	if err != nil {
		return nil
	}
	serial, _ := strconv.ParseUint(fields[2], 10, 32)
	refresh, _ := strconv.ParseUint(fields[3], 10, 32)
	retry, _ := strconv.ParseUint(fields[4], 10, 32)
	expire, _ := strconv.ParseUint(fields[5], 10, 32)
	minimum, _ := strconv.ParseUint(fields[6], 10, 32)
	return &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  uint32(serial),
		Refresh: uint32(refresh),
		Retry:   uint32(retry),
		Expire:  uint32(expire),
		Minimum: uint32(minimum),
	}
}

// parseSRVRData parses SRV RData: "priority weight port target"
func parseSRVRData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	priority, _ := strconv.ParseUint(fields[0], 10, 16)
	weight, _ := strconv.ParseUint(fields[1], 10, 16)
	port, _ := strconv.ParseUint(fields[2], 10, 16)
	target, err := protocol.ParseName(fields[3])
	if err != nil {
		return nil
	}
	return &protocol.RDataSRV{
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   target,
	}
}

// parseCAARData parses CAA RData: "flags tag value"
func parseCAARData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 3 {
		return nil
	}
	flags, _ := strconv.ParseUint(fields[0], 10, 8)
	return &protocol.RDataCAA{
		Flags: uint8(flags),
		Tag:   fields[1],
		Value: strings.Join(fields[2:], " "),
	}
}

// extractTTL extracts a reasonable TTL from a response.
func extractTTL(resp *protocol.Message) uint32 {
	if len(resp.Answers) > 0 && resp.Answers[0].TTL > 0 {
		return resp.Answers[0].TTL
	}
	return 300
}

// hasDOBit checks if the client wants DNSSEC (DO bit in OPT record).
// The DO bit indicates the client supports DNSSEC and wants signatures.
func hasDOBit(msg *protocol.Message) bool {
	for _, rr := range msg.Additionals {
		if rr.Type == protocol.TypeOPT {
			// The DO bit is bit 15 of the TTL field in OPT records
			// Format: Extended RCODE (8 bits) | Version (8 bits) | DO (1 bit) | Z (15 bits)
			return (rr.TTL & 0x8000) != 0
		}
	}
	return false
}

// buildSignedResponse builds a DNS response with DNSSEC signatures.
// This adds RRSIG records to the response if the zone has a signer configured.
func (h *integratedHandler) buildSignedResponse(query *protocol.Message, records []zone.Record, signer *dnssec.Signer, wantsDNSSEC bool) *protocol.Message {
	resp := h.buildResponse(query, records)

	if !wantsDNSSEC || signer == nil {
		return resp
	}

	// Convert zone records to protocol.ResourceRecord for signing
	var rrs []*protocol.ResourceRecord
	for _, rec := range records {
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  parseRData(rec.Type, rec.RData),
		}
		rrs = append(rrs, rr)
	}

	// Sign the RRSet and add RRSIG to answers
	if len(rrs) > 0 {
		inception := time.Now().UTC()
		expiration := inception.Add(24 * time.Hour * 30) // 30 days

		// Find ZSK for signing
		zsks := signer.GetZSKs()
		if len(zsks) > 0 {
			zsk := zsks[0] // Use first ZSK
			rrsig, err := signer.SignRRSet(
				rrs,
				zsk,
				uint32(inception.Unix()),
				uint32(expiration.Unix()),
			)
			if err == nil && rrsig != nil {
				resp.AddAnswer(rrsig)
				h.logger.Debugf("Added RRSIG for %s", query.Questions[0].Name.String())
			}
		}
	}

	return resp
}

// parseDurationOrDefault parses a duration string, returning defaultValue if parsing fails.
func parseDurationOrDefault(s string, defaultValue time.Duration) time.Duration {
	if s == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}

func printHelp() {
	fmt.Printf(`%s - Zero-dependency DNS server

Usage: %s [options]

Options:
  -config string
        Path to configuration file (default "/etc/nothingdns/nothingdns.yaml")
  -version
        Show version and exit
  -help
        Show this help message and exit

Examples:
  # Start with default configuration
  %s

  # Start with custom configuration
  %s -config /path/to/config.yaml

  # Show version
  %s -version

For more information, visit: https://github.com/nothingdns/nothingdns
`, Name, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

// logLevelFromString converts a level string to LogLevel.
func logLevelFromString(s string) util.LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return util.DEBUG
	case "info":
		return util.INFO
	case "warn", "warning":
		return util.WARN
	case "error":
		return util.ERROR
	case "fatal":
		return util.FATAL
	default:
		return util.INFO
	}
}

// logFormatFromString converts a format string to LogFormat.
func logFormatFromString(s string) util.LogFormat {
	switch strings.ToLower(s) {
	case "json":
		return util.JSONFormat
	case "text":
		return util.TextFormat
	default:
		return util.TextFormat
	}
}
