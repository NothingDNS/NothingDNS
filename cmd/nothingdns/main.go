// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/memory"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/storage"
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
		ServeStale:        cfg.Cache.ServeStale,
		StaleGrace:        time.Duration(cfg.Cache.StaleGraceSecs) * time.Second,
	}
	dnsCache := cache.New(cacheConfig)
	logger.Infof("Cache initialized with capacity %d", cfg.Cache.Size)

	// Initialize memory monitor if limit is configured
	var memMonitor *memory.Monitor
	if cfg.MemoryLimitMB > 0 {
		memCfg := memory.DefaultConfig()
		memCfg.LimitBytes = uint64(cfg.MemoryLimitMB) * 1024 * 1024
		memMonitor = memory.NewMonitor(memCfg, memory.NewCacheEvictor(dnsCache))
		memMonitor.Start()
		logger.Infof("Memory monitor started: limit=%dMB", cfg.MemoryLimitMB)
	}

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

	// Initialize RPZ engine
	var rpzEngine *rpz.Engine
	if cfg.RPZ.Enabled {
		rpzFiles := make([]string, 0, len(cfg.RPZ.Files)+len(cfg.RPZ.Zones))
		rpzFiles = append(rpzFiles, cfg.RPZ.Files...)
		policies := make(map[string]int)
		for _, pz := range cfg.RPZ.Zones {
			rpzFiles = append(rpzFiles, pz.File)
			policies[pz.File] = pz.Priority
		}
		rpzEngine = rpz.NewEngine(rpz.Config{
			Enabled:  true,
			Files:    rpzFiles,
			Policies: policies,
		})
		if err := rpzEngine.Load(); err != nil {
			logger.Warnf("Failed to load RPZ zones: %v", err)
		} else {
			stats := rpzEngine.Stats()
			logger.Infof("RPZ engine loaded with %d rules from %d files", stats.TotalRules, stats.Files)
		}
	}

	// Initialize GeoDNS engine
	var geoEngine *geodns.Engine
	if cfg.GeoDNS.Enabled {
		geoEngine = geodns.NewEngine(geodns.Config{Enabled: true})
		if cfg.GeoDNS.MMDBFile != "" {
			if err := geoEngine.LoadMMDB(cfg.GeoDNS.MMDBFile); err != nil {
				logger.Warnf("Failed to load MMDB: %v", err)
			} else {
				logger.Infof("GeoDNS MMDB loaded from %s", cfg.GeoDNS.MMDBFile)
			}
		}
		for _, rule := range cfg.GeoDNS.Rules {
			geoEngine.SetRule(rule.Domain, rule.Type, &geodns.GeoRecord{
				Records: rule.Records,
				Default: rule.Default,
				Type:    rule.Type,
			})
		}
		if len(cfg.GeoDNS.Rules) > 0 {
			stats := geoEngine.Stats()
			logger.Infof("GeoDNS engine loaded with %d rules", stats.Rules)
		}
	}

	// Initialize DNS64 synthesizer (RFC 6147)
	var dns64Synth *dns64.Synthesizer
	if cfg.DNS64.Enabled {
		dns64Synth, err = dns64.NewSynthesizer(cfg.DNS64.Prefix, cfg.DNS64.PrefixLen)
		if err != nil {
			logger.Warnf("Failed to initialize DNS64: %v", err)
		} else {
			for _, cidr := range cfg.DNS64.ExcludeNets {
				if err := dns64Synth.AddExcludeNet(cidr); err != nil {
					logger.Warnf("DNS64: invalid exclude network %q: %v", cidr, err)
				}
			}
			logger.Infof("DNS64 enabled with prefix %s/%d", cfg.DNS64.Prefix, cfg.DNS64.PrefixLen)
		}
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
			Enabled:       cfg.Cluster.Enabled,
			NodeID:        cfg.Cluster.NodeID,
			BindAddr:      cfg.Cluster.BindAddr,
			GossipPort:     cfg.Cluster.GossipPort,
			Region:        cfg.Cluster.Region,
			Zone:          cfg.Cluster.Zone,
			Weight:        cfg.Cluster.Weight,
			SeedNodes:     cfg.Cluster.SeedNodes,
			CacheSync:     cfg.Cluster.CacheSync,
			HTTPAddr:      cfg.Server.HTTP.Bind,
			EncryptionKey: cfg.Cluster.EncryptionKey,
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
	if cfg.ZoneDir != "" {
		zoneManager.SetZoneDir(cfg.ZoneDir)
		logger.Infof("Zone file persistence enabled: %s", cfg.ZoneDir)
	}
	for origin, z := range zones {
		zoneManager.LoadZone(z, zoneFiles[origin])
	}

	// Initialize KV store and KVPersistence for persistent zone storage (UNWIRED-001+002)
	var kvPersistence *zone.KVPersistence
	kvDataDir := cfg.ZoneDir
	if kvDataDir == "" {
		kvDataDir = "."
	}
	kvStore, err := storage.OpenKVStore(kvDataDir)
	if err != nil {
		logger.Warnf("Failed to initialize KV store: %v", err)
	} else {
		kvPersistence = zone.NewKVPersistence(zoneManager, kvStore)
		kvPersistence.Enable()
		logger.Infof("KV store and KVPersistence initialized at %s", kvDataDir)
	}

	// Initialize AXFR server for zone transfers
	// Note: zonesMu is set later after handler is created
	axfrServer := transfer.NewAXFRServer(zones)
	logger.Infof("AXFR server initialized with %d zones", len(zones))

	// Initialize IXFR server for incremental zone transfers
	ixfrServer := transfer.NewIXFRServer(axfrServer)
	logger.Infof("IXFR server initialized for incremental transfers")

	// Wire KV journal store for persistent IXFR journals
	journalDataDir := cfg.ZoneDir
	if journalDataDir == "" {
		journalDataDir = "."
	}
	journalStore := transfer.NewKVJournalStore(journalDataDir)
	ixfrServer.SetJournalStore(journalStore)
	logger.Infof("IXFR journal store initialized at %s", journalDataDir)

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

	// Initialize auth store
	authUsers := make([]auth.User, len(cfg.Server.HTTP.Users))
	for i, u := range cfg.Server.HTTP.Users {
		authUsers[i] = auth.User{
			Username: u.Username,
			Password: u.Password,
			Role:     auth.Role(u.Role),
		}
	}
	authStore := auth.NewStore(&auth.Config{
		Secret:      cfg.Server.HTTP.AuthSecret,
		Users:       authUsers,
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	})
	logger.Infof("Auth store initialized with %d users", len(cfg.Server.HTTP.Users))

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

	// Initialize DNS cookie jar (RFC 7873)
	var cookieJar *dnscookie.CookieJar
	if cfg.Cookie.Enabled {
		rotation := parseDurationOrDefault(cfg.Cookie.SecretRotation, 1*time.Hour)
		cookieJar = dnscookie.NewCookieJar(rotation)
		logger.Infof("DNS cookies enabled (secret rotation: %s)", rotation)
	}

	// Initialize split-horizon views
	var splitHorizon *filter.SplitHorizon
	var viewZones map[string]map[string]*zone.Zone
	if len(cfg.Views) > 0 {
		viewConfigs := make([]filter.ViewConfig, len(cfg.Views))
		for i, v := range cfg.Views {
			viewConfigs[i] = filter.ViewConfig{
				Name:         v.Name,
				MatchClients: v.MatchClients,
				ZoneFiles:    v.ZoneFiles,
			}
		}
		var shErr error
		splitHorizon, shErr = filter.NewSplitHorizon(viewConfigs)
		if shErr != nil {
			return fmt.Errorf("initializing split-horizon: %w", shErr)
		}

		viewZones = make(map[string]map[string]*zone.Zone)
		for _, v := range cfg.Views {
			vzMap := make(map[string]*zone.Zone)
			for _, zf := range v.ZoneFiles {
				vz, vzErr := loadZoneFile(zf)
				if vzErr != nil {
					return fmt.Errorf("loading zone file %q for view %q: %w", zf, v.Name, vzErr)
				}
				vzMap[vz.Origin] = vz
				logger.Infof("Loaded zone %s for view %s", vz.Origin, v.Name)
			}
			viewZones[v.Name] = vzMap
		}
		logger.Infof("Split-horizon enabled with %d views", len(cfg.Views))
	}

	// Create DNS handler (needed for API server DoH support)
	handler := &integratedHandler{
		config:        cfg,
		logger:        logger,
		cache:         dnsCache,
		upstream:      client,
		loadBalancer:  loadBalancer,
		zones:         zones,
		zoneManager:   zoneManager,
		kvPersistence: kvPersistence,
		blocklist:     bl,
		rpzEngine:     rpzEngine,
		geoEngine:     geoEngine,
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
		splitHorizon:  splitHorizon,
		viewZones:     viewZones,
		auditLogger:   auditLogger,
		nsecCache:     cache.NewNSECCache(10000),
		dns64Synth:    dns64Synth,
		cookieJar:     cookieJar,
	}

	// Initialize iterative recursive resolver if enabled
	if cfg.Resolution.Recursive {
		resolverTransport := newResolverTransport(client, loadBalancer)
		resolverConfig := resolver.Config{
			MaxDepth:          cfg.Resolution.MaxDepth,
			MaxCNAMEDepth:     16,
			Timeout:           5 * time.Second,
			EDNS0BufSize:      uint16(cfg.Resolution.EDNS0BufferSize),
			QnameMinimization: cfg.Resolution.QnameMinimization,
			Use0x20:           cfg.Resolution.Use0x20,
		}
		if cfg.Resolution.Timeout != "" {
			if d, err := time.ParseDuration(cfg.Resolution.Timeout); err == nil {
				resolverConfig.Timeout = d
			}
		}
		if resolverConfig.EDNS0BufSize == 0 {
			resolverConfig.EDNS0BufSize = 4096
		}
		if cfg.Resolution.RootHints != "" {
			hints, err := loadRootHintsFile(cfg.Resolution.RootHints)
			if err != nil {
				logger.Warnf("Failed to load root hints file %s: %v", cfg.Resolution.RootHints, err)
			} else {
				resolverConfig.Hints = hints
				logger.Infof("Loaded %d custom root hints from %s", len(hints), cfg.Resolution.RootHints)
			}
		}
		handler.resolver = resolver.NewResolver(resolverConfig, &resolverCacheAdapter{cache: dnsCache}, resolverTransport)
		logger.Info("Iterative recursive resolver enabled")
		if resolverConfig.QnameMinimization {
			logger.Info("QNAME minimization enabled (RFC 7816)")
		}
		if resolverConfig.Use0x20 {
			logger.Info("0x20 encoding enabled for spoofing resistance")
		}
	}

	// Share the zones mutex between handler, AXFR server, and DDNS handler
	// to prevent data races on the shared zones map
	axfrServer.SetZonesMu(&handler.zonesMu)
	ddnsHandler.SetZonesMu(&handler.zonesMu)

	// Initialize API server
	dashboardServer := dashboard.NewServer()
	apiServer := api.NewServer(cfg.Server.HTTP, zoneManager, dnsCache, func() error {
		logger.Info("Reloading configuration via API...")
		now := time.Now().UTC().Format(time.RFC3339)
		if auditLogger != nil {
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: now,
				Action:    "start",
			})
		}
		reloadedZones := 0
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
			reloadedZones++
			// Persist reloaded zone to KV store
			if kvPersistence != nil {
				if err := kvPersistence.PersistZone(z.Origin); err != nil {
					logger.Warnf("Failed to persist reloaded zone %s to KV store: %v", z.Origin, err)
				}
			}
		}
		// Reload blocklist
		if bl != nil {
			if err := bl.Reload(); err != nil {
				logger.Warnf("Failed to reload blocklist: %v", err)
			}
		}
		// Reload RPZ
		if rpzEngine != nil {
			if err := rpzEngine.Reload(); err != nil {
				logger.Warnf("Failed to reload RPZ zones: %v", err)
			} else {
				stats := rpzEngine.Stats()
				logger.Infof("Reloaded RPZ with %d rules from %d files", stats.TotalRules, stats.Files)
			}
		}
		// Reload split-horizon views
		if len(cfg.Views) > 0 {
			viewConfigs := make([]filter.ViewConfig, len(cfg.Views))
			for i, v := range cfg.Views {
				viewConfigs[i] = filter.ViewConfig{
					Name:         v.Name,
					MatchClients: v.MatchClients,
					ZoneFiles:    v.ZoneFiles,
				}
			}
			if err := handler.ReloadViews(viewConfigs, loadZoneFile); err != nil {
				logger.Warnf("Failed to reload split-horizon views: %v", err)
			} else {
				logger.Infof("Reloaded split-horizon views")
			}
		}
		if auditLogger != nil {
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Action:    "complete",
				Zones:     reloadedZones,
			})
		}
		return nil
	}, handler, clusterMgr, dashboardServer).
		WithBlocklist(bl).
		WithUpstream(client, loadBalancer).
		WithACL(aclChecker).
		WithAuth(authStore).
		WithDashboard(dashboardServer).
		WithMetrics(metricsCollector).
		WithDNSSEC(validator).
		WithRPZ(rpzEngine)
	if err := apiServer.Start(); err != nil {
		logger.Warnf("Failed to start API server: %v", err)
	} else if cfg.Server.HTTP.Enabled {
		logger.Infof("API server listening on %s", cfg.Server.HTTP.Bind)
		if cfg.Server.HTTP.DoHEnabled {
			logger.Infof("DoH endpoint enabled at %s", cfg.Server.HTTP.DoHPath)
		}
	}

	// Create and start DNS servers
	// Use configured bind addresses if set, otherwise default to ":PORT"
	defaultAddr := fmt.Sprintf(":%d", cfg.Server.Port)

	udpAddr := defaultAddr
	if len(cfg.Server.UDPBind) > 0 {
		udpAddr = cfg.Server.UDPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		udpAddr = cfg.Server.Bind[0]
	}

	tcpAddr := defaultAddr
	if len(cfg.Server.TCPBind) > 0 {
		tcpAddr = cfg.Server.TCPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		tcpAddr = cfg.Server.Bind[0]
	}

	udpServer := server.NewUDPServerWithWorkers(udpAddr, handler, cfg.Server.UDPWorkers)
	tcpServer := server.NewTCPServerWithWorkers(tcpAddr, handler, cfg.Server.TCPWorkers)

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

	// Start QUIC server (DNS over QUIC, RFC 9250) if enabled
	var doqServer *quic.DoQServer
	if cfg.Server.QUIC.Enabled {
		doqAddr := cfg.Server.QUIC.Bind
		if doqAddr == "" {
			doqAddr = fmt.Sprintf(":%d", quic.DefaultDoQPort)
		}

		certFile := cfg.Server.QUIC.CertFile
		keyFile := cfg.Server.QUIC.KeyFile
		// Fall back to TLS cert if QUIC-specific cert is not set
		if certFile == "" && cfg.Server.TLS.CertFile != "" {
			certFile = cfg.Server.TLS.CertFile
			keyFile = cfg.Server.TLS.KeyFile
		}

		if certFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return fmt.Errorf("loading QUIC certificate: %w", err)
			}

			quicTLSConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"doq"},
			}

			doqHandler := &doqHandlerAdapter{handler: handler}
			doqServer = quic.NewDoQServer(doqAddr, doqHandler, quicTLSConfig)
			if err := doqServer.Listen(); err != nil {
				return fmt.Errorf("starting DoQ server: %w", err)
			}
			go func() {
				if err := doqServer.Serve(); err != nil {
					logger.Errorf("DoQ server error: %v", err)
				}
			}()
			logger.Infof("DoQ server listening on %s (DNS over QUIC)", doqAddr)
		} else {
			logger.Warn("QUIC enabled but no certificate configured; skipping DoQ server")
		}
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

			shutdownTimeout := parseDurationOrDefault(cfg.ShutdownTimeout, 30*time.Second)
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
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
				if doqServer != nil {
					doqServer.Stop()
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

				// Stop rate limiter
				if rateLimiter != nil {
					rateLimiter.Stop()
				}

				// Stop memory monitor
				if memMonitor != nil {
					memMonitor.Stop()
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
			now := time.Now().UTC().Format(time.RFC3339)
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: now,
					Action:    "start",
				})
			}
			// Reload the config file to pick up changes
			newCfg, cfgErr := loadConfig(*configPath)
			if cfgErr != nil {
				logger.Warnf("Failed to reload config: %v", cfgErr)
			} else {
				cfg = newCfg
			}
			// Reload zone files
			reloadCfg := cfg
			if cfgErr != nil {
				reloadCfg = cfg // keep current config on error
			}
			reloadedZones := 0
			for _, zoneFile := range reloadCfg.Zones {
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
				reloadedZones++
				// Persist reloaded zone to KV store
				if kvPersistence != nil {
					if err := kvPersistence.PersistZone(z.Origin); err != nil {
						logger.Warnf("Failed to persist reloaded zone %s to KV store: %v", z.Origin, err)
					}
				}
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
			// Reload RPZ
			if rpzEngine != nil {
				if err := rpzEngine.Reload(); err != nil {
					logger.Warnf("Failed to reload RPZ zones: %v", err)
				} else {
					stats := rpzEngine.Stats()
					logger.Infof("Reloaded RPZ with %d rules from %d files", stats.TotalRules, stats.Files)
				}
			}
			// Reload split-horizon views from the new config
			if len(reloadCfg.Views) > 0 {
				viewConfigs := make([]filter.ViewConfig, len(reloadCfg.Views))
				for i, v := range reloadCfg.Views {
					viewConfigs[i] = filter.ViewConfig{
						Name:         v.Name,
						MatchClients: v.MatchClients,
						ZoneFiles:    v.ZoneFiles,
					}
				}
				if err := handler.ReloadViews(viewConfigs, loadZoneFile); err != nil {
					logger.Warnf("Failed to reload split-horizon views: %v", err)
				} else {
					logger.Infof("Reloaded split-horizon views")
				}
			}
			if auditLogger != nil {
				errStr := ""
				if cfgErr != nil {
					errStr = cfgErr.Error()
				}
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     reloadedZones,
					Error:     errStr,
				})
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
