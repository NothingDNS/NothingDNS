// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	Name = "NothingDNS"
)

var (
	configPath     = flag.String("config", "/etc/nothingdns/nothingdns.yaml", "Path to configuration file")
	showVersion    = flag.Bool("version", false, "Show version and exit")
	showHelp       = flag.Bool("help", false, "Show help and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration file and exit")
)

func main() {
	flag.Parse()

	if *validateConfig {
		if err := validateConfigOnly(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Config validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config file %s is valid\n", *configPath)
		os.Exit(0)
	}

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

	// Initialize cache manager
	cacheManager, err := NewCacheManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating cache manager: %w", err)
	}
	dnsCache := cacheManager.Cache

	// Load cache from persistent storage
	cacheManager.LoadCache()
	// Start periodic cache persistence
	cacheManager.StartPersistence(5 * time.Minute)

	// Initialize upstream manager
	upstreamManager, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating upstream manager: %w", err)
	}
	client := upstreamManager.Client
	loadBalancer := upstreamManager.LoadBalancer

	// Initialize zone manager
	zoneManager, err := NewZoneManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating zone manager: %w", err)
	}
	zones := zoneManager.Zones()
	zoneFiles := zoneManager.ZoneFiles()
	zoneSigners := zoneManager.Signers()
	zoneManagerInstance := zoneManager.Manager()
	kvPersistence := zoneManager.KVPersistence()

	// Initialize security manager
	securityManager, err := NewSecurityManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating security manager: %w", err)
	}
	bl := securityManager.Result().Blocklist
	rpzEngine := securityManager.Result().RPZEngine
	geoEngine := securityManager.Result().GeoEngine
	dns64Synth := securityManager.Result().DNS64Synth
	aclChecker := securityManager.Result().ACLChecher
	rateLimiter := securityManager.Result().RateLimiter

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

	// Initialize DNSSEC manager
	dnssecManager, err := NewDNSSECManager(cfg, upstreamManager.Resolver(), logger)
	if err != nil {
		return fmt.Errorf("creating DNSSEC manager: %w", err)
	}
	validator := dnssecManager.Validator

	// Stop channel for graceful goroutine shutdown
	stopCh := make(chan struct{})

	// Initialize cluster manager
	clusterManager, err := NewClusterManager(cfg, logger, dnsCache, metricsCollector, zoneManagerInstance)
	if err != nil {
		return fmt.Errorf("creating cluster manager: %w", err)
	}
	clusterMgr := clusterManager.Cluster

	// Set up cache invalidation callback for cluster sync
	if cfg.Cluster.Enabled && cfg.Cluster.CacheSync {
		cacheManager.SetInvalidateFunc(func(key string) {
			if err := clusterMgr.InvalidateCache([]string{key}); err != nil {
				logger.Debugf("Failed to broadcast cache invalidation: %v", err)
			}
		})
	}

	// Initialize transfer manager
	transferManager, err := NewTransferManager(cfg, zones, nil, logger)
	if err != nil {
		return fmt.Errorf("creating transfer manager: %w", err)
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
	authStore, err := auth.NewStore(&auth.Config{
		Secret:      cfg.Server.HTTP.AuthSecret,
		Users:       authUsers,
		TokenExpiry: auth.Duration{Duration: 24 * time.Hour},
	})
	if err != nil {
		logger.Fatalf("Failed to initialize auth store: %v", err)
	}
	logger.Infof("Auth store initialized with %d users", len(cfg.Server.HTTP.Users))

	// Warn if using legacy single-token auth without multi-user auth
	// In this mode, RBAC is not enforced - token holders have full access to all endpoints
	if cfg.Server.HTTP.AuthToken != "" && len(cfg.Server.HTTP.Users) == 0 {
		logger.Warnf("AUTH: Using legacy single-token auth (auth_token configured, no users). " +
			"Note: RBAC is not enforced in this mode - all token holders have operator-level access. " +
			"Consider configuring multi-user auth (users) for production deployments requiring RBAC.")
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
		jar, err := dnscookie.NewCookieJar(rotation)
		if err != nil {
			return fmt.Errorf("failed to initialize DNS cookie jar: %w", err)
		}
		cookieJar = jar
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

	// Initialize IDNA validator if enabled (RFC 5891)
	idnaEnabled := cfg.IDNA.Enabled
	if idnaEnabled {
		logger.Infof("IDNA validation enabled (STD3=%v, Bidi=%v, Joiner=%v)",
			cfg.IDNA.UseSTD3Rules, cfg.IDNA.CheckBidi, cfg.IDNA.CheckJoiner)
	}

	// Create DNS handler (needed for API server DoH support)
	handler := &integratedHandler{
		config:        cfg,
		logger:        logger,
		cache:         dnsCache,
		upstream:      client,
		loadBalancer:  loadBalancer,
		zones:         zones,
		zoneTree:      zone.BuildRadixTree(zones),
		zoneManager:   zoneManagerInstance,
		kvPersistence: kvPersistence,
		blocklist:     bl,
		rpzEngine:     rpzEngine,
		geoEngine:     geoEngine,
		metrics:       metricsCollector,
		validator:     validator,
		zoneSigners:   zoneSigners,
		idnaEnabled:   idnaEnabled,
		cluster:       clusterMgr,
		axfrServer:    transferManager.Result().AXFRServer,
		ixfrServer:    transferManager.Result().IXFRServer,
		notifyHandler: transferManager.Result().NotifyHandler,
		ddnsHandler:   transferManager.Result().DDNSHandler,
		slaveManager:  transferManager.Result().SlaveManager,
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
		if resolverConfig.MaxDepth > 30 {
			logger.Warnf("MaxDepth %d exceeds safe limit, clamping to 30", resolverConfig.MaxDepth)
			resolverConfig.MaxDepth = 30
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
	transferManager.SetZonesMu(&handler.zonesMu)

	// Initialize API server
	dashboardServer := dashboard.NewServer()
	dashboardServer.SetAllowedOrigins(cfg.Server.HTTP.AllowedOrigins)
	dashboardServer.SetAuthStore(authStore)
	dashboardServer.SetAuthToken(cfg.Server.HTTP.AuthSecret)
	dashboardServer.SetZoneManager(zoneManagerInstance)
	apiServer := api.NewServer(cfg.Server.HTTP, zoneManagerInstance, dnsCache, func() error {
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
			zoneManagerInstance.LoadZone(z, zoneFile)
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
		WithConfigGetter(func() *config.Config { return cfg }).
		WithBlocklist(bl).
		WithUpstream(client, loadBalancer).
		WithACL(aclChecker).
		WithAuth(authStore).
		WithDashboard(dashboardServer).
		WithMetrics(metricsCollector).
		WithDNSSEC(validator).
		WithZoneSigners(zoneSigners).
		WithRPZ(rpzEngine)

	// Initialize ODoH (RFC 9230) if enabled
	if cfg.Server.HTTP.ODoHEnabled {
		odohConfig := &odoh.ODoHConfig{
			TargetName: cfg.Server.HTTP.Bind,
			ProxyName:  cfg.Server.HTTP.Bind,
			HPKEKEM:    cfg.Server.HTTP.ODoHKEM,
			HPKEKDF:    cfg.Server.HTTP.ODoHKDF,
			HPKEAEAD:   cfg.Server.HTTP.ODoHAEAD,
		}

		if cfg.ODoH.Enabled && cfg.ODoH.TargetURL != "" {
			// Running as ODoH proxy forwarding to external target
			odohConfig.TargetURL = cfg.ODoH.TargetURL
			odohConfig.ProxyURL = cfg.ODoH.ProxyURL
			odohProxy, err := odoh.NewObliviousProxy(odohConfig)
			if err != nil {
				logger.Warnf("Failed to create ODoH proxy: %v", err)
			} else {
				logger.Infof("ODoH proxy configured (target: %s)", cfg.ODoH.TargetURL)
				apiServer = apiServer.WithODoH(odohProxy)
			}
		} else {
			// Running as ODoH target resolver with local DNS handler
			odohTarget, err := odoh.NewObliviousTarget(odohConfig, handler)
			if err != nil {
				logger.Warnf("Failed to create ODoH target: %v", err)
			} else {
				logger.Infof("ODoH target configured (KEM=%d, KDF=%d, AEAD=%d)",
					cfg.Server.HTTP.ODoHKEM, cfg.Server.HTTP.ODoHKDF, cfg.Server.HTTP.ODoHAEAD)
				apiServer = apiServer.WithODoHTarget(odohTarget)
			}
		}
	}

	if err := apiServer.Start(); err != nil {
		logger.Warnf("Failed to start API server: %v", err)
	} else if cfg.Server.HTTP.Enabled {
		logger.Infof("API server listening on %s", cfg.Server.HTTP.Bind)
		if cfg.Server.HTTP.DoHEnabled {
			logger.Infof("DoH endpoint enabled at %s", cfg.Server.HTTP.DoHPath)
		}
		if cfg.Server.HTTP.ODoHEnabled {
			logger.Infof("ODoH endpoint enabled at %s", cfg.Server.HTTP.ODoHPath)
		}
	}

	// Create and start DNS servers
	// Use configured bind addresses if set, otherwise default to ":PORT"
	defaultAddr := fmt.Sprintf(":%d", cfg.Server.Port)

	udpAddr := defaultAddr
	if len(cfg.Server.UDPBind) > 0 {
		udpAddr = cfg.Server.UDPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		udpAddr = net.JoinHostPort(cfg.Server.Bind[0], fmt.Sprintf("%d", cfg.Server.Port))
	}

	tcpAddr := defaultAddr
	if len(cfg.Server.TCPBind) > 0 {
		tcpAddr = cfg.Server.TCPBind[0]
	} else if len(cfg.Server.Bind) > 0 {
		tcpAddr = net.JoinHostPort(cfg.Server.Bind[0], fmt.Sprintf("%d", cfg.Server.Port))
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
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			// Dynamic certificate loading — reloads on each handshake
			// Supports Let's Encrypt auto-renewal without restart
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				updatedCert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
				if err != nil {
					return nil, err
				}
				return &updatedCert, nil
			},
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
				MinVersion:   tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
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

	// Start XoT server (DNS Zone Transfer over TLS, RFC 9103) if enabled
	var xotServer *transfer.XoTServer
	if cfg.Server.XoT.Enabled {
		xotAddr := cfg.Server.XoT.Bind
		if xotAddr == "" {
			xotAddr = fmt.Sprintf(":%d", 853) // XoT default port
		}

		xotConfig := &transfer.XoTConfig{
			CertFile:      cfg.Server.XoT.CertFile,
			KeyFile:       cfg.Server.XoT.KeyFile,
			CAFile:        cfg.Server.XoT.CAFile,
			ListenPort:    853,
			MinTLSVersion: cfg.Server.XoT.MinTLSVersion,
		}

		// Reuse TLS cert if XoT cert not specifically configured
		if xotConfig.CertFile == "" && cfg.Server.TLS.CertFile != "" {
			xotConfig.CertFile = cfg.Server.TLS.CertFile
			xotConfig.KeyFile = cfg.Server.TLS.KeyFile
		}

		if xotConfig.CertFile != "" && xotConfig.KeyFile != "" {
			xotServer, err = transfer.NewXoTServer(zones, xotConfig)
			if err != nil {
				return fmt.Errorf("creating XoT server: %w", err)
			}

			if err := xotServer.Serve(xotAddr); err != nil {
				return fmt.Errorf("starting XoT server: %w", err)
			}

			go xotServer.AcceptLoop()
			logger.Infof("XoT server listening on %s (DNS Zone Transfer over TLS, RFC 9103)", xotServer.Addr())
		} else {
			logger.Warn("XoT enabled but no certificate configured; skipping XoT server")
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

	// Capture proper goroutine baseline after all servers are running
	apiServer.SetGoroutineBaseline()

	logger.Info("Server started successfully")

	// Write PID file if configured
	if cfg.Server.PIDFile != "" {
		if err := os.WriteFile(cfg.Server.PIDFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
			logger.Warnf("Failed to write PID file %s: %v", cfg.Server.PIDFile, err)
		} else {
			logger.Infof("Wrote PID to %s", cfg.Server.PIDFile)
		}
	}

	// Send systemd notify if configured
	if cfg.Server.SystemdNotify != "" {
		if err := sdNotifySend(cfg.Server.SystemdNotify); err != nil {
			logger.Warnf("Failed to send systemd notify: %v", err)
		} else {
			logger.Infof("Sent systemd READY=1 to %s", cfg.Server.SystemdNotify)
		}
	}

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
				if xotServer != nil {
					xotServer.Close()
				}

				// Close upstream client and load balancer
				upstreamManager.Stop()

				// Stop metrics server
				if metricsCollector != nil {
					metricsCollector.Stop()
				}

				// Stop API server
				if apiServer != nil {
					apiServer.Stop()
				}

				// Stop cluster manager
				clusterManager.Stop()

				// Stop transfer manager (slave manager, notify handler, DDNS handler)
				transferManager.Stop()

				// Stop security manager (rate limiter)
				securityManager.Stop()

				// Stop cache manager (memory monitor)
				cacheManager.Stop()

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

			// Clean up PID file
			if cfg.Server.PIDFile != "" {
				os.Remove(cfg.Server.PIDFile)
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
				zoneManagerInstance.LoadZone(z, zoneFile)
				logger.Infof("Reloaded zone %s", z.Origin)
				reloadedZones++
				// Persist reloaded zone to KV store
				if kvPersistence != nil {
					if err := kvPersistence.PersistZone(z.Origin); err != nil {
						logger.Warnf("Failed to persist reloaded zone %s to KV store: %v", z.Origin, err)
					}
				}
			}
			// Rebuild zone radix tree after zone changes
			handler.RebuildZoneTree()
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

// validateConfigOnly loads and validates a configuration file without starting the server.
func validateConfigOnly(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// sdNotifySend sends a notification to systemd via unix sock.
func sdNotifySend(socket string) error {
	// Try NOTIFY_SOCKET environment variable first, then explicit path
	notifySocket := socket
	if notifySocket == "" {
		notifySocket = os.Getenv("NOTIFY_SOCKET")
	}
	if notifySocket == "" {
		return fmt.Errorf("no systemd notify socket configured")
	}

	conn, err := net.Dial("unixgram", notifySocket)
	if err != nil {
		return fmt.Errorf("dialing systemd socket: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("READY=1\n"))
	if err != nil {
		return fmt.Errorf("writing to systemd socket: %w", err)
	}
	return nil
}

func printHelp() {
	fmt.Printf(`%s - Zero-dependency DNS server

Usage: %s [options]

Options:
  -config string
        Path to configuration file (default "/etc/nothingdns/nothingdns.yaml")
  -validate-config
        Validate configuration file and exit
  -version
        Show version and exit
  -help
        Show this help message and exit

Examples:
  # Start with default configuration
  %s

  # Start with custom configuration
  %s -config /path/to/config.yaml

  # Validate configuration
  %s -validate-config /path/to/config.yaml

  # Show version
  %s -version

For more information, visit: https://github.com/nothingdns/nothingdns
`, Name, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
