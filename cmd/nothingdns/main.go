// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/mdns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/odoh"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	Name                        = "NothingDNS"
	maxConfigFileSize           = 4 << 20
	maxDNSSECPrivateKeyFileSize = 64 << 10
)

var (
	configPath = flag.String("config", "/etc/nothingdns/nothingdns.yaml", "Path to configuration file")
)

type blocklistReloader interface {
	Reload() error
	Stats() blocklist.Stats
}

type rpzReloader interface {
	Reload() error
	Stats() rpz.Stats
}

func effectiveHTTPConfig(cfg *config.Config) config.HTTPConfig {
	httpCfg := cfg.Server.HTTP
	if httpCfg.ODoHKEM == 0 {
		httpCfg.ODoHKEM = cfg.ODoH.KEM
	}
	if httpCfg.ODoHKDF == 0 {
		httpCfg.ODoHKDF = cfg.ODoH.KDF
	}
	if httpCfg.ODoHAEAD == 0 {
		httpCfg.ODoHAEAD = cfg.ODoH.AEAD
	}
	if httpCfg.ODoHPath == "" {
		httpCfg.ODoHPath = "/odoh"
	}
	if cfg.ODoH.Enabled {
		httpCfg.Enabled = true
		httpCfg.ODoHEnabled = true
		if httpCfg.Bind == "" && cfg.ODoH.Bind != "" {
			httpCfg.Bind = cfg.ODoH.Bind
		}
	}
	return httpCfg
}

func buildODoHConfig(cfg *config.Config, httpCfg config.HTTPConfig) *odoh.ODoHConfig {
	odohCfg := &odoh.ODoHConfig{
		TargetName: httpCfg.Bind,
		ProxyName:  httpCfg.Bind,
		HPKEKEM:    httpCfg.ODoHKEM,
		HPKEKDF:    httpCfg.ODoHKDF,
		HPKEAEAD:   httpCfg.ODoHAEAD,
	}
	if cfg.ODoH.Enabled {
		odohCfg.HPKEKEM = cfg.ODoH.KEM
		odohCfg.HPKEKDF = cfg.ODoH.KDF
		odohCfg.HPKEAEAD = cfg.ODoH.AEAD
		odohCfg.TargetURL = cfg.ODoH.TargetURL
		odohCfg.ProxyURL = cfg.ODoH.ProxyURL
	}
	return odohCfg
}

func reloadConfiguredZoneFiles(handler *integratedHandler, zoneManager *zone.Manager, zoneFiles map[string]string, configuredZoneFiles []string, loadZoneFileFunc func(string) (*zone.Zone, error), logger *util.Logger) (int, error) {
	loaded, err := prepareConfiguredZoneFiles(configuredZoneFiles, loadZoneFileFunc)
	if err != nil {
		return 0, err
	}
	applyConfiguredZoneFiles(handler, zoneManager, zoneFiles, loaded, logger)
	return len(loaded), nil
}

type loadedZoneFile struct {
	zone *zone.Zone
	file string
}

func prepareConfiguredZoneFiles(configuredZoneFiles []string, loadZoneFileFunc func(string) (*zone.Zone, error)) ([]loadedZoneFile, error) {
	loaded := make([]loadedZoneFile, 0, len(configuredZoneFiles))
	for _, zoneFile := range configuredZoneFiles {
		z, err := loadZoneFileFunc(zoneFile)
		if err != nil {
			return nil, fmt.Errorf("loading zone file %s: %w", zoneFile, err)
		}
		loaded = append(loaded, loadedZoneFile{zone: z, file: zoneFile})
	}
	return loaded, nil
}

func applyConfiguredZoneFiles(handler *integratedHandler, zoneManager *zone.Manager, zoneFiles map[string]string, loaded []loadedZoneFile, logger *util.Logger) {
	for _, item := range loaded {
		handler.zonesMu.Lock()
		handler.zones[item.zone.Origin] = item.zone
		handler.zonesMu.Unlock()
		zoneFiles[item.zone.Origin] = item.file
		zoneManager.LoadZone(item.zone, item.file)
		logger.Infof("Reloaded zone %s", item.zone.Origin)
		// Do NOT mirror file-backed zones into the KV store: the zone
		// file is their durable source, and a KV copy would resurrect
		// the zone after the operator removes it from the config.
	}

	handler.RebuildZoneTree()
}

func reloadConfiguredViews(handler *integratedHandler, views []config.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error), logger *util.Logger) error {
	plan, count, err := prepareConfiguredViews(handler, views, loadZoneFileFunc)
	if err != nil {
		return err
	}
	applyConfiguredViews(handler, plan, count, logger)
	return nil
}

func prepareConfiguredViews(handler *integratedHandler, views []config.ViewConfig, loadZoneFileFunc func(string) (*zone.Zone, error)) (*viewReloadPlan, int, error) {
	viewConfigs := make([]filter.ViewConfig, len(views))
	for i, v := range views {
		viewConfigs[i] = filter.ViewConfig{
			Name:         v.Name,
			MatchClients: v.MatchClients,
			ZoneFiles:    v.ZoneFiles,
		}
	}
	plan, err := handler.prepareReloadViews(viewConfigs, loadZoneFileFunc)
	if err != nil {
		return nil, len(viewConfigs), fmt.Errorf("reloading configured split-horizon views: %w", err)
	}
	return plan, len(viewConfigs), nil
}

func applyConfiguredViews(handler *integratedHandler, plan *viewReloadPlan, count int, logger *util.Logger) {
	handler.applyReloadViews(plan)
	if count == 0 {
		logger.Info("Cleared split-horizon views")
	} else {
		logger.Infof("Reloaded split-horizon views")
	}
}

type upstreamReloadPlan struct {
	upstreamManager *UpstreamManager
	dnssecManager   *DNSSECManager
	dnssecFetch     *dnssecResolverAdapter
}

func prepareUpstreamComponents(cfg *config.Config, logger *util.Logger) (*upstreamReloadPlan, error) {
	nextUpstreamManager, err := NewUpstreamManager(cfg, logger)
	if err != nil {
		return nil, err
	}
	nextDNSSECFetch := nextUpstreamManager.Resolver()
	nextDNSSECManager, err := NewDNSSECManager(cfg, nextDNSSECFetch, logger)
	if err != nil {
		nextUpstreamManager.Stop()
		return nil, err
	}
	return &upstreamReloadPlan{
		upstreamManager: nextUpstreamManager,
		dnssecManager:   nextDNSSECManager,
		dnssecFetch:     nextDNSSECFetch,
	}, nil
}

func applyUpstreamComponents(plan *upstreamReloadPlan, current *UpstreamManager, handler *integratedHandler, apiServer *api.Server) {
	if plan == nil || plan.upstreamManager == nil || plan.dnssecManager == nil {
		return
	}
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.upstream = plan.upstreamManager.Client
		handler.loadBalancer = plan.upstreamManager.LoadBalancer
		handler.validator = plan.dnssecManager.Validator
		// Preserve the iterative fetch path across hot reloads — the
		// resolver itself is not rebuilt on SIGHUP, but the fresh
		// validator's adapter starts without it (recursive-only setups
		// would otherwise lose DNSSEC fetches until restart).
		plan.dnssecFetch.SetIterative(handler.resolver)
		handler.runtimeMu.Unlock()
	}
	if apiServer != nil {
		apiServer.
			WithUpstream(plan.upstreamManager.Client, plan.upstreamManager.LoadBalancer).
			WithDNSSEC(plan.dnssecManager.Validator)
	}
	if current != nil && current != plan.upstreamManager {
		current.Stop()
	}
}

func reloadSecurityPolicy(bl blocklistReloader, rpzEngine rpzReloader, logger *util.Logger) error {
	var errs []error
	if bl != nil {
		if err := bl.Reload(); err != nil {
			wrapped := fmt.Errorf("reloading blocklist: %w", err)
			logger.Warnf("Failed to reload blocklist: %v", err)
			errs = append(errs, wrapped)
		} else {
			stats := bl.Stats()
			logger.Infof("Reloaded blocklist with %d entries from %d files", stats.TotalBlocks, stats.Files)
		}
	}
	if rpzEngine != nil {
		if err := rpzEngine.Reload(); err != nil {
			wrapped := fmt.Errorf("reloading RPZ zones: %w", err)
			logger.Warnf("Failed to reload RPZ zones: %v", err)
			errs = append(errs, wrapped)
		} else {
			stats := rpzEngine.Stats()
			logger.Infof("Reloaded RPZ with %d rules from %d files", stats.TotalRules, stats.Files)
		}
	}
	return errors.Join(errs...)
}

func reloadSecurityComponents(cfg *config.Config, current *SecurityManager, handler *integratedHandler, apiServer *api.Server, logger *util.Logger) (*SecurityManager, *SecurityManagerResult, error) {
	next, err := NewSecurityManager(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	result := next.Result()
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.security.Blocklist = result.Blocklist
		handler.security.RPZEngine = result.RPZEngine
		handler.security.GeoEngine = result.GeoEngine
		handler.security.DNS64Synth = result.DNS64Synth
		handler.security.ACLChecker = result.ACLChecker
		handler.security.RateLimiter = result.RateLimiter
		handler.security.RRL = result.RRL
		handler.runtimeMu.Unlock()
	}
	if apiServer != nil {
		apiServer.
			WithBlocklist(result.Blocklist).
			WithRPZ(result.RPZEngine).
			WithGeoDNS(result.GeoEngine).
			WithACL(result.ACLChecker).
			WithRateLimiter(result.RateLimiter)
	}
	if current != nil {
		current.Stop()
	}
	return next, result, nil
}

func loadReloadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func storeReloadConfig(path string, cfgMu *sync.RWMutex, cfgRef **config.Config) (*config.Config, error) {
	newCfg, err := loadReloadConfig(path)
	if err != nil {
		return nil, err
	}
	storeLoadedConfig(newCfg, cfgMu, cfgRef)
	return newCfg, nil
}

func storeLoadedConfig(newCfg *config.Config, cfgMu *sync.RWMutex, cfgRef **config.Config) {
	cfgMu.Lock()
	*cfgRef = newCfg
	cfgMu.Unlock()
}

func commitLoadedConfig(newCfg *config.Config, cfgMu *sync.RWMutex, cfgRef **config.Config, handler *integratedHandler) {
	storeLoadedConfig(newCfg, cfgMu, cfgRef)
	if handler != nil {
		handler.runtimeMu.Lock()
		handler.config = newCfg
		handler.runtimeMu.Unlock()
	}
}

// main is the process entry point. All real logic lives in MainDispatch
// so it can be tested without invoking os.Exit.
func main() {
	os.Exit(MainDispatch(os.Args, os.Stdout, os.Stderr))
}

// MainDispatch parses the given arg slice, dispatches to the right
// sub-command, and returns a process exit code. main() is now just a
// thin wrapper so tests can exercise every flag combination without
// terminating the test binary via os.Exit.
func MainDispatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nothingdns", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfgPath := fs.String("config", "config.yaml", "path to configuration file")
	validateCfg := fs.Bool("validate-config", false, "validate config and exit")
	validateProdFlag := fs.Bool("validate-production-config", false, "validate production config and exit")
	showHelp := fs.Bool("help", false, "show help")
	showHelpShort := fs.Bool("h", false, "show help")
	showVersion := fs.Bool("version", false, "show version")

	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	if *validateCfg {
		if err := validateConfigOnly(*cfgPath); err != nil {
			fmt.Fprintf(stderr, "Config validation failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Config file %s is valid\n", *cfgPath)
		return 0
	}

	if *validateProdFlag {
		if err := validateProductionConfigOnly(*cfgPath); err != nil {
			fmt.Fprintf(stderr, "Production config validation failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Production config file %s is valid\n", *cfgPath)
		return 0
	}

	if *showHelp || *showHelpShort {
		printHelpTo(stdout)
		return 0
	}

	if *showVersion {
		fmt.Fprintf(stdout, "%s version %s\n", Name, util.Version)
		return 0
	}

	*configPath = *cfgPath
	if err := run(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// printHelpTo writes the help text to w. Mirrors the CLI behaviour.
func printHelpTo(w io.Writer) {
	fmt.Fprintf(w, "Usage: nothingdns [options]\n\nOptions:\n")
	fmt.Fprintf(w, "  -config string\n        path to configuration file (default \"config.yaml\")\n")
	fmt.Fprintf(w, "  -validate-config\n        validate configuration and exit\n")
	fmt.Fprintf(w, "  -validate-production-config\n        validate production configuration and exit\n")
	fmt.Fprintf(w, "  -version\n        print version and exit\n")
	fmt.Fprintf(w, "  -help, -h\n        show this help message\n")
}

func run() error {
	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	return runWithContext(context.Background(), cfg)
}

// runWithContext performs the full server lifecycle with the supplied
// context. Tests typically inject a signal via installFakeSignalHandler
// to drive shutdown cleanly without sending real OS signals. Production
// callers should use run() which seeds the context with context.Background().
func runWithContext(ctx context.Context, cfg *config.Config) error {
	var cfgMu sync.RWMutex

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
	cacheManager := NewCacheManager(cfg, logger)
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
	aclChecker := securityManager.Result().ACLChecker
	rateLimiter := securityManager.Result().RateLimiter

	// Initialize metrics collector
	metricsCollector := metrics.New(metrics.Config{
		Enabled:   cfg.Metrics.Enabled,
		Bind:      cfg.Metrics.Bind,
		Path:      cfg.Metrics.Path,
		AuthToken: cfg.Metrics.AuthToken,
	})
	if err := metricsCollector.Start(); err != nil {
		if cfg.Metrics.Enabled {
			return fmt.Errorf("starting metrics server: %w", err)
		}
		logger.Warnf("Failed to start metrics server: %v", err)
	} else if cfg.Metrics.Enabled {
		logger.Infof("Metrics server listening on %s%s", cfg.Metrics.Bind, cfg.Metrics.Path)
	}

	// Initialize DNSSEC manager. Keep the fetch adapter: when the iterative
	// resolver is enabled below, it becomes the validator's fetch path
	// (mandatory in recursive-only deployments, which have no upstream).
	dnssecFetch := upstreamManager.Resolver()
	dnssecManager, err := NewDNSSECManager(cfg, dnssecFetch, logger)
	if err != nil {
		return fmt.Errorf("creating DNSSEC manager: %w", err)
	}
	validator := dnssecManager.Validator

	// Stop channel for graceful goroutine shutdown
	stopCh := make(chan struct{})

	// Server root context — cancelled on SIGINT/SIGTERM to tear down
	// in-flight queries before the process exits.
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer() // Safe: deferred before any early return

	// Initialize cluster manager
	clusterManager, err := NewClusterManager(cfg, logger, dnsCache, metricsCollector, zoneManagerInstance)
	if err != nil {
		return fmt.Errorf("creating cluster manager: %w", err)
	}
	clusterMgr := clusterManager.Cluster

	// Initialize mDNS responder
	var mdnsResponder *mdns.Responder
	if cfg.MDNS.Enabled {
		mdnsConfig := mdns.Config{
			Enabled:     cfg.MDNS.Enabled,
			MulticastIP: cfg.MDNS.MulticastIP,
			Port:        cfg.MDNS.Port,
			HostName:    cfg.MDNS.HostName,
			Browser:     cfg.MDNS.Browser,
		}
		mdnsResponder = mdns.NewResponder(mdnsConfig, logger)
		if err := mdnsResponder.Start(); err != nil {
			return fmt.Errorf("starting mDNS responder: %w", err)
		} else {
			logger.Infof("mDNS responder started on %s:%d", mdnsConfig.MulticastIP, mdnsConfig.Port)
		}
	}

	// Initialize DSO manager
	var dsoManager *dso.Manager
	if cfg.DSO.Enabled {
		dsoConfig := dso.Config{
			Enabled:           cfg.DSO.Enabled,
			InactivityTimeout: parseDurationOrDefault(cfg.DSO.SessionTimeout, dso.DefaultInactivityTimeout),
			KeepaliveInterval: parseDurationOrDefault(cfg.DSO.HeartbeatInterval, dso.MinKeepaliveInterval),
			MaxSessions:       cfg.DSO.MaxSessions,
			MaxPayloadSize:    dso.DefaultMaxPayloadSize,
		}
		dsoManager = dso.NewManager(dsoConfig, logger)
		dsoManager.Start()
		logger.Info("DSO (DNS Stateful Operations) manager started")
	}

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
		// Hash plaintext password and zero it from memory
		if authUsers[i].Password != "" {
			hash, err := auth.HashPasswordWithError(authUsers[i].Password, nil)
			if err != nil {
				return fmt.Errorf("hashing configured password for user %q: %w", authUsers[i].Username, err)
			}
			authUsers[i].Hash = hash
			authUsers[i].Password = strings.Repeat("\x00", len(authUsers[i].Password))
		}
		// Zero plaintext in the raw config struct as well
		cfg.Server.HTTP.Users[i].Password = strings.Repeat("\x00", len(cfg.Server.HTTP.Users[i].Password))
	}
	authStore, err := auth.NewStore(&auth.Config{
		Secret:             cfg.Server.HTTP.AuthSecret,
		Users:              authUsers,
		TokenExpiry:        auth.Duration{Duration: 24 * time.Hour},
		MaxSessionsPerUser: cfg.Server.HTTP.MaxSessionsPerUser, // L-N10
	})
	if err != nil {
		logger.Fatalf("Failed to initialize auth store: %v", err)
	}
	logger.Infof("Auth store initialized with %d users", len(cfg.Server.HTTP.Users))

	// Restore persistent tokens from file if configured. Validation
	// lives in cmd/nothingdns/helpers.validateAuthPersistenceConfig
	// so it's unit-testable (L-4).
	if err := validateAuthPersistenceConfig(cfg.Server.HTTP); err != nil {
		logger.Fatalf("%v", err)
	}
	if cfg.Server.HTTP.TokenPersistencePath != "" {
		authStore.SetTokenFilePath(cfg.Server.HTTP.TokenPersistencePath)
		if err := authStore.LoadTokensSigned(cfg.Server.HTTP.TokenPersistencePath); err != nil {
			logger.Warnf("Failed to load persisted tokens from %s: %v", cfg.Server.HTTP.TokenPersistencePath, err)
		} else {
			logger.Infof("Loaded session tokens from %s", cfg.Server.HTTP.TokenPersistencePath)
		}
	}

	// Warn if using legacy single-token auth without multi-user auth.
	// Since VULN-003 (CVE-2025-pending), the legacy token binds to the
	// role configured by `auth_token_role` (default: viewer). Reflect
	// the actual bound role in the warning so operators don't think
	// the token grants more than it does.
	if cfg.Server.HTTP.AuthToken != "" && len(cfg.Server.HTTP.Users) == 0 {
		boundRole := strings.ToLower(strings.TrimSpace(cfg.Server.HTTP.AuthTokenRole))
		if boundRole == "" {
			boundRole = "viewer"
		}
		if boundRole != "admin" && boundRole != "operator" && boundRole != "viewer" {
			boundRole = "viewer"
		}
		logger.Warnf("AUTH: Using legacy single-token auth (auth_token configured, no users). "+
			"All requests bearing this token are bound to role %q (set via auth_token_role; default \"viewer\"). "+
			"For per-user RBAC, configure multi-user auth via the `users` block.",
			boundRole)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewAuditLogger(cfg.Logging.QueryLog, cfg.Logging.QueryLogFile)
	if err != nil {
		logger.Warnf("Failed to initialize audit logger: %v", err)
	} else if cfg.Logging.QueryLog {
		logger.Info("Query audit logging enabled")
	}

	// Initialize tracing (OpenTelemetry SDK). Disabled by default; when
	// enabled, spans are exported over OTLP/HTTP to cfg.Tracing.Endpoint
	// (or OTEL_EXPORTER_OTLP_* env vars) with W3C TraceContext propagation.
	var tracer *otel.Tracer
	if cfg.Tracing.Enabled {
		level := otel.LevelBasic
		if err := level.UnmarshalText([]byte(cfg.Tracing.Level)); err != nil {
			logger.Warnf("Invalid tracing level %q, defaulting to basic", cfg.Tracing.Level)
		}
		tracer = otel.NewTracer(otel.Config{
			Enabled:    true,
			Level:      level,
			SampleRate: cfg.Tracing.SampleRate,
			Endpoint:   cfg.Tracing.Endpoint,
		})
		logger.Infof("Tracing enabled (OTel SDK, sample_rate=%.2f, endpoint=%q)",
			cfg.Tracing.SampleRate, cfg.Tracing.Endpoint)
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
		metrics:       metricsCollector,
		validator:     validator,
		zoneSigners:   zoneSigners,
		idnaEnabled:   idnaEnabled,
		cluster:       clusterMgr,
		splitHorizon:  splitHorizon,
		viewZones:     viewZones,
		auditLogger:   auditLogger,
		tracer:        tracer,
		nsecCache:     cache.NewNSECCache(10000),
		cookieJar:     cookieJar,
		mdnsResponder: mdnsResponder,
		dsoManager:    dsoManager,
		security: SecurityComponents{
			Blocklist:   bl,
			RPZEngine:   rpzEngine,
			GeoEngine:   geoEngine,
			DNS64Synth:  dns64Synth,
			ACLChecker:  aclChecker,
			RateLimiter: rateLimiter,
			RRL:         securityManager.Result().RRL,
		},
		transfer: TransferComponents{
			AXFRServer:    transferManager.Result().AXFRServer,
			IXFRServer:    transferManager.Result().IXFRServer,
			NotifyHandler: transferManager.Result().NotifyHandler,
			DDNSHandler:   transferManager.Result().DDNSHandler,
			SlaveManager:  transferManager.Result().SlaveManager,
		},
		zoneProvider: NewMultiZoneProvider(
			zones,
			zoneManagerInstance,
			kvPersistence,
			zone.BuildRadixTree(zones),
		),
		serverCtx:    serverCtx,
		cancelServer: cancelServer,
	}
	handlerLogger = logger

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
			DNSSECOK:          cfg.DNSSEC.Enabled,
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
				return fmt.Errorf("loading root hints file %s: %w", cfg.Resolution.RootHints, err)
			}
			resolverConfig.Hints = hints
			logger.Infof("Loaded %d custom root hints from %s", len(hints), cfg.Resolution.RootHints)
		}
		handler.resolver = resolver.NewResolver(resolverConfig, &resolverCacheAdapter{cache: dnsCache}, resolverTransport)
		// Route the validator's chain fetches through the iterative resolver:
		// in recursive mode it is the authoritative fetch path (and the ONLY
		// one when no upstream is configured).
		dnssecFetch.SetIterative(handler.resolver)
		logger.Info("Iterative recursive resolver enabled")
		if resolverConfig.QnameMinimization {
			logger.Info("QNAME minimization enabled (RFC 7816)")
		}
		if resolverConfig.Use0x20 {
			logger.Info("0x20 encoding enabled for spoofing resistance")
		}
	}

	// VULN-041: Warn if recursion is enabled without ACL rules but with explicit allow-unrestricted
	if cfg.Resolution.Recursive && aclChecker == nil && cfg.Server.ACLAllowUnrestrictedRecursion {
		logger.Warnf("SECURITY WARNING: Recursive resolver is enabled with no ACL rules but acl_allow_unrestricted_recursion=true. This configuration makes the server an OPEN RECURSIVE RESOLVER accessible from any IP. Only set acl_allow_unrestricted_recursion=true if you intentionally want to run an open resolver.")
	}

	// Share the zones mutex between handler, AXFR server, and DDNS handler
	// to prevent data races on the shared zones map
	transferManager.SetZonesMu(&handler.zonesMu)

	// ── Build hot-reload state (shared by the API callback and SIGHUP) ──
	reloadState := &reloadableState{
		cfg:             &cfg,
		cfgMu:           &cfgMu,
		securityManager: &securityManager,
		bl:              &bl,
		rpzEngine:       &rpzEngine,
		geoEngine:       &geoEngine,
		dns64Synth:      &dns64Synth,
		aclChecker:      &aclChecker,
		rateLimiter:     &rateLimiter,
		upstreamManager: &upstreamManager,
		dnssecManager:   &dnssecManager,
		client:          &client,
		loadBalancer:    &loadBalancer,
		validator:       &validator,
		zoneFiles:       &zoneFiles,
		zoneMgr:         zoneManagerInstance,
		handler:         handler,
		apiServer:       nil, // set below after apiServer is created
		logger:          logger,
		auditLog:        auditLogger,
	}

	// Initialize API server
	dashboardServer := dashboard.NewServer()
	dashboardServer.SetAllowedOrigins(cfg.Server.HTTP.AllowedOrigins)
	dashboardServer.SetAuthStore(authStore)
	dashboardServer.SetAuthToken(resolveDashboardBearer(cfg.Server.HTTP))
	dashboardServer.SetZoneManager(zoneManagerInstance)
	// Feed per-query events into the dashboard (Query Log page + live stream).
	handler.dashboardServer = dashboardServer
	httpConfig := effectiveHTTPConfig(cfg)
	var apiServer *api.Server
	apiServer = api.NewServer(httpConfig, zoneManagerInstance, dnsCache, func() error {
		logger.Info("Reloading configuration via API...")
		if auditLogger != nil {
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Action:    "start",
			})
		}
		n, err := reloadConfig(*configPath, reloadState)
		if auditLogger != nil {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			auditLogger.LogReload(audit.ReloadAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Action:    "complete",
				Zones:     n,
				Error:     errStr,
			})
		}
		return err
	}, handler, clusterMgr, dashboardServer).
		WithConfigGetter(func() *config.Config {
			cfgMu.RLock()
			c := cfg
			cfgMu.RUnlock()
			return c
		}).
		WithBlocklist(bl).
		WithUpstream(client, loadBalancer).
		WithACL(aclChecker).
		WithAuth(authStore).
		WithDashboard(dashboardServer).
		WithMetrics(metricsCollector).
		WithDNSSEC(validator).
		WithTracer(tracer).
		WithZoneSigners(zoneSigners).
		WithRPZ(rpzEngine).
		WithGeoDNS(geoEngine).
		WithSlaveManager(transferManager.Result().SlaveManager).
		WithRateLimiter(rateLimiter)
	reloadState.apiServer = apiServer // wire apiServer back into reload state

	// Initialize ODoH (RFC 9230) if enabled
	if httpConfig.ODoHEnabled {
		odohConfig := buildODoHConfig(cfg, httpConfig)

		if cfg.ODoH.Enabled && cfg.ODoH.TargetURL != "" {
			// Running as ODoH proxy forwarding to external target
			odohConfig.TargetURL = cfg.ODoH.TargetURL
			odohConfig.ProxyURL = cfg.ODoH.ProxyURL
			odohProxy, err := odoh.NewObliviousProxy(odohConfig)
			if err != nil {
				return fmt.Errorf("creating ODoH proxy: %w", err)
			} else {
				logger.Infof("ODoH proxy configured (target: %s)", cfg.ODoH.TargetURL)
				apiServer = apiServer.WithODoH(odohProxy)
			}
		} else {
			// Running as ODoH target resolver with local DNS handler
			odohTarget, err := odoh.NewObliviousTarget(odohConfig, handler)
			if err != nil {
				return fmt.Errorf("creating ODoH target: %w", err)
			} else {
				logger.Infof("ODoH target configured (KEM=%d, KDF=%d, AEAD=%d)",
					odohConfig.HPKEKEM, odohConfig.HPKEKDF, odohConfig.HPKEAEAD)
				apiServer = apiServer.WithODoHTarget(odohTarget)
			}
		}
	}

	if err := apiServer.Start(); err != nil {
		if httpConfig.Enabled {
			return fmt.Errorf("starting API server: %w", err)
		}
		logger.Warnf("Failed to start API server: %v", err)
	} else if httpConfig.Enabled {
		logger.Infof("API server listening on %s", httpConfig.Bind)
		if httpConfig.DoHEnabled {
			logger.Infof("DoH endpoint enabled at %s", httpConfig.DoHPath)
		}
		if httpConfig.ODoHEnabled {
			logger.Infof("ODoH endpoint enabled at %s", httpConfig.ODoHPath)
		}
	}

	// ── Phase 2: Start DNS transport servers ───────────────────────────
	transports, err := startServers(cfg, handler, transferManager, logger)
	if err != nil {
		// Clean up already-started transports before returning the error.
		transports.stopAll(logger)
		return err
	}
	startStatsCollector(transports, metricsCollector, stopCh)

	// Setup signal handling — delegating to a package-level helper makes
	// the lifecycle overridable from tests (see main_test.go's
	// installFakeSignalHandler). Default: real OS signals.
	sigChan := setupSignalHandler()

	// Capture proper goroutine baseline after all servers are running
	apiServer.SetGoroutineBaseline()

	logger.Info("Server started successfully")

	// Write PID file if configured
	if cfg.Server.PIDFile != "" {
		pidStr := fmt.Sprintf("%d\n", os.Getpid())
		if err := writePIDFile(cfg.Server.PIDFile, []byte(pidStr)); err != nil {
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

				// Stop transport servers (UDP/TCP/TLS/DoQ/XoT)
				cancelServer() // Cancel in-flight queries before stopping transports
				transports.stopAll(logger)

				// Close upstream client and load balancer
				upstreamManager.Stop()

				// Stop metrics server
				if metricsCollector != nil {
					if err := metricsCollector.Stop(); err != nil {
						logger.Warnf("Failed to stop metrics collector cleanly: %v", err)
					}
				}

				// Drain dashboard/DoWS WebSocket clients before stopping the
				// API server. These connections are hijacked off the API
				// http.Server, so httpServer.Shutdown() does not track them;
				// without this they are abandoned rather than gracefully
				// closed, losing in-flight writes and leaking their goroutines.
				if dashboardServer != nil {
					dashboardServer.Stop()
				}

				// Stop API server
				if apiServer != nil {
					if err := apiServer.Stop(); err != nil {
						logger.Warnf("Failed to stop API server cleanly: %v", err)
					}
				}

				// Stop cluster manager
				clusterManager.Stop()

				// Stop transfer manager (slave manager, notify handler, DDNS handler)
				transferManager.Stop()

				// Flush and shut down the OpenTelemetry tracer provider so
				// batched spans reach the collector before exit.
				if tracer != nil {
					if err := tracer.Shutdown(context.Background()); err != nil {
						logger.Warnf("Failed to shut down tracer cleanly: %v", err)
					}
				}

				// Stop mDNS responder
				if mdnsResponder != nil {
					mdnsResponder.Stop()
				}

				// Stop DSO manager
				if dsoManager != nil {
					dsoManager.Stop()
				}

				// Stop security manager (rate limiter)
				securityManager.Stop()

				// Persist session tokens to file if configured
				if cfg.Server.HTTP.TokenPersistencePath != "" {
					if err := authStore.SaveTokensSigned(cfg.Server.HTTP.TokenPersistencePath); err != nil {
						logger.Warnf("Failed to persist tokens to %s: %v", cfg.Server.HTTP.TokenPersistencePath, err)
					}
				}

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
				logger.Warnf("Server shutdown timed out after %s", shutdownTimeout)
			}

			// Clean up PID file
			if cfg.Server.PIDFile != "" {
				if err := os.Remove(cfg.Server.PIDFile); err != nil && !os.IsNotExist(err) {
					logger.Warnf("Failed to remove PID file %s: %v", cfg.Server.PIDFile, err)
				}
			}

			return nil

		case syscall.SIGHUP:
			logger.Info("Received SIGHUP, reloading configuration...")
			if auditLogger != nil {
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "start",
				})
			}
			n, err := reloadConfig(*configPath, reloadState)
			if err != nil {
				logger.Warnf("SIGHUP reload failed (keeping old config): %v", err)
			}
			if auditLogger != nil {
				errStr := ""
				if err != nil {
					errStr = err.Error()
				}
				auditLogger.LogReload(audit.ReloadAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Action:    "complete",
					Zones:     n,
					Error:     errStr,
				})
			}
		}
	}
}

// loadConfig loads and validates the configuration file.
func loadConfig(path string) (*config.Config, error) {
	data, err := readLimitedFile(path, maxConfigFileSize)
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
	if z == nil {
		return nil, fmt.Errorf("zone.ParseFile returned nil zone for %s", path)
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

	for _, keyConfig := range signingCfg.Keys {
		if keyConfig.PrivateKey == "" {
			continue
		}

		key, err := loadConfiguredSigningKey(keyConfig)
		if err != nil {
			return nil, fmt.Errorf("loading private key %q: %w", keyConfig.PrivateKey, err)
		}
		signer.AddKey(key)
	}

	return signer, nil
}

func loadConfiguredSigningKey(keyConfig config.KeyConfig) (*dnssec.SigningKey, error) {
	if !protocol.IsAlgorithmSupported(keyConfig.Algorithm) {
		return nil, fmt.Errorf("unsupported algorithm: %d", keyConfig.Algorithm)
	}

	privKey, err := loadDNSSECPrivateKeyFile(keyConfig.PrivateKey, keyConfig.Algorithm)
	if err != nil {
		return nil, err
	}

	publicKey, err := dnssec.GeneratePublicKeyData(keyConfig.Algorithm, privKey)
	if err != nil {
		return nil, fmt.Errorf("generating DNSKEY public key: %w", err)
	}

	flags := uint16(protocol.DNSKEYFlagZone)
	isKSK := keyConfig.Type == "ksk"
	if isKSK {
		flags |= protocol.DNSKEYFlagSEP
	}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     flags,
		Protocol:  3,
		Algorithm: keyConfig.Algorithm,
		PublicKey: publicKey,
	}
	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	if keyTag == 0 {
		return nil, fmt.Errorf("DNSSEC key tag must not be zero")
	}

	return &dnssec.SigningKey{
		PrivateKey: privKey,
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}, nil
}

func loadDNSSECPrivateKeyFile(path string, algorithm uint8) (*dnssec.PrivateKey, error) {
	data, err := readLimitedFile(path, maxDNSSECPrivateKeyFileSize)
	if err != nil {
		return nil, err
	}
	return parseDNSSECPrivateKey(data, algorithm)
}

func readLimitedFile(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSize)
	}
	return data, nil
}

func writePIDFile(path string, data []byte) error {
	return util.AtomicWriteFile(path, data)
}

func parseDNSSECPrivateKey(data []byte, algorithm uint8) (*dnssec.PrivateKey, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}

	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		key, err := parseRSAPrivateKey(der)
		if err != nil {
			return nil, err
		}
		return &dnssec.PrivateKey{Algorithm: algorithm, Key: key}, nil
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		key, err := parseECDSAPrivateKey(der, algorithm)
		if err != nil {
			return nil, err
		}
		return &dnssec.PrivateKey{Algorithm: algorithm, Key: key}, nil
	case protocol.AlgorithmED25519:
		key, err := parseEd25519PrivateKey(der)
		if err != nil {
			return nil, err
		}
		return &dnssec.PrivateKey{Algorithm: algorithm, Key: key}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", key)
	}
	return rsaKey, nil
}

func parseECDSAPrivateKey(der []byte, algorithm uint8) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return validateECDSAPrivateKeyCurve(key, algorithm)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDSA private key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not ECDSA", key)
	}
	return validateECDSAPrivateKeyCurve(ecdsaKey, algorithm)
}

func validateECDSAPrivateKeyCurve(key *ecdsa.PrivateKey, algorithm uint8) (*ecdsa.PrivateKey, error) {
	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ECDSAP256SHA256 requires P-256 private key")
		}
	case protocol.AlgorithmECDSAP384SHA384:
		if key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ECDSAP384SHA384 requires P-384 private key")
		}
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %d", algorithm)
	}
	return key, nil
}

func parseEd25519PrivateKey(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, not Ed25519", key)
		}
		return edKey, nil
	}
	if len(der) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), der...)), nil
	}
	return nil, fmt.Errorf("parsing Ed25519 private key: %w", err)
}

// validateConfigOnly loads and validates a configuration file without starting the server.
//
// Unlike loadConfig (which falls back to defaults when the path doesn't
// exist — handy at server start, but wrong here), this explicitly
// requires the file to be present. Otherwise `nothingdns -config
// /typo'd/path -validate-config` used to print "is valid" — the
// operator would think their config worked when the file isn't even
// being read.
func validateConfigOnly(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return err
	}
	return nil
}

func validateProductionConfigOnly(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("config file %s not accessible: %w", path, err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if errs := cfg.ValidateProduction(); len(errs) > 0 {
		return fmt.Errorf("production config validation failed: %s", strings.Join(errs, "; "))
	}
	if err := validateRuntimeAssets(cfg); err != nil {
		return err
	}
	return nil
}

func validateRuntimeAssets(cfg *config.Config) error {
	zoneFiles, err := discoverStartupZoneFiles(cfg)
	if err != nil {
		return err
	}
	loadedZones := make([]*zone.Zone, 0, len(zoneFiles))
	for _, zoneFile := range zoneFiles {
		z, err := loadZoneFile(zoneFile)
		if err != nil {
			return fmt.Errorf("validating zone file %s: %w", zoneFile, err)
		}
		loadedZones = append(loadedZones, z)
	}
	if cfg.DNSSEC.Enabled && cfg.DNSSEC.Signing.Enabled {
		for _, z := range loadedZones {
			if _, err := loadZoneSigner(z, cfg.DNSSEC.Signing); err != nil {
				return fmt.Errorf("validating DNSSEC signer for %s: %w", z.Origin, err)
			}
		}
	}
	for _, view := range cfg.Views {
		for _, zoneFile := range view.ZoneFiles {
			if _, err := loadZoneFile(zoneFile); err != nil {
				return fmt.Errorf("validating zone file %s for view %s: %w", zoneFile, view.Name, err)
			}
		}
	}
	if cfg.Resolution.Recursive && cfg.Resolution.RootHints != "" {
		if _, err := loadRootHintsFile(cfg.Resolution.RootHints); err != nil {
			return fmt.Errorf("validating root hints file %s: %w", cfg.Resolution.RootHints, err)
		}
	}
	// Compile ACL rules so invalid CIDRs, unknown query types, and — most
	// importantly — unknown/typo'd actions (which would otherwise fail open at
	// runtime) are reported at validate-config time rather than silently
	// permitting traffic in production.
	if len(cfg.ACL) > 0 {
		if _, err := filter.NewACLChecker(cfg.ACL, true); err != nil {
			return fmt.Errorf("validating ACL rules: %w", err)
		}
	}
	return nil
}

// bindEntryToAddr turns a `server.bind` list entry into a listener
// address. The historical implementation always called
// net.JoinHostPort(entry, port), which silently wrapped an entry
// that already carried a port (e.g. ":15353" or "127.0.0.1:5353")
// into nonsense like "[:15353]:53" — UDP/TCP startup then failed
// with "lookup :15353" because the result was treated as an IPv6
// host. We now accept both forms: if the entry already parses as
// host:port we use it as-is; otherwise we treat it as a bare host
// and join it with the configured port. IPv6 literals must already
// be bracket-wrapped per RFC 3986 to disambiguate from host:port.
func bindEntryToAddr(entry string, port int) string {
	if _, _, err := net.SplitHostPort(entry); err == nil {
		return entry
	}
	// Strip outer brackets if a user supplied "[::1]" — JoinHostPort
	// would re-bracket and produce "[[::1]]:port".
	if len(entry) >= 2 && entry[0] == '[' && entry[len(entry)-1] == ']' {
		entry = entry[1 : len(entry)-1]
	}
	return net.JoinHostPort(entry, fmt.Sprintf("%d", port))
}

// sdNotifySend sends a READY notification to systemd via the unix
// datagram socket named in NOTIFY_SOCKET (or the explicit `socket`
// arg, which takes precedence).
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
  -validate-production-config
        Validate production configuration file and exit
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
  %s -config /path/to/config.yaml -validate-config

  # Validate production configuration
  %s -config /path/to/config.yaml -validate-production-config

  # Show version
  %s -version

For more information, visit: https://github.com/nothingdns/nothingdns
`, Name, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

// setupSignalHandler returns the channel that the wait-for-signals loop
// reads from. Production wires real OS signals into it; tests can
// replace it via installFakeSignalHandler. Each call returns a fresh
// channel.
func setupSignalHandler() <-chan os.Signal {
	if fakeSigCh != nil {
		return fakeSigCh
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return ch
}

// fakeSigCh is a process-wide swap point used by tests to bypass real OS
// signal delivery. Nil means "use real OS signals". Cleared after each
// test by installFakeSignalHandler.
var fakeSigCh chan os.Signal

// installFakeSignalHandler swaps setupSignalHandler's output for the
// supplied channel. Returns a restore function so tests can leave the
// state clean for subsequent runs.
func installFakeSignalHandler(ch chan os.Signal) func() {
	fakeSigCh = ch
	return func() { fakeSigCh = nil }
}
