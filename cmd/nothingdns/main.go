// NothingDNS - Main server binary
// Zero-dependency DNS server written in pure Go

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nothingdns/nothingdns/internal/api"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	Version = "0.1.0"
	Name    = "NothingDNS"
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

// integratedHandler is the DNS request handler that uses all components.
type integratedHandler struct {
	config    *config.Config
	logger    *util.Logger
	cache     *cache.Cache
	upstream  *upstream.Client
	zones     map[string]*zone.Zone
	blocklist *blocklist.Blocklist
	metrics   *metrics.MetricsCollector
}

func main() {
	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", Name, Version)
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
	logger.Infof("Starting %s v%s", Name, Version)

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

	// Initialize upstream client
	var client *upstream.Client
	if len(cfg.Upstream.Servers) > 0 {
		upstreamConfig := upstream.Config{
			Servers:  cfg.Upstream.Servers,
			Strategy: cfg.Upstream.Strategy,
		}
		client, err = upstream.NewClient(upstreamConfig)
		if err != nil {
			logger.Warnf("Failed to initialize upstream client: %v", err)
		} else {
			logger.Infof("Upstream client initialized with %d servers", len(cfg.Upstream.Servers))
		}
	}

	// Load zone files
	zones := make(map[string]*zone.Zone)
	for _, zoneFile := range cfg.Zones {
		z, err := loadZoneFile(zoneFile)
		if err != nil {
			logger.Warnf("Failed to load zone file %s: %v", zoneFile, err)
			continue
		}
		zones[z.Origin] = z
		logger.Infof("Loaded zone %s with %d records", z.Origin, len(z.Records))
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

	// Initialize zone manager
	zoneManager := zone.NewManager()
	for _, zoneFile := range cfg.Zones {
		z, err := loadZoneFile(zoneFile)
		if err != nil {
			logger.Warnf("Failed to load zone file %s: %v", zoneFile, err)
			continue
		}
		zoneManager.LoadZone(z, zoneFile)
		logger.Infof("Loaded zone %s with %d records", z.Origin, len(z.Records))
	}

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
	})
	if err := apiServer.Start(); err != nil {
		logger.Warnf("Failed to start API server: %v", err)
	} else if cfg.Server.HTTP.Enabled {
		logger.Infof("API server listening on %s", cfg.Server.HTTP.Bind)
	}

	// Create handler
	handler := &integratedHandler{
		config:    cfg,
		logger:    logger,
		cache:     dnsCache,
		upstream:  client,
		zones:     zones,
		blocklist: bl,
		metrics:   metricsCollector,
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

			// Stop servers
			udpServer.Stop()
			tcpServer.Stop()

			// Close upstream client
			if client != nil {
				client.Close()
			}

			// Stop metrics server
			if metricsCollector != nil {
				metricsCollector.Stop()
			}

			// Stop API server
			if apiServer != nil {
				apiServer.Stop()
			}

			logger.Info("Server shutdown complete")
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
				zones[z.Origin] = z
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
	if errors := cfg.Validate(); len(errors) > 0 {
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "Config validation error: %s\n", e)
		}
		return nil, fmt.Errorf("configuration validation failed")
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

// ServeDNS implements the server.Handler interface.
func (h *integratedHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	// Check if we have questions
	if len(r.Questions) == 0 {
		h.logger.Debug("Query with no questions")
		sendError(w, r, protocol.RcodeFormatError)
		return
	}

	q := r.Questions[0]
	qname := q.Name.String()
	qtype := q.QType

	h.logger.Debugf("Query: %s %s", qname, typeToString(qtype))

	// Record query metric
	if h.metrics != nil {
		h.metrics.RecordQuery(typeToString(qtype))
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

	// Check authoritative zones
	for origin, z := range h.zones {
		if isSubdomain(qname, origin) {
			h.logger.Debugf("Checking zone %s for %s", origin, qname)
			if resp := h.handleAuthoritative(z, w, r, q); resp {
				return
			}
		}
	}

	// Forward to upstream
	if h.upstream != nil {
		h.logger.Debugf("Forwarding query for %s to upstream", qname)
		if h.metrics != nil {
			h.metrics.RecordUpstreamQuery(h.config.Upstream.Servers[0])
		}
		resp, err := h.upstream.Query(r)
		if err != nil {
			h.logger.Warnf("Upstream query failed for %s: %v", qname, err)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			sendError(w, r, protocol.RcodeServerFailure)
			return
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
func (h *integratedHandler) handleAuthoritative(z *zone.Zone, w server.ResponseWriter, r *protocol.Message, q *protocol.Question) bool {
	qname := q.Name.String()
	qtype := q.QType

	// Look up records
	records := z.Lookup(qname, typeToString(qtype))
	if len(records) == 0 {
		// Check for CNAME
		cnameRecords := z.Lookup(qname, "CNAME")
		if len(cnameRecords) > 0 {
			resp := h.buildResponse(r, cnameRecords)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeSuccess)
			}
			reply(w, r, resp)
			return true
		}
		return false
	}

	resp := h.buildResponse(r, records)
	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
	reply(w, r, resp)
	return true
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
		rr := &protocol.ResourceRecord{
			Name:  query.Questions[0].Name,
			Type:  stringToType(rec.Type),
			Class: protocol.ClassIN,
			TTL:   rec.TTL,
			Data:  parseRData(rec.Type, rec.RData),
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
	w.Write(response)
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
	w.Write(resp)
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
	switch qtype {
	case protocol.TypeA:
		return "A"
	case protocol.TypeAAAA:
		return "AAAA"
	case protocol.TypeCNAME:
		return "CNAME"
	case protocol.TypeMX:
		return "MX"
	case protocol.TypeNS:
		return "NS"
	case protocol.TypeTXT:
		return "TXT"
	case protocol.TypePTR:
		return "PTR"
	case protocol.TypeSOA:
		return "SOA"
	case protocol.TypeSRV:
		return "SRV"
	default:
		return "UNKNOWN"
	}
}

// stringToType converts a type string to DNS type number.
func stringToType(s string) uint16 {
	switch strings.ToUpper(s) {
	case "A":
		return protocol.TypeA
	case "AAAA":
		return protocol.TypeAAAA
	case "CNAME":
		return protocol.TypeCNAME
	case "MX":
		return protocol.TypeMX
	case "NS":
		return protocol.TypeNS
	case "TXT":
		return protocol.TypeTXT
	case "PTR":
		return protocol.TypePTR
	case "SOA":
		return protocol.TypeSOA
	case "SRV":
		return protocol.TypeSRV
	default:
		return 0
	}
}

// parseRData parses RData string based on record type.
func parseRData(rtype, rdata string) protocol.RData {
	switch strings.ToUpper(rtype) {
	case "A":
		ip := net.ParseIP(rdata)
		if ip != nil {
			var addr [4]byte
			copy(addr[:], ip.To4())
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
	}
	return nil
}

// extractTTL extracts a reasonable TTL from a response.
func extractTTL(resp *protocol.Message) uint32 {
	if len(resp.Answers) > 0 && resp.Answers[0].TTL > 0 {
		return resp.Answers[0].TTL
	}
	return 300
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
