package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/doh"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Server provides HTTP API for DNS server management.
type Server struct {
	config      config.HTTPConfig
	httpServer  *http.Server
	zoneManager *zone.Manager
	cache       *cache.Cache
	reloadFunc  func() error
	dnsHandler  server.Handler
	cluster     *cluster.Cluster
}

// NewServer creates a new API server.
func NewServer(cfg config.HTTPConfig, zm *zone.Manager, c *cache.Cache, reload func() error, dnsHandler server.Handler, cluster *cluster.Cluster) *Server {
	return &Server{
		config:      cfg,
		zoneManager: zm,
		cache:       c,
		reloadFunc:  reload,
		dnsHandler:  dnsHandler,
		cluster:     cluster,
	}
}

// Start starts the API server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()

	// DoH endpoint (RFC 8484) - no auth required
	if s.config.DoHEnabled && s.dnsHandler != nil {
		dohHandler := doh.NewHandler(s.dnsHandler)
		mux.Handle(s.config.DoHPath, dohHandler)
	}

	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Cluster management
	if s.cluster != nil {
		mux.HandleFunc("/api/v1/cluster/status", s.handleClusterStatus)
		mux.HandleFunc("/api/v1/cluster/nodes", s.handleClusterNodes)
	}

	// Zone management
	mux.HandleFunc("/api/v1/zones", s.handleZones)
	mux.HandleFunc("/api/v1/zones/reload", s.handleZoneReload)
	mux.HandleFunc("/api/v1/zones/", s.handleZoneActions)

	// Cache management
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/api/v1/cache/flush", s.handleCacheFlush)

	// Config management
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)

	// Dashboard UI
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/dashboard/stats", s.handleDashboardStats)
	mux.HandleFunc("/", s.handleDashboard)

	s.httpServer = &http.Server{
		Addr:         s.config.Bind,
		Handler:      s.corsMiddleware(s.authMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the API server.
func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// corsMiddleware adds CORS headers.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware adds authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.AuthToken == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		token := r.Header.Get("Authorization")

		// Check query parameter
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		// Check cookie
		if token == "" {
			if c, err := r.Cookie("ndns_token"); err == nil {
				token = c.Value
			}
		}

		expected := "Bearer " + s.config.AuthToken
		if token == expected || token == s.config.AuthToken {
			next.ServeHTTP(w, r)
			return
		}

		// For dashboard pages, serve the login page instead of JSON error
		if r.URL.Path == "/" || r.URL.Path == "/dashboard" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(dashboard.GetLoginHTML()))
			return
		}

		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
	})
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleDashboard serves the web UI dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Only serve dashboard for exact "/" or "/dashboard" paths
	if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboard.GetIndexHTML()))
}

// handleDashboardStats returns stats formatted for the web dashboard.
func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"uptime":          0,
		"queriesTotal":    0,
		"queriesPerSec":   0.0,
		"cacheHitRate":    0.0,
		"blockedQueries":  0,
		"activeClients":   0,
		"zoneCount":       0,
		"upstreamLatency": 0,
	}

	if s.cache != nil {
		cs := s.cache.Stats()
		stats["queriesTotal"] = cs.Hits + cs.Misses
		total := float64(cs.Hits + cs.Misses)
		if total > 0 {
			stats["cacheHitRate"] = float64(cs.Hits) / total * 100
		}
	}

	if s.zoneManager != nil {
		stats["zoneCount"] = s.zoneManager.Count()
	}

	s.writeJSON(w, http.StatusOK, stats)
}

// handleStatus returns server status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "running",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   util.Version,
	}

	if s.cache != nil {
		stats := s.cache.Stats()
		status["cache"] = map[string]interface{}{
			"size":      stats.Size,
			"capacity":  stats.Capacity,
			"hits":      stats.Hits,
			"misses":    stats.Misses,
			"hit_ratio": stats.HitRatio(),
		}
	}

	if s.cluster != nil {
		clusterStats := s.cluster.Stats()
		status["cluster"] = map[string]interface{}{
			"enabled":     true,
			"node_id":     clusterStats.NodeID,
			"node_count":  clusterStats.NodeCount,
			"alive_count": clusterStats.AliveCount,
			"healthy":     clusterStats.IsHealthy,
		}
	} else {
		status["cluster"] = map[string]interface{}{
			"enabled": false,
		}
	}

	s.writeJSON(w, http.StatusOK, status)
}

// handleZones handles GET (list zones) and POST (create zone).
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListZones(w, r)
	case http.MethodPost:
		s.handleCreateZone(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleListZones returns list of zones with serial and record count.
func (s *Server) handleListZones(w http.ResponseWriter, r *http.Request) {
	zones := []map[string]interface{}{}
	if s.zoneManager != nil {
		for name, z := range s.zoneManager.List() {
			z.RLock()
			recordCount := 0
			for _, records := range z.Records {
				recordCount += len(records)
			}
			serial := uint32(0)
			if z.SOA != nil {
				serial = z.SOA.Serial
			}
			z.RUnlock()
			zones = append(zones, map[string]interface{}{
				"name":    name,
				"serial":  serial,
				"records": recordCount,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"zones": zones,
	})
}

// handleZoneActions dispatches zone-specific operations based on path and method.
// Routes: DELETE /api/v1/zones/{name}
//
//	GET    /api/v1/zones/{name}/records
//	POST   /api/v1/zones/{name}/records
//	PUT    /api/v1/zones/{name}/records
//	DELETE /api/v1/zones/{name}/records
//	GET    /api/v1/zones/{name}/export
func (s *Server) handleZoneActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/zones/")

	// Decode URL-encoded zone name (e.g., "example.com." from "example.com.")
	zoneName, err := url.PathUnescape(path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid zone name")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	// Check if there's a sub-path after the zone name
	parts := strings.SplitN(zoneName, "/", 2)
	if len(parts) == 1 || parts[1] == "" {
		// /api/v1/zones/{name}
		switch r.Method {
		case http.MethodGet:
			s.handleGetZone(w, r, parts[0])
		case http.MethodDelete:
			s.handleDeleteZone(w, r, parts[0])
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	zoneName = parts[0]
	subPath := parts[1]

	switch {
	case subPath == "records":
		switch r.Method {
		case http.MethodGet:
			s.handleGetRecords(w, r, zoneName)
		case http.MethodPost:
			s.handleAddRecord(w, r, zoneName)
		case http.MethodPut:
			s.handleUpdateRecord(w, r, zoneName)
		case http.MethodDelete:
			s.handleDeleteRecord(w, r, zoneName)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case subPath == "export":
		if r.Method == http.MethodGet {
			s.handleExportZone(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		s.writeError(w, http.StatusNotFound, "Not found")
	}
}

// handleGetZone returns details of a single zone.
func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request, name string) {
	z, ok := s.zoneManager.Get(name)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", name))
		return
	}

	z.RLock()
	defer z.RUnlock()

	recordCount := 0
	for _, records := range z.Records {
		recordCount += len(records)
	}

	result := map[string]interface{}{
		"name":    z.Origin,
		"records": recordCount,
	}

	if z.SOA != nil {
		result["serial"] = z.SOA.Serial
		result["soa"] = map[string]interface{}{
			"mname":   z.SOA.MName,
			"rname":   z.SOA.RName,
			"serial":  z.SOA.Serial,
			"refresh": z.SOA.Refresh,
			"retry":   z.SOA.Retry,
			"expire":  z.SOA.Expire,
			"minimum": z.SOA.Minimum,
		}
	}

	var nsList []string
	for _, ns := range z.NS {
		nsList = append(nsList, ns.NSDName)
	}
	result["nameservers"] = nsList

	s.writeJSON(w, http.StatusOK, result)
}

// handleCreateZone creates a new zone.
func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name        string   `json:"name"`
		TTL         uint32   `json:"ttl"`
		AdminEmail  string   `json:"admin_email"`
		Nameservers []string `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Zone name is required")
		return
	}
	if len(req.Nameservers) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one nameserver is required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = 3600
	}

	soa := &zone.SOARecord{
		TTL:     ttl,
		MName:   req.Nameservers[0],
		RName:   req.AdminEmail,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	var nsRecords []zone.NSRecord
	for _, ns := range req.Nameservers {
		nsRecords = append(nsRecords, zone.NSRecord{
			TTL:    ttl,
			NSDName: ns,
		})
	}

	if err := s.zoneManager.CreateZone(req.Name, ttl, soa, nsRecords); err != nil {
		s.writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": fmt.Sprintf("Zone %s created", req.Name),
		"name":    req.Name,
	})
}

// handleDeleteZone deletes a zone.
func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.zoneManager.DeleteZone(name); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Zone %s deleted", name),
	})
}

// handleGetRecords returns records for a zone.
func (s *Server) handleGetRecords(w http.ResponseWriter, r *http.Request, zoneName string) {
	name := r.URL.Query().Get("name")

	records, err := s.zoneManager.GetRecords(zoneName, name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Convert to API response
	result := make([]map[string]interface{}, 0, len(records))
	for _, r := range records {
		result = append(result, map[string]interface{}{
			"name":  r.Name,
			"type":  r.Type,
			"ttl":   r.TTL,
			"class": r.Class,
			"data":  r.RData,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"records": result,
	})
}

// handleAddRecord adds a record to a zone.
func (s *Server) handleAddRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
		TTL  uint32 `json:"ttl"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" || req.Data == "" {
		s.writeError(w, http.StatusBadRequest, "name, type, and data are required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		// Use zone's default TTL
		if z, ok := s.zoneManager.Get(zoneName); ok {
			z.RLock()
			ttl = z.DefaultTTL
			z.RUnlock()
		}
		if ttl == 0 {
			ttl = 3600
		}
	}

	record := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   ttl,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.AddRecord(zoneName, record); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Record added",
	})
}

// handleUpdateRecord updates a record in a zone.
func (s *Server) handleUpdateRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		OldData string `json:"old_data"`
		TTL     uint32 `json:"ttl"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	newRecord := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   req.TTL,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.UpdateRecord(zoneName, req.Name, req.Type, req.OldData, newRecord); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Record updated",
	})
}

// handleDeleteRecord deletes a record from a zone.
func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	if err := s.zoneManager.DeleteRecord(zoneName, req.Name, req.Type); err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Record deleted",
	})
}

// handleExportZone returns a zone in BIND format.
func (s *Server) handleExportZone(w http.ResponseWriter, r *http.Request, zoneName string) {
	content, err := s.zoneManager.ExportZone(zoneName)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", strings.TrimSuffix(zoneName, ".")))
	w.Write([]byte(content))
}

// handleZoneReload reloads a zone.
func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	zoneName := r.URL.Query().Get("zone")
	if zoneName == "" {
		s.writeError(w, http.StatusBadRequest, "Missing zone parameter")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	if err := s.zoneManager.Reload(zoneName); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload zone: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Zone %s reloaded", zoneName),
	})
}

// handleCacheStats returns cache statistics.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats := s.cache.Stats()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"size":      stats.Size,
		"capacity":  stats.Capacity,
		"hits":      stats.Hits,
		"misses":    stats.Misses,
		"hit_ratio": stats.HitRatio(),
	})
}

// handleCacheFlush flushes the cache.
func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	s.cache.Flush()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Cache flushed",
	})
}

// handleConfigReload reloads configuration.
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.reloadFunc == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Reload not available")
		return
	}

	if err := s.reloadFunc(); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload config: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Configuration reloaded",
	})
}

// handleClusterStatus returns cluster status.
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	stats := s.cluster.Stats()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"node_id":     stats.NodeID,
		"node_count":  stats.NodeCount,
		"alive_count": stats.AliveCount,
		"healthy":     stats.IsHealthy,
		"gossip": map[string]interface{}{
			"messages_sent":     stats.GossipStats.MessagesSent,
			"messages_received": stats.GossipStats.MessagesReceived,
			"ping_sent":         stats.GossipStats.PingSent,
			"ping_received":     stats.GossipStats.PingReceived,
		},
	})
}

// handleClusterNodes returns list of cluster nodes.
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.cluster == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cluster not available")
		return
	}

	nodes := s.cluster.GetNodes()
	nodeList := make([]map[string]interface{}, 0, len(nodes))
	for _, node := range nodes {
		nodeList = append(nodeList, map[string]interface{}{
			"id":        node.ID,
			"addr":      node.Addr,
			"port":      node.Port,
			"state":     node.State.String(),
			"region":    node.Meta.Region,
			"zone":      node.Meta.Zone,
			"weight":    node.Meta.Weight,
			"http_addr": node.Meta.HTTPAddr,
			"version":   node.Version,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": nodeList,
	})
}

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("api: failed to encode JSON response: %v", err)
	}
}

// writeError writes an error response.
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]interface{}{
		"error": message,
	})
}
