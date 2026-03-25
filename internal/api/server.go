package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Server provides HTTP API for DNS server management.
type Server struct {
	config      config.HTTPConfig
	httpServer  *http.Server
	zoneManager *zone.Manager
	cache       *cache.Cache
	reloadFunc  func() error
}

// NewServer creates a new API server.
func NewServer(cfg config.HTTPConfig, zm *zone.Manager, c *cache.Cache, reload func() error) *Server {
	return &Server{
		config:      cfg,
		zoneManager: zm,
		cache:       c,
		reloadFunc:  reload,
	}
}

// Start starts the API server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()

	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Zone management
	mux.HandleFunc("/api/v1/zones", s.handleZones)
	mux.HandleFunc("/api/v1/zones/reload", s.handleZoneReload)

	// Cache management
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/api/v1/cache/flush", s.handleCacheFlush)

	// Config management
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)

	s.httpServer = &http.Server{
		Addr:         s.config.Bind,
		Handler:      s.corsMiddleware(s.authMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error
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

		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		expected := "Bearer " + s.config.AuthToken
		if token != expected && token != s.config.AuthToken {
			s.writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleStatus returns server status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "running",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "0.1.0",
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

	s.writeJSON(w, http.StatusOK, status)
}

// handleZones returns list of zones.
func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	zones := []map[string]interface{}{}
	if s.zoneManager != nil {
		for name, z := range s.zoneManager.List() {
			zones = append(zones, map[string]interface{}{
				"name":    name,
				"records": len(z.Records),
			})
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"zones": zones,
	})
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

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response.
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]interface{}{
		"error": message,
	})
}
