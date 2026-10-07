package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	resp := &ServerConfigResponse{
		Version: util.Version,
	}

	s.runtimeMu.RLock()
	configGetter := s.configGetter
	s.runtimeMu.RUnlock()
	if configGetter != nil {
		cfg := configGetter()
		if cfg != nil {
			// Real values from config — the dashboard's server-config tile
			// showed a permanent port 0 / empty log level before this.
			resp.ListenPort = cfg.Server.Port
			resp.LogLevel = cfg.Logging.Level
			resp.DNS64 = DNS64ConfigInfo{
				Enabled:     cfg.DNS64.Enabled,
				Prefix:      cfg.DNS64.Prefix,
				PrefixLen:   cfg.DNS64.PrefixLen,
				ExcludeNets: cfg.DNS64.ExcludeNets,
			}
			resp.Cookie = CookieConfigInfo{
				Enabled:        cfg.Cookie.Enabled,
				SecretRotation: cfg.Cookie.SecretRotation,
			}
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleConfigLogging updates the runtime logging level.
func (s *Server) handleGeoDNSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	stats := geodns.Stats{Enabled: false}
	s.runtimeMu.RLock()
	geoEngine := s.geoEngine
	s.runtimeMu.RUnlock()
	if geoEngine != nil {
		stats = geoEngine.Stats()
	}

	s.writeJSON(w, http.StatusOK, &GeoDNSStatsResponse{
		Enabled:    stats.Enabled,
		Rules:      stats.Rules,
		MMDBLoaded: stats.MMDBLoaded,
		Lookups:    stats.Lookups,
		Hits:       stats.Hits,
		Misses:     stats.Misses,
	})
}

// handleSlaveZones returns the list of slave zones and their transfer status.
func (s *Server) handleSlaveZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	resp := &SlaveZonesResponse{SlaveZones: []SlaveZoneResponse{}}
	s.runtimeMu.RLock()
	slaveManager := s.slaveManager
	s.runtimeMu.RUnlock()
	if slaveManager != nil {
		for _, sz := range slaveManager.GetAllSlaveZones() {
			status := "pending"
			serial := sz.GetLastSerial()
			records := 0
			// GetZone reads the pointer under the slave zone's lock: a
			// completing transfer replaces it concurrently (F483).
			if z := sz.GetZone(); z != nil {
				status = "synced"
				z.RLock()
				for _, recs := range z.Records {
					records += len(recs)
				}
				z.RUnlock()
			}
			lastTransfer := ""
			if t := sz.GetLastTransfer(); !t.IsZero() {
				lastTransfer = t.Format(time.RFC3339)
			}
			resp.SlaveZones = append(resp.SlaveZones, SlaveZoneResponse{
				Zone:         sz.Config.ZoneName,
				Masters:      strings.Join(sz.Config.Masters, ", "),
				Serial:       serial,
				LastTransfer: lastTransfer,
				Status:       status,
				Records:      records,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// actionToString converts a PolicyAction to a string.
