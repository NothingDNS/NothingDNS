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
		Version:    util.Version,
		ListenPort: 0,  // Not available in HTTPConfig
		LogLevel:   "", // Not available in HTTPConfig
	}

	if s.configGetter != nil {
		cfg := s.configGetter()
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
	if s.geoEngine != nil {
		stats = s.geoEngine.Stats()
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
	if s.slaveManager != nil {
		for _, sz := range s.slaveManager.GetAllSlaveZones() {
			status := "pending"
			serial := sz.GetLastSerial()
			records := 0
			if sz.Zone != nil {
				status = "synced"
				for _, recs := range sz.Zone.Records {
					records += len(recs)
				}
			}
			lastTransfer := ""
			if !sz.LastTransfer.IsZero() {
				lastTransfer = sz.LastTransfer.Format(time.RFC3339)
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
