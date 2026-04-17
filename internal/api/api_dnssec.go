package api

import (
	"net/http"

	"github.com/nothingdns/nothingdns/internal/dnssec"
)

func (s *Server) handleDNSSECStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.validator == nil {
		s.writeJSON(w, http.StatusOK, &dnssec.DNSSECStatus{
			Enabled: false,
		})
		return
	}

	status := s.validator.DNSSECStatus()
	s.writeJSON(w, http.StatusOK, status)
}

// handleDNSSECKeys returns DNSSEC signing keys for all zones or a specific zone.
func (s *Server) handleDNSSECKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireAdmin(w, r) {
		return
	}

	var keys []DNSSECKeyInfo
	s.zoneSignersMu.RLock()
	for zone, signer := range s.zoneSigners {
		for _, k := range signer.GetKeys() {
			keys = append(keys, DNSSECKeyInfo{
				KeyTag:    k.KeyTag,
				Algorithm: k.DNSKEY.Algorithm,
				Flags:     k.DNSKEY.Flags,
				IsKSK:     k.IsKSK,
				IsZSK:     k.IsZSK,
				Zone:      zone,
			})
		}
	}
	s.zoneSignersMu.RUnlock()
	s.writeJSON(w, http.StatusOK, DNSSECKeysResponse{Zones: keys})
}

// handleStatus returns server status.
