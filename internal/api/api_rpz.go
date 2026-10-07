package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/rpz"
)

func (s *Server) handleRPZ(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	s.runtimeMu.RLock()
	rpzEngine := s.rpzEngine
	s.runtimeMu.RUnlock()

	if rpzEngine == nil {
		s.writeJSON(w, http.StatusOK, &RPZStatsResponse{
			Enabled:       false,
			TotalRules:    0,
			QNAMERules:    0,
			ClientIPRules: 0,
			RespIPRules:   0,
			FilesCount:    0,
			TotalMatches:  0,
			TotalLookups:  0,
		})
		return
	}

	stats := rpzEngine.Stats()
	lastReload := ""
	if !stats.LastReload.IsZero() {
		lastReload = stats.LastReload.Format(time.RFC3339)
	}
	s.writeJSON(w, http.StatusOK, &RPZStatsResponse{
		Enabled:       stats.Enabled,
		TotalRules:    stats.TotalRules,
		QNAMERules:    stats.QNAMERules,
		ClientIPRules: stats.ClientIPRules,
		RespIPRules:   stats.RespIPRules,
		FilesCount:    stats.Files,
		TotalMatches:  stats.TotalMatches,
		TotalLookups:  stats.TotalLookups,
		LastReload:    lastReload,
	})
}

// handleRPZRules returns RPZ QNAME rules list.
func (s *Server) handleRPZRules(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet, http.MethodPost, http.MethodDelete) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		// RPZ rewrites can redirect arbitrary zones (e.g. bank.com →
		// attacker.example), so admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
	}

	s.runtimeMu.RLock()
	rpzEngine := s.rpzEngine
	s.runtimeMu.RUnlock()

	if rpzEngine == nil {
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusServiceUnavailable, "RPZ not available")
			return
		}
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{Rules: []RPZRuleResponse{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := rpzEngine.ListQNAMERules()
		// L-N5: cap response to RPZRulesMaxResults. Real malware-feed
		// RPZ ships millions of rules; even an admin shouldn't
		// accidentally fetch them all in one JSON document.
		total := len(rules)
		limit := total
		truncated := false
		if limit > RPZRulesMaxResults {
			limit = RPZRulesMaxResults
			truncated = true
		}
		resp := make([]RPZRuleResponse, 0, limit)
		for _, r := range rules[:limit] {
			resp = append(resp, RPZRuleResponse{
				Pattern:      r.Pattern,
				Action:       actionToString(r.Action),
				Trigger:      triggerToString(r.Trigger),
				OverrideData: r.OverrideData,
				PolicyName:   r.PolicyName,
				Priority:     r.Priority,
			})
		}
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{
			Rules:     resp,
			Total:     total,
			Truncated: truncated,
		})
	case http.MethodPost:
		var req RPZAddRuleRequest
		if !s.decode(w, r, &req) {
			return
		}
		if req.Pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern is required")
			return
		}
		action := parseAction(req.Action)
		// F282: CNAME and OVERRIDE rules are useless without valid data. The
		// DNS handler answers a CNAME rule with protocol.ParseName(data) (an
		// empty value becomes a CNAME to the root) and silently skips an
		// OVERRIDE rule whose data is not an IP, letting the query through.
		switch action {
		case rpz.ActionCNAME:
			if target, err := protocol.ParseName(req.OverrideData); err != nil || target.IsRoot() {
				s.writeError(w, http.StatusBadRequest, "override_data must be a domain name for a CNAME rule")
				return
			}
		case rpz.ActionOverride:
			if net.ParseIP(req.OverrideData) == nil {
				s.writeError(w, http.StatusBadRequest, "override_data must be an IP address for an OVERRIDE rule")
				return
			}
		}
		rpzEngine.AddQNAMERule(req.Pattern, action, req.OverrideData)
		s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Rule added"})
	case http.MethodDelete:
		// DELETE /api/v1/rpz/rules?pattern=domain.com
		pattern := r.URL.Query().Get("pattern")
		if pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern query parameter required")
			return
		}
		rpzEngine.RemoveQNAMERule(pattern)
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Rule removed"})
	}
}

// handleRPZActions handles RPZ enable/disable toggle.
func (s *Server) handleRPZActions(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}

	s.runtimeMu.RLock()
	rpzEngine := s.rpzEngine
	s.runtimeMu.RUnlock()

	if rpzEngine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "RPZ not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rpz/")
	if path == "toggle" {
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		// Disabling RPZ effectively turns off response filtering for every
		// client — admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
		// Toggle enabled state atomically (VULN-015).
		newState := rpzEngine.Toggle()
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("RPZ %s", map[bool]string{true: "enabled", false: "disabled"}[newState]),
		})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
}

// handleServerConfig returns the current server configuration (read-only, sanitized).
