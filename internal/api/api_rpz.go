package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleRPZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.rpzEngine == nil {
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

	stats := s.rpzEngine.Stats()
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
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.rpzEngine == nil {
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{Rules: []RPZRuleResponse{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := s.rpzEngine.ListQNAMERules()
		resp := make([]RPZRuleResponse, 0, len(rules))
		for _, r := range rules {
			resp = append(resp, RPZRuleResponse{
				Pattern:      r.Pattern,
				Action:       actionToString(r.Action),
				Trigger:      triggerToString(r.Trigger),
				OverrideData: r.OverrideData,
				PolicyName:   r.PolicyName,
				Priority:     r.Priority,
			})
		}
		s.writeJSON(w, http.StatusOK, &RPZRulesResponse{Rules: resp})
	case http.MethodPost:
		// RPZ rewrites can redirect arbitrary zones (e.g. bank.com →
		// attacker.example), so admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
		var req RPZAddRuleRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if req.Pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern is required")
			return
		}
		action := parseAction(req.Action)
		s.rpzEngine.AddQNAMERule(req.Pattern, action, req.OverrideData)
		s.writeJSON(w, http.StatusCreated, &MessageResponse{Message: "Rule added"})
	case http.MethodDelete:
		if s.requireAdmin(w, r) {
			return
		}
		// DELETE /api/v1/rpz/rules?pattern=domain.com
		pattern := r.URL.Query().Get("pattern")
		if pattern == "" {
			s.writeError(w, http.StatusBadRequest, "pattern query parameter required")
			return
		}
		s.rpzEngine.RemoveQNAMERule(pattern)
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Rule removed"})
	}
}

// handleRPZActions handles RPZ enable/disable toggle.
func (s *Server) handleRPZActions(w http.ResponseWriter, r *http.Request) {
	if s.rpzEngine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "RPZ not available")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rpz/")
	if strings.HasPrefix(path, "toggle") {
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
		newState := s.rpzEngine.Toggle()
		s.writeJSON(w, http.StatusOK, &MessageResponse{
			Message: fmt.Sprintf("RPZ %s", map[bool]string{true: "enabled", false: "disabled"}[newState]),
		})
		return
	}

	s.writeError(w, http.StatusNotFound, "Not found")
}

// handleServerConfig returns the current server configuration (read-only, sanitized).
