package api

import (
	"encoding/json"
	"net/http"

	"github.com/nothingdns/nothingdns/internal/config"
)

func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	if s.aclChecker == nil {
		s.writeJSON(w, http.StatusOK, &ACLResponse{Rules: []ACLRuleResponse{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := s.aclChecker.GetRules()
		aclRules := make([]ACLRuleResponse, 0, len(rules))
		for _, rule := range rules {
			aclRules = append(aclRules, ACLRuleResponse{
				Name:     rule.Name,
				Networks: rule.Networks,
				Action:   rule.Action,
				Types:    rule.Types,
			})
		}
		s.writeJSON(w, http.StatusOK, &ACLResponse{Rules: aclRules})
	case http.MethodPut:
		if s.requireOperator(w, r) {
			return
		}
		var req struct {
			Rules []struct {
				Name     string   `json:"name"`
				Networks []string `json:"networks"`
				Action   string   `json:"action"`
				Types    []string `json:"types,omitempty"`
				Redirect string   `json:"redirect,omitempty"`
			} `json:"rules"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Convert to config rules
		configRules := make([]config.ACLRule, 0, len(req.Rules))
		for _, rule := range req.Rules {
			configRules = append(configRules, config.ACLRule{
				Name:     rule.Name,
				Networks: rule.Networks,
				Action:   rule.Action,
				Types:    rule.Types,
				Redirect: rule.Redirect,
			})
		}

		if err := s.aclChecker.UpdateRules(configRules); err != nil {
			s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "ACL rules updated"})
	}
}

// handleRPZ returns RPZ statistics.
