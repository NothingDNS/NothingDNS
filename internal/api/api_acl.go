package api

import (
	"net/http"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/filter"
)

func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	// GET: operator-readable. PUT: admin-only — an ACL rewrite can trivially
	// self-grant "0.0.0.0/0 allow ANY" and turn the server into an open
	// amplifier, so operator-role is too broad (VULN-009).
	if r.Method == http.MethodPut {
		if s.requireAdmin(w, r) {
			return
		}
	} else if s.requireOperator(w, r) {
		return
	}

	s.runtimeMu.RLock()
	aclChecker := s.aclChecker
	s.runtimeMu.RUnlock()
	if aclChecker == nil {
		if r.Method == http.MethodGet {
			s.writeJSON(w, http.StatusOK, s.aclResponse(nil))
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, "ACL not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, s.aclResponse(aclChecker))
	case http.MethodPut:
		// Admin gate already applied above.
		var req struct {
			Rules []struct {
				Name     string   `json:"name"`
				Networks []string `json:"networks"`
				Action   string   `json:"action"`
				Types    []string `json:"types,omitempty"`
				Redirect string   `json:"redirect,omitempty"`
			} `json:"rules"`
		}
		if !s.decode(w, r, &req) {
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

		s.accessPolicyMu.Lock()
		defer s.accessPolicyMu.Unlock()
		previous := aclChecker.GetRules()
		if err := aclChecker.UpdateRules(configRules); err != nil {
			s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
			return
		}
		if err := s.saveAccessPolicy(aclChecker); err != nil {
			_ = aclChecker.UpdateRules(previous)
			s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save access policy"))
			return
		}
		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "ACL rules updated"})
	}
}

// handleACLRecursion reads and replaces the recursion allow list: the
// clients that may use recursion (upstream forwarding, iterative resolution
// and cached answers). Clients outside it still get the server's own zones.
func (s *Server) handleACLRecursion(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	// Widening recursion turns the server into an open resolver: admin-only,
	// like ACL rewrites.
	if r.Method == http.MethodPut {
		if s.requireAdmin(w, r) {
			return
		}
	} else if s.requireOperator(w, r) {
		return
	}

	s.runtimeMu.RLock()
	policy := s.recursionPolicy
	aclChecker := s.aclChecker
	s.runtimeMu.RUnlock()

	if r.Method == http.MethodGet {
		s.writeJSON(w, http.StatusOK, recursionPolicyResponse(policy))
		return
	}
	if policy == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Recursion policy not available")
		return
	}

	var req RecursionPolicyRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Networks == nil {
		s.writeError(w, http.StatusBadRequest, "networks is required (use [] to deny recursion to every client)")
		return
	}
	if _, _, err := filter.ParseRecursionNetworks(req.Networks); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
		return
	}

	s.accessPolicyMu.Lock()
	defer s.accessPolicyMu.Unlock()
	previousNetworks, previousAll := policy.Networks(), policy.AllowAll()
	if err := policy.Update(req.Networks); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
		return
	}
	if err := s.saveAccessPolicy(aclChecker); err != nil {
		_ = policy.Replace(previousNetworks, previousAll)
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save access policy"))
		return
	}
	s.writeJSON(w, http.StatusOK, recursionPolicyResponse(policy))
}

func recursionPolicyResponse(policy *filter.RecursionPolicy) *RecursionPolicyResponse {
	networks := policy.Networks()
	if networks == nil {
		networks = []string{}
	}
	return &RecursionPolicyResponse{AllowAll: policy.AllowAll(), Networks: networks}
}

func (s *Server) aclResponse(aclChecker *filter.ACLChecker) *ACLResponse {
	s.runtimeMu.RLock()
	policy := s.recursionPolicy
	file := s.accessPolicyFile
	s.runtimeMu.RUnlock()

	rules := aclChecker.GetRules()
	aclRules := make([]ACLRuleResponse, 0, len(rules))
	for _, rule := range rules {
		aclRules = append(aclRules, ACLRuleResponse{
			Name:     rule.Name,
			Networks: rule.Networks,
			Action:   rule.Action,
			Types:    rule.Types,
			Redirect: rule.Redirect,
		})
	}
	return &ACLResponse{
		Rules:          aclRules,
		AllowRecursion: *recursionPolicyResponse(policy),
		Persistent:     file != "",
		PolicyFile:     file,
	}
}

// saveAccessPolicy writes the current ACL and recursion allow list to the
// access policy file. Without a file (no storage.data_dir) changes stay in
// memory until the next restart or reload. Callers hold accessPolicyMu.
func (s *Server) saveAccessPolicy(aclChecker *filter.ACLChecker) error {
	s.runtimeMu.RLock()
	policy := s.recursionPolicy
	file := s.accessPolicyFile
	s.runtimeMu.RUnlock()
	if file == "" {
		return nil
	}
	stored := &filter.AccessPolicy{
		ACL:            filter.StoredRules(aclChecker.GetRules()),
		AllowRecursion: policy.Networks(),
	}
	if policy.AllowAll() {
		// The file stores explicit networks only; keep "everyone" expressible.
		stored.AllowRecursion = []string{"0.0.0.0/0", "::/0"}
	}
	return filter.SaveAccessPolicy(file, stored)
}

// handleRPZ returns RPZ statistics.
