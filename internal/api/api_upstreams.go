package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		var upstreams []UpstreamStatus
		if s.upstreamLB != nil {
			queries, failed, failovers := s.upstreamLB.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address:   "load-balancer",
				Healthy:   s.upstreamLB.IsHealthy(),
				Queries:   queries,
				Failed:    failed,
				Failovers: failovers,
			})
		}
		if s.upstreamClient != nil {
			queries, failed, _ := s.upstreamClient.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address: "direct-upstream",
				Healthy: s.upstreamClient.IsHealthy(),
				Queries: queries,
				Failed:  failed,
			})
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams})
	case http.MethodPut:
		if s.requireOperator(w, r) {
			return
		}
		// Update upstream configuration (add/remove servers)
		var req UpstreamUpdateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if s.upstreamClient == nil {
			s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
			return
		}

		switch req.Action {
		case "add":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			if err := s.upstreamClient.AddServer(req.Server); err != nil {
				s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server added: " + req.Server})

		case "remove":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			if err := s.upstreamClient.RemoveServer(req.Server); err != nil {
				s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server removed: " + req.Server})

		default:
			s.writeError(w, http.StatusBadRequest, "Invalid action: must be 'add' or 'remove'")
		}
	}
}

// handleACL returns ACL rules or updates them.
