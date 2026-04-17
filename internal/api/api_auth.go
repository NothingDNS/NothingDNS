package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	// Check IP-based rate limit
	ip := getClientIP(r)
	if rejected, delay := s.loginLimiter.checkRateLimit(ip); rejected {
		w.Header().Set("Retry-After", strconv.Itoa(int(delay.Seconds())))
		s.writeError(w, http.StatusTooManyRequests, "Too many requests, try again later")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check account-based rate limit (username lockout)
	if rejected, delay := s.loginLimiter.checkUserRateLimit(req.Username); rejected {
		w.Header().Set("Retry-After", strconv.Itoa(int(delay.Seconds())))
		s.writeError(w, http.StatusTooManyRequests, "Account locked due to too many failed attempts")
		return
	}

	// Validate user credentials
	if !s.authStore.VerifyUserPassword(req.Username, req.Password) {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Get user for role and token generation
	user, err := s.authStore.GetUser(req.Username)
	if err != nil {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Successful login - clear rate limit state
	s.loginLimiter.recordSuccess(ip, req.Username)

	// Revoke all existing tokens to prevent session fixation
	s.authStore.RevokeAllTokens(req.Username)

	// Generate token
	token, err := s.authStore.GenerateToken(req.Username, s.authStore.TokenExpiry())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.authStore.TokenExpiry().Seconds()),
	})

	s.writeJSON(w, http.StatusOK, &LoginResponse{
		Token:    token.Token,
		Username: user.Username,
		Role:     string(user.Role),
		Expires:  token.ExpiresAt.Format(time.RFC3339),
	})
}

// handleBootstrap creates the first admin user when no users exist.
// This endpoint allows initial setup without pre-configured credentials.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Serialize bootstrap to prevent TOCTOU race between ListUsers and CreateUser
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()

	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	// Get client IP for localhost check
	ip := getClientIP(r)
	isLocalhost := ip == "127.0.0.1" || ip == "::1"

	users := s.authStore.ListUsers()

	// Bootstrap must ALWAYS be from localhost to prevent remote attacker from creating admin accounts.
	// If users exist: only localhost can perform bootstrap (for password reset).
	// If no users exist: only localhost can perform first-time setup.
	// This prevents a remote attacker from creating an admin account when the system is first deployed.
	if !isLocalhost {
		s.writeError(w, http.StatusForbidden, "Bootstrap is only allowed from localhost. Please access this server directly on the server host.")
		return
	}

	var req BootstrapRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password required")
		return
	}

	if len(req.Username) < 2 || len(req.Username) > 64 {
		s.writeError(w, http.StatusBadRequest, "Username must be 2-64 characters")
		return
	}

	if len(req.Password) < 8 {
		s.writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}
	if len(req.Password) > auth.MaxPasswordBytes {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Password must be at most %d bytes", auth.MaxPasswordBytes))
		return
	}

	var user *auth.User
	var err error

	if len(users) > 0 {
		// Users exist (from localhost) - require old password for password reset
		if req.OldPassword == "" {
			s.writeError(w, http.StatusBadRequest, "Old password required")
			return
		}
		if !s.authStore.VerifyUserPassword(req.Username, req.OldPassword) {
			s.writeError(w, http.StatusUnauthorized, "Invalid old password")
			return
		}
		user, err = s.authStore.UpdateUser(req.Username, req.Password, "")
		if err != nil {
			s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
			return
		}
	} else {
		// No users - create the first admin user
		user, err = s.authStore.CreateUser(req.Username, req.Password, auth.RoleAdmin)
		if err != nil {
			s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
			return
		}
	}

	// Generate token
	token, err := s.authStore.GenerateToken(req.Username, s.authStore.TokenExpiry())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.authStore.TokenExpiry().Seconds()),
	})

	s.writeJSON(w, http.StatusOK, &BootstrapResponse{
		Token:    token.Token,
		Username: user.Username,
		Role:     string(user.Role),
	})
}

// handleLogout invalidates the current token.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	if token != "" && s.authStore != nil {
		s.authStore.RevokeToken(token)
	}

	// Also revoke cookie token
	if cookie, err := r.Cookie("ndns_token"); err == nil && cookie.Value != "" && s.authStore != nil {
		s.authStore.RevokeToken(cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Logged out"})
}

// handleUsers manages users.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !hasRole(r.Context(), s.authStore, auth.RoleOperator) {
			s.writeError(w, http.StatusForbidden, "Operator role required")
			return
		}
		users := s.authStore.ListUsers()
		resp := make([]UserResponse, 0, len(users))
		for _, u := range users {
			resp = append(resp, UserResponse{
				Username: u.Username,
				Role:     string(u.Role),
				Created:  u.CreatedAt,
				Updated:  u.UpdatedAt,
			})
		}
		s.writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		// Require admin role
		if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		var req CreateUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			s.writeError(w, http.StatusBadRequest, "Username and password required")
			return
		}

		role := auth.RoleViewer
		if req.Role != "" {
			switch auth.Role(req.Role) {
			case auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin:
				role = auth.Role(req.Role)
			default:
				s.writeError(w, http.StatusBadRequest, "Invalid role")
				return
			}
		}

		user, err := s.authStore.CreateUser(req.Username, req.Password, role)
		if err != nil {
			s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
			return
		}

		s.writeJSON(w, http.StatusCreated, &UserResponse{
			Username: user.Username,
			Role:     string(user.Role),
			Created:  user.CreatedAt,
			Updated:  user.UpdatedAt,
		})

	case http.MethodDelete:
		// Require admin role
		if !hasRole(r.Context(), s.authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			s.writeError(w, http.StatusBadRequest, "username required")
			return
		}

		if err := s.authStore.DeleteUser(username); err != nil {
			s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
			return
		}

		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "User deleted"})
	}
}

// handleRoles returns available roles.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, &RolesResponse{
		Roles: []RoleResponse{
			{Name: "admin", Description: "Full access to all resources"},
			{Name: "operator", Description: "Can modify zones, cache, and config"},
			{Name: "viewer", Description: "Read-only access"},
		},
	})
}

// hasRole checks if the current user has at least the required role.
