package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/auth"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}

	authStore := s.currentAuthStore()
	if authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	// Check IP-based rate limit
	ip := s.clientIP(r)
	if rejected, delay := s.loginLimiter.checkRateLimit(ip); rejected {
		w.Header().Set("Retry-After", retryAfterSeconds(delay))
		s.writeError(w, http.StatusTooManyRequests, "Too many requests, try again later")
		return
	}

	var req LoginRequest
	if !s.decode(w, r, &req) {
		return
	}

	// Check account-based rate limit (username lockout) — keyed by (IP, username) pair
	if rejected, delay := s.loginLimiter.checkUserRateLimit(ip, req.Username); rejected {
		w.Header().Set("Retry-After", retryAfterSeconds(delay))
		s.writeError(w, http.StatusTooManyRequests, "Account locked due to too many failed attempts")
		return
	}

	// Validate user credentials
	if !authStore.VerifyUserPassword(req.Username, req.Password) {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Get user for role and token generation
	user, err := authStore.GetUser(req.Username)
	if err != nil {
		s.loginLimiter.recordFailedAttempt(ip, req.Username)
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Successful login - clear rate limit state
	s.loginLimiter.recordSuccess(ip, req.Username)

	// Revoke all existing tokens to prevent session fixation
	authStore.RevokeAllTokens(req.Username)

	// Generate token
	tokenExpiry := authStore.TokenExpiry()
	token, err := authStore.GenerateToken(req.Username, tokenExpiry)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	// SECURITY (LOW-018): Secure flag is set for direct TLS or when a trusted
	// proxy forwarded X-Forwarded-Proto: https (see isRequestSecure).
	// Plaintext deployments transmit cookies unencrypted. Deploy behind TLS
	// or a TLS-terminating reverse proxy for production.
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isRequestSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieMaxAgeSeconds(tokenExpiry),
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
// SECURITY (LOW-009): Restricted to localhost. Defense-in-depth: require a
// bootstrap token from file or environment variable for production deployments.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}

	// Serialize bootstrap to prevent TOCTOU race between ListUsers and CreateUser
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()

	// Get client IP for localhost check — inside lock to ensure atomic check
	ip := s.clientIP(r)
	isLocalhost := ip == "127.0.0.1" || ip == "::1"

	authStore := s.currentAuthStore()
	if authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}

	users := authStore.ListUsers()

	// Bootstrap must ALWAYS be from localhost to prevent remote attacker from creating admin accounts.
	// If users exist: only localhost can perform bootstrap (for password reset).
	// If no users exist: only localhost can perform first-time setup.
	// This prevents a remote attacker from creating an admin account when the system is first deployed.
	if !isLocalhost {
		s.writeError(w, http.StatusForbidden, "Bootstrap is only allowed from localhost. Please access this server directly on the server host.")
		return
	}

	var req BootstrapRequest
	if !s.decode(w, r, &req) {
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

	// Special case: the only existing user is the auto-created default
	// admin (random unknowable password). The bootstrap warning at startup
	// promises an admin can be set "via the dashboard or API," but the
	// usual password-reset flow demands OldPassword, which by construction
	// no one knows. Detect this state and let localhost take over without
	// the impossible OldPassword check. The localhost gate above is
	// already the strong authority for this path.
	if len(users) == 1 && users[0].Username == "admin" && users[0].IsAutoCreated {
		// Remove the synthetic admin and create the operator's chosen
		// account fresh. Using CreateUser (not UpdateUser) means the
		// new account loses the IsAutoCreated marker and behaves like
		// any normally-provisioned user from here on out.
		if err := authStore.DeleteUser("admin"); err != nil {
			s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to remove default admin"))
			return
		}
		user, err = authStore.CreateUser(req.Username, req.Password, auth.RoleAdmin)
		if err != nil {
			s.writeError(w, userWriteErrorStatus(err), sanitizeError(err, "Operation failed"))
			return
		}
	} else if len(users) > 0 {
		// Users exist (from localhost) - require old password for password reset
		if req.OldPassword == "" {
			s.writeError(w, http.StatusBadRequest, "Old password required")
			return
		}
		if !authStore.VerifyUserPassword(req.Username, req.OldPassword) {
			s.writeError(w, http.StatusUnauthorized, "Invalid old password")
			return
		}
		user, err = authStore.UpdateUser(req.Username, req.Password, "")
		if err != nil {
			s.writeError(w, userWriteErrorStatus(err), sanitizeError(err, "Operation failed"))
			return
		}
	} else {
		// No users - create the first admin user
		user, err = authStore.CreateUser(req.Username, req.Password, auth.RoleAdmin)
		if err != nil {
			s.writeError(w, userWriteErrorStatus(err), sanitizeError(err, "Operation failed"))
			return
		}
	}

	// Generate token
	tokenExpiry := authStore.TokenExpiry()
	token, err := authStore.GenerateToken(req.Username, tokenExpiry)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	// SECURITY (LOW-018): Secure flag is set for direct TLS or when a trusted
	// proxy forwarded X-Forwarded-Proto: https (see isRequestSecure).
	// Plaintext deployments transmit cookies unencrypted. Deploy behind TLS
	// or a TLS-terminating reverse proxy for production.
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    token.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isRequestSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieMaxAgeSeconds(tokenExpiry),
	})

	s.writeJSON(w, http.StatusOK, &BootstrapResponse{
		Token:    token.Token,
		Username: user.Username,
		Role:     string(user.Role),
	})
}

// handleLogout invalidates the current token.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
		return
	}

	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	authStore := s.currentAuthStore()
	if token != "" && authStore != nil {
		authStore.RevokeToken(token)
	}

	// Also revoke cookie token
	if cookie, err := r.Cookie("ndns_token"); err == nil && cookie.Value != "" && authStore != nil {
		authStore.RevokeToken(cookie.Value)
	}

	// Clear cookie — Secure must match original so browser can actually delete it
	http.SetCookie(w, &http.Cookie{
		Name:     "ndns_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isRequestSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Logged out"})
}

// handleUsers manages users.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	authStore := s.currentAuthStore()
	if authStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Auth not configured")
		return
	}
	if userPathParameter(r) && r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !hasRole(r.Context(), authStore, auth.RoleOperator) {
			s.writeError(w, http.StatusForbidden, "Operator role required")
			return
		}
		users := authStore.ListUsers()
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
		if !hasRole(r.Context(), authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		var req CreateUserRequest
		if !s.decode(w, r, &req) {
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
				// SECURITY: req.Role must not exceed caller's own privilege level.
				// hasRole already confirmed caller is Admin; compare privilege levels.
				caller := GetUser(r.Context())
				if caller != nil && roleOrder[auth.Role(req.Role)] > roleOrder[caller.Role] {
					s.writeError(w, http.StatusForbidden, "Cannot assign a role higher than your own")
					return
				}
				role = auth.Role(req.Role)
			default:
				s.writeError(w, http.StatusBadRequest, "Invalid role")
				return
			}
		}

		user, err := authStore.CreateUser(req.Username, req.Password, role)
		if err != nil {
			s.writeError(w, userWriteErrorStatus(err), sanitizeError(err, "Operation failed"))
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
		if !hasRole(r.Context(), authStore, auth.RoleAdmin) {
			s.writeError(w, http.StatusForbidden, "Admin role required")
			return
		}

		username := userDeleteName(r)
		if username == "" {
			s.writeError(w, http.StatusBadRequest, "username required")
			return
		}
		caller := GetUser(r.Context())
		if caller != nil && username == caller.Username {
			s.writeError(w, http.StatusBadRequest, "Cannot delete current user")
			return
		}
		if err := authStore.DeleteUserPreservingLastAdmin(username); errors.Is(err, auth.ErrLastAdmin) {
			s.writeError(w, http.StatusBadRequest, "Cannot delete the last admin user")
			return
		} else if err != nil {
			s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
			return
		}

		s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "User deleted"})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func userDeleteName(r *http.Request) string {
	if username := r.URL.Query().Get("username"); username != "" {
		return username
	}
	path, ok := userPathParameterValue(r)
	if !ok || strings.Contains(path, "/") {
		return ""
	}
	username, err := url.PathUnescape(path)
	if err != nil {
		return ""
	}
	return username
}

func userPathParameter(r *http.Request) bool {
	_, ok := userPathParameterValue(r)
	return ok
}

func userPathParameterValue(r *http.Request) (string, bool) {
	escapedPath := r.URL.EscapedPath()
	path := strings.TrimPrefix(escapedPath, "/api/v1/auth/users/")
	if path == escapedPath || path == "" {
		return "", false
	}
	return path, true
}

// handleRoles returns available roles.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	s.writeJSON(w, http.StatusOK, &RolesResponse{
		Roles: []RoleResponse{
			{Name: "admin", Description: "Full access to all resources"},
			{Name: "operator", Description: "Can modify zones and view operational data"},
			{Name: "viewer", Description: "Read-only access"},
		},
	})
}

// hasRole checks if the current user has at least the required role.

// userWriteErrorStatus maps auth store errors from creating or updating a
// user to an HTTP status: 409 for a taken username or a last-admin conflict,
// 404 for an unknown user, 400 for input that fails validation (for example
// a password shorter than 8 characters).
func userWriteErrorStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrLastAdmin):
		return http.StatusConflict
	case strings.Contains(err.Error(), "user not found"):
		return http.StatusNotFound
	case strings.HasPrefix(err.Error(), "hashing password"):
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}
