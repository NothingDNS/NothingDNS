package nothingdns

import (
	"context"
)

// Roles a user account can hold, ordered viewer < operator < admin. The server
// enforces this hierarchy on every non-"any" operation.
var Roles = []string{"viewer", "operator", "admin"}

// IsValidRole reports whether role is one of "viewer", "operator" or "admin".
func IsValidRole(role string) bool {
	for _, r := range Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AuthService handles authentication, user accounts and roles
// (the /api/v1/auth endpoints). Credential *acquisition* — turning a username
// and password into a bearer token — lives here; credential *transmission* is
// handled by the shared Transport, which sets the Authorization header. That
// split keeps the login/bootstrap password payloads and the bearer header in
// separate files.
type AuthService struct {
	t *Transport
}

// loginRequest is the JSON body of POST /api/v1/auth/login. Both fields are
// required by the server.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// bootstrapRequest is the JSON body of POST /api/v1/auth/bootstrap. Username
// and Password are required; OldPassword is only needed when resetting an
// existing account.
type bootstrapRequest struct {
	Username    string  `json:"username"`
	Password    string  `json:"password"`
	OldPassword *string `json:"old_password,omitempty"`
}

// createUserRequest is the JSON body of POST /api/v1/auth/users.
type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// Login logs in and receives a bearer token.
//
// username and password are the account credentials. The returned token is
// stored on the client, so subsequent calls are authenticated automatically;
// pass storeToken=false to keep the client anonymous and use the Session
// manually.
//
// It returns the Session (token, username, role, expiry).
//
// It fails with an *ErrAPIError carrying status 400 for a malformed request,
// 401 for bad credentials, or 429 when the login rate limit is hit.
func (a *AuthService) Login(ctx context.Context, username, password string, storeToken bool) (*Session, error) {
	var session Session
	body := loginRequest{Username: username, Password: password}
	if err := a.t.doJSON(ctx, "POST", "/api/v1/auth/login", nil, body, &session); err != nil {
		return nil, err
	}
	if storeToken && session.Token != "" {
		a.t.SetToken(session.Token)
	}
	return &session, nil
}

// Bootstrap creates the first admin account, or resets an existing account's
// password.
//
// Use it to provision the very first admin on a fresh server, or to recover
// access when the current password is known. username and password are the new
// (or first) admin credentials. oldPassword is the current password of the
// account being reset; it is required when resetting an existing account that
// is not the initial bootstrap and may be nil otherwise.
//
// It fails with an *ErrAPIError carrying status 401 when oldPassword is
// wrong, 403 when the change is not permitted for this caller, or 409 when the
// server already has an admin and no oldPassword was given.
func (a *AuthService) Bootstrap(ctx context.Context, username, password string, oldPassword *string, storeToken bool) (*Session, error) {
	var session Session
	body := bootstrapRequest{Username: username, Password: password, OldPassword: oldPassword}
	if err := a.t.doJSON(ctx, "POST", "/api/v1/auth/bootstrap", nil, body, &session); err != nil {
		return nil, err
	}
	if storeToken && session.Token != "" {
		a.t.SetToken(session.Token)
	}
	return &session, nil
}

// Session returns the current session: token, username and role.
//
// This mirrors the dashboard restoring its in-memory bearer after a page
// reload without persisting the token. The server rejects the legacy shared
// auth_token for this call — a real login session is required.
func (a *AuthService) Session(ctx context.Context) (*Session, error) {
	var session Session
	if err := a.t.doJSON(ctx, "GET", "/api/v1/auth/session", nil, nil, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// Logout invalidates the current session and returns the server's message.
func (a *AuthService) Logout(ctx context.Context) (string, error) {
	return a.t.doMessage(ctx, "POST", "/api/v1/auth/logout", nil, nil)
}

// Roles lists the roles the server knows about. It requires the operator role
// or higher.
//
// The returned order mirrors the server's own listing.
func (a *AuthService) Roles(ctx context.Context) ([]Role, error) {
	var out struct {
		Roles []Role `json:"roles"`
	}
	if err := a.t.doJSON(ctx, "GET", "/api/v1/auth/roles", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Roles, nil
}

// ListUsers lists every user account. It requires the operator role or
// higher. Passwords are never returned by the API.
func (a *AuthService) ListUsers(ctx context.Context) ([]User, error) {
	var users []User
	if err := a.t.doJSON(ctx, "GET", "/api/v1/auth/users", nil, nil, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// CreateUser creates a user account. It requires the admin role.
//
// username is the new, unique account name; password is its password; role is
// "viewer" (read-only), "operator" (zones, cache, config reads) or "admin"
// (everything, including users and runtime config changes). It returns the
// created account.
//
// It fails with an *ErrAPIError carrying status 409 when the username already
// exists, or an *ErrValidationError when role is not a known role.
func (a *AuthService) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	if !IsValidRole(role) {
		return nil, &ErrValidationError{Message: "role must be one of viewer, operator, admin"}
	}
	var user User
	body := createUserRequest{Username: username, Password: password, Role: role}
	if err := a.t.doJSON(ctx, "POST", "/api/v1/auth/users", nil, body, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// DeleteUser deletes a user account by name (admin only), using the path
// form DELETE /api/v1/auth/users/{username}. It returns the server's
// confirmation message.
func (a *AuthService) DeleteUser(ctx context.Context, username string) (string, error) {
	return a.t.doMessage(ctx, "DELETE", "/api/v1/auth/users/"+a.t.escape(username), nil, nil)
}

// DeleteUserByQuery deletes a user account by name (admin only), using the
// query form DELETE /api/v1/auth/users?username=… . It is the same operation
// as DeleteUser expressed with a query parameter; use whichever the server or
// proxy in front of it prefers. It returns the server's confirmation message.
func (a *AuthService) DeleteUserByQuery(ctx context.Context, username string) (string, error) {
	return a.t.doMessage(ctx, "DELETE", "/api/v1/auth/users", map[string]any{"username": username}, nil)
}
