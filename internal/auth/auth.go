package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/nothingdns/nothingdns/internal/util"
	"time"
)

// Role represents a user's RBAC role.
type Role string

const (
	RoleAdmin   Role = "admin"   // Full access
	RoleOperator Role = "operator" // Can modify zones, cache, config
	RoleViewer  Role = "viewer"  // Read-only access
)

// User represents a user account.
type User struct {
	Username  string   `json:"username"`
	Password  string   `json:"-"` // Never expose in JSON
	Hash      []byte   `json:"hash"` // Stored password hash
	Role      Role     `json:"role"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// Token represents an active authentication token.
type Token struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Store manages users and tokens.
type Store struct {
	mu      sync.RWMutex
	users   map[string]*User
	tokens  map[string]*Token
	secret  []byte // HMAC signing key
}

// Config holds auth store configuration.
type Config struct {
	Secret      string   `yaml:"secret"`        // HMAC signing key
	Users       []User   `yaml:"users"`         // Initial users
	TokenExpiry Duration `yaml:"token_expiry"` // Token TTL (default: 24h)
}

type Duration struct {
	time.Duration
}

// DefaultConfig returns a default auth configuration.
func DefaultConfig() *Config {
	return &Config{
		Secret:      generateSecret(32),
		TokenExpiry: Duration{24 * time.Hour},
	}
}

// NewStore creates a new auth store.
func NewStore(cfg *Config) *Store {
	var secret []byte
	if cfg.Secret == "" {
		// Generate a random secret and log it for first-run / dev environments.
		// This is cryptographically weak (secret is not persisted) but prevents
		// token forgery until a proper auth_secret is configured.
		generated := generateSecret(32)
		secret = []byte(generated)
		util.Warnf("AUTH: No auth_secret configured. Generated temporary secret for this run: %s. " +
			"Set auth_secret in config for production deployments.", generated)
	} else {
		secret = []byte(cfg.Secret)
	}

	s := &Store{
		users:  make(map[string]*User),
		tokens: make(map[string]*Token),
		secret: secret,
	}

	// Load initial users
	for _, u := range cfg.Users {
		u := u // capture range variable
		s.users[u.Username] = &u
	}

	// Add default admin user if no users configured
	// SECURITY: Generate a secure random password instead of using a known default
	if len(s.users) == 0 {
		defaultPassword, err := generateSecurePassword(24)
		if err != nil {
			// crypto/rand failure is extremely rare but would indicate system-level issues
			panic("auth: crypto/rand unavailable for password generation: " + err.Error())
		}
		s.users["admin"] = &User{
			Username:  "admin",
			Hash:      HashPassword(defaultPassword, nil),
			Role:      RoleAdmin,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		// Warn that default admin was created — password must be set via first login or config
		util.Warnf("No users configured. Default admin account created. Set password via dashboard or API before use.")
	}

	return s
}

// HashPassword hashes a password with a random salt.
// Returns the hash that can be stored and later verified.
func HashPassword(password string, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, 16)
		rand.Read(salt)
	}

	// PBKDF2-like key derivation using SHA256
	key := make([]byte, 32)
	h := sha256.New()

	// First iteration: password + salt
	h.Write([]byte(password))
	h.Write(salt)
	copy(key, h.Sum(nil))

	// Multiple iterations for computational cost
	for i := 1; i < 10000; i++ {
		h.Reset()
		h.Write(key)
		h.Write(salt)
		copy(key, h.Sum(nil))
	}

	// Prepend salt to hash
	result := make([]byte, len(salt)+len(key))
	copy(result, salt)
	copy(result[len(salt):], key)
	return result
}

// generateSecurePassword generates a cryptographically secure random password.
func generateSecurePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	charsetLen := len(charset) // 70

	bytes := make([]byte, length)
	for i := range bytes {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			// Rejection sampling: only use bytes < (256/charsetLen)*charsetLen
			// to avoid modulo bias. charsetLen=70, 256/70=3, 3*70=210
			if int(b[0]) < 210 {
				bytes[i] = charset[int(b[0])%charsetLen]
				break
			}
		}
	}

	return string(bytes), nil
}

// VerifyPassword checks if a password matches a stored hash.
func VerifyPassword(password string, hash []byte) bool {
	if len(hash) < 16 {
		return false
	}
	salt := hash[:16]
	expected := HashPassword(password, salt)
	return subtle.ConstantTimeCompare(hash, expected) == 1
}

// GenerateToken creates a new authentication token for a user.
func (s *Store) GenerateToken(username string, expiry time.Duration) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	now := time.Now()
	t := &Token{
		Token:     token,
		Username:  username,
		Role:      user.Role,
		ExpiresAt: now.Add(expiry),
		CreatedAt: now,
	}

	s.tokens[token] = t
	return t, nil
}

// ValidateToken checks if a token is valid and returns the associated user.
func (s *Store) ValidateToken(tokenStr string) (*User, error) {
	s.mu.RLock()
	token, ok := s.tokens[tokenStr]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("invalid token")
	}

	if time.Now().After(token.ExpiresAt) {
		s.mu.RUnlock()
		s.mu.Lock()
		delete(s.tokens, tokenStr)
		s.mu.Unlock()
		return nil, fmt.Errorf("token expired")
	}

	user, ok := s.users[token.Username]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// RevokeToken invalidates a token.
func (s *Store) RevokeToken(tokenStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenStr)
}

// RevokeAllTokens revokes all tokens for a user.
func (s *Store) RevokeAllTokens(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, t := range s.tokens {
		if t.Username == username {
			delete(s.tokens, token)
		}
	}
}

// CreateUser creates a new user.
func (s *Store) CreateUser(username, password string, role Role) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return nil, fmt.Errorf("user already exists")
	}

	hash := HashPassword(password, nil)
	now := time.Now().UTC().Format(time.RFC3339)
	user := &User{
		Username:  username,
		Hash:     hash,
		Role:     role,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.users[username] = user
	return user, nil
}

// UpdateUser updates an existing user's password or role.
func (s *Store) UpdateUser(username, password string, role Role) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	if password != "" {
		user.Hash = HashPassword(password, nil)
	}
	if role != "" {
		user.Role = role
	}
	user.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Revoke all tokens for this user (password changed)
	for token, t := range s.tokens {
		if t.Username == username {
			delete(s.tokens, token)
		}
	}

	return user, nil
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[username]; !ok {
		return fmt.Errorf("user not found")
	}
	delete(s.users, username)

	// Revoke all tokens for this user
	for token, t := range s.tokens {
		if t.Username == username {
			delete(s.tokens, token)
		}
	}
	return nil
}

// ListUsers returns all users (without passwords).
func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, &User{
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		})
	}
	return users
}

// GetUser returns a user by username (without password hash).
func (s *Store) GetUser(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return &User{
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

// VerifyUserPassword checks username + password against stored credentials.
func (s *Store) VerifyUserPassword(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return false
	}
	return VerifyPassword(password, user.Hash)
}

// Save persists users to a file.
func (s *Store) Save(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load reads users from a file.
func (s *Store) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var users map[string]*User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = users
	return nil
}

// HasRole checks if a user has at least the specified role.
func (s *Store) HasRole(username string, required Role) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return false
	}

	// Admin > Operator > Viewer
	roleOrder := map[Role]int{
		RoleViewer:  1,
		RoleOperator: 2,
		RoleAdmin:   3,
	}

	return roleOrder[user.Role] >= roleOrder[required]
}

// generateSecret generates a random secret for HMAC signing.
func generateSecret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// SignToken creates an HMAC signature for a token.
func SignToken(token string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(token))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// VerifyTokenSignature verifies an HMAC signature.
func VerifyTokenSignature(token, sig string, secret []byte) bool {
	expected := SignToken(token, secret)
	return hmac.Equal([]byte(expected), []byte(sig))
}
