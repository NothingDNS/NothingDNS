package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Role represents a user's RBAC role.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access
	RoleOperator Role = "operator" // Can modify zones and view operational data
	RoleViewer   Role = "viewer"   // Read-only access
)

var ErrLastAdmin = errors.New("cannot delete the last admin user")

// ErrUserExists is returned by CreateUser when the username is taken.
var ErrUserExists = errors.New("user already exists")

const maxAuthPersistFileSize = 16 << 20

// User represents a user account.
type User struct {
	Username string `json:"username"`
	Password string `json:"-"` // Never expose in JSON
	// Hash uses lowercase JSON for on-disk persistence (Save/Load
	// round-trip the users.json file) but it must never reach an
	// API response. The api/response.UserResponse type intentionally
	// omits this field; any future endpoint that marshals *auth.User
	// directly via writeJSON would leak the PBKDF2 digest plus salt
	// to clients. Until that defense is encoded at the type level
	// (e.g. a separate UserOnDisk struct), the json tag stays
	// lowercase and reviewers must catch direct *auth.User
	// serialization at PR time.
	Hash      []byte `json:"hash,omitempty"`
	Role      Role   `json:"role"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// IsAutoCreated is true for the synthetic default-admin that the
	// auth store creates when no users are configured. Bootstrap from
	// localhost is allowed to replace such accounts without supplying
	// the (unknowable, randomly-generated) old password — otherwise the
	// daemon ships in a permanently unbootstrappable state.
	IsAutoCreated bool `json:"is_auto_created,omitempty"`

	// configured marks users defined in the server config. The config stays
	// their source of truth, so they are never written to the users file.
	configured bool
}

// Token represents an active authentication token.
// SECURITY (LOW-015): Role is cached at generation time for serialization only.
// Authorization always uses the live user store role via ValidateToken.
type Token struct {
	Token      string    `json:"token"`
	Signature  string    `json:"signature"` // HMAC signature for verification
	Username   string    `json:"username"`
	Role       Role      `json:"role"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_access"` // For session activity tracking
}

// Store manages users and tokens.
type Store struct {
	mu     sync.RWMutex
	users  map[string]*User
	tokens map[string]*Token
	// MaxSessionsPerUser limits concurrent sessions per user (0 = unlimited).
	// When a new login would exceed the limit, the oldest session is revoked.
	maxSessionsPerUser int
	activeSessions     map[string]int // username → count of active tokens
	// SECURITY (LOW-019/020): Secret strength depends on operator choice.
	// No minimum entropy enforcement or key rotation support. Operators must
	// generate strong secrets (≥32 bytes from crypto/rand) and rotate them
	// manually by revoking all tokens and restarting with a new secret.
	secret        []byte        // HMAC signing key
	tokenFilePath string        // Path to persist tokens (optional)
	usersFilePath string        // Path to persist runtime-managed users (optional)
	tokenExpiry   time.Duration // TTL for newly-issued tokens (VULN-032)
}

// TokenExpiry returns the configured TTL for newly-issued tokens.
func (s *Store) TokenExpiry() time.Duration {
	return s.tokenExpiry
}

// Config holds auth store configuration.
type Config struct {
	Secret             string   `yaml:"secret"`                // HMAC signing key
	Users              []User   `yaml:"users"`                 // Initial users
	TokenExpiry        Duration `yaml:"token_expiry"`          // Token TTL (default: 24h)
	MaxSessionsPerUser int      `yaml:"max_sessions_per_user"` // Max concurrent sessions per user (0 = unlimited)
}

type Duration struct {
	time.Duration
}

// DefaultConfig returns a default auth configuration.
func DefaultConfig() (*Config, error) {
	secret, err := generateSecret(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth secret: %w", err)
	}
	return &Config{
		Secret:      secret,
		TokenExpiry: Duration{24 * time.Hour},
	}, nil
}

// NewStore creates a new auth store.
func NewStore(cfg *Config) (*Store, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is required")
	}

	var secret []byte
	if cfg.Secret == "" {
		// Generate a random secret for this run. This is cryptographically weak
		// (secret is not persisted) but prevents token forgery until a proper
		// auth_secret is configured. Tokens will be invalidated on server restart.
		generated, err := generateSecret(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate auth secret: %w", err)
		}
		secret = []byte(generated)
		util.Warnf("AUTH: No auth_secret configured. Generated temporary secret for this run. " +
			"Set auth_secret in config for production deployments to ensure token persistence across restarts.")
	} else {
		secret = []byte(cfg.Secret)
	}
	if cfg.MaxSessionsPerUser < 0 {
		return nil, fmt.Errorf("max_sessions_per_user cannot be negative")
	}

	s := &Store{
		users:              make(map[string]*User),
		tokens:             make(map[string]*Token),
		secret:             secret,
		tokenExpiry:        cfg.TokenExpiry.Duration,
		maxSessionsPerUser: cfg.MaxSessionsPerUser,
		activeSessions:     make(map[string]int),
	}
	if s.tokenExpiry <= 0 {
		s.tokenExpiry = 24 * time.Hour
	}

	// Load initial users
	seenUsers := make(map[string]struct{}, len(cfg.Users))
	for _, u := range cfg.Users {
		u := u // capture range variable
		if err := ValidateUsername(u.Username); err != nil {
			return nil, fmt.Errorf("invalid configured user %q: %w", u.Username, err)
		}
		if err := ValidateRole(u.Role); err != nil {
			return nil, fmt.Errorf("invalid configured role for user %q: %w", u.Username, err)
		}
		if _, exists := seenUsers[u.Username]; exists {
			return nil, fmt.Errorf("duplicate configured user %q", u.Username)
		}
		seenUsers[u.Username] = struct{}{}
		if u.Password == "" && len(u.Hash) == 0 {
			return nil, fmt.Errorf("configured user %q must have password or hash", u.Username)
		}
		// Hash plaintext password if present and zero it from memory
		if u.Password != "" && len(u.Hash) == 0 {
			if err := ValidatePassword(u.Password); err != nil {
				return nil, fmt.Errorf("invalid password for configured user %q: %w", u.Username, err)
			}
			hash, err := HashPasswordWithError(u.Password, nil)
			if err != nil {
				return nil, fmt.Errorf("hashing password for user %q: %w", u.Username, err)
			}
			u.Hash = hash
			u.Password = strings.Repeat("\x00", len(u.Password))
		}
		u.configured = true
		s.users[u.Username] = &u
	}

	// Add default admin user if no users configured
	// SECURITY: Generate a secure random password instead of using a known default
	if len(s.users) == 0 {
		defaultPassword, err := generateSecurePassword(24)
		if err != nil {
			return nil, fmt.Errorf("auth: crypto/rand unavailable for password generation: %w", err)
		}
		hash, err := HashPasswordWithError(defaultPassword, nil)
		if err != nil {
			return nil, fmt.Errorf("hashing default admin password: %w", err)
		}
		s.users["admin"] = &User{
			Username:      "admin",
			Hash:          hash,
			Role:          RoleAdmin,
			CreatedAt:     time.Now().UTC().Format(time.RFC3339),
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
			IsAutoCreated: true,
		}
		// SECURITY (LOW-012): The generated password is NEVER logged. It exists only
		// in memory during this function. Operators must use the localhost-only
		// bootstrap endpoint or config reload to set a known password. The
		// caller warns via UsesAutoCreatedAdmin once runtime users are loaded:
		// a users file usually replaces this placeholder.
	}

	return s, nil
}

// HashPassword hashes a password with a random salt using PBKDF2-HMAC-SHA512.
// Uses crypto/pbkdf2 for a standard, audited implementation (MED-001).
// Parameters: 310,000 iterations (OWASP 2023 recommendation for SHA-512), 64-byte output.
// Returns the hash that can be stored and later verified.
func HashPassword(password string, salt []byte) []byte {
	hash, err := HashPasswordWithError(password, salt)
	if err != nil {
		util.Errorf("auth: password hashing failed: %v", err)
		return nil
	}
	return hash
}

// HashPasswordWithError hashes a password and reports entropy/KDF failures to
// callers that can surface startup or request errors instead of panicking.
func HashPasswordWithError(password string, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 32) // 256-bit salt
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate password salt: %w", err)
		}
	}

	// PBKDF2-HMAC-SHA512 with iterations chosen for balance of security and performance.
	// OWASP 2023 recommends 310,000 iterations for SHA-512 at 128-bit security.
	// See: https://owasp.org/www-project-web-security-testing-guide/
	iterations := 310000
	keyLen := 64

	key, err := pbkdf2.Key(sha512.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive password key: %w", err)
	}

	// Prepend salt to hash (salt bytes | key bytes)
	hash := make([]byte, len(salt)+len(key))
	copy(hash, salt)
	copy(hash[len(salt):], key)
	return hash, nil
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
// Timing-safe: all code paths pay the same PBKDF2 cost and the final
// constant-time comparison always operates on equal-length buffers,
// eliminating the timing side-channel from the old length-check-then-
// constant-time-compare pattern (VULN-076).
func VerifyPassword(password string, hash []byte) bool {
	// Max output length = 32-byte salt + 64-byte PBKDF2 key = 96 bytes.
	const maxLen = 96

	// Determine salt length from hash length.
	// New format: 32-byte salt + 64-byte key = 96 bytes total
	// Legacy format: 16-byte salt + 32-byte key = 48 bytes total
	saltLen := 32
	if len(hash) == 48 {
		saltLen = 16
	}

	// Extract salt — if hash is shorter than saltLen, copy what we have;
	// zeros fill the remainder. The copied bytes are only used for KDF,
	// not for the comparison, so zero-filling is safe.
	salt := make([]byte, saltLen)
	copy(salt, hash) // zeros pad any remaining bytes if hash is shorter

	// Always run PBKDF2 so every code path pays the same crypto cost.
	// This closes the timing side-channel where a very-short hash would
	// return before the expensive KDF (VULN-076).
	expected, err := HashPasswordWithError(password, salt)
	if err != nil {
		return false
	}

	// Constant-time comparison of equal-length (maxLen) buffers.
	// Zero-pad both hash and expected to maxLen so that:
	//   - old 48-byte hashes are padded to 96 bytes (zero-fill)
	//   - old 96-byte hashes compare directly
	//   - new 96-byte hashes compare directly
	// No secret-dependent branching or early returns occur.
	var bufHash, bufExpected [maxLen]byte
	copy(bufHash[:], hash)
	copy(bufExpected[:], expected)
	return subtle.ConstantTimeCompare(bufHash[:], bufExpected[:]) == 1
}

// GenerateToken creates a new authentication token for a user.
// When MaxSessionsPerUser > 0 and the user has reached their session limit,
// the oldest session is revoked before issuing the new one.
func (s *Store) GenerateToken(username string, expiry time.Duration) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	// Enforce session limit: revoke oldest token if at capacity. When
	// we evict, decrement the counter first — the unconditional
	// increment below otherwise drives \`activeSessions[username]\`
	// past maxSessionsPerUser (active=5 + evict + ++ → 6) and the
	// counter drifts upward by 1 on every eviction-triggered login.
	// After enough churn the apparent count exceeds the actual token
	// population, which manifests as users being unable to log in
	// even though their sessions are well under the cap.
	if s.maxSessionsPerUser > 0 {
		if count := s.activeSessions[username]; count >= s.maxSessionsPerUser {
			oldestToken := ""
			oldestTime := time.Time{}
			for tok, t := range s.tokens {
				if t.Username == username && (oldestTime.IsZero() || t.CreatedAt.Before(oldestTime)) {
					oldestTime = t.CreatedAt
					oldestToken = tok
				}
			}
			if oldestToken != "" {
				delete(s.tokens, oldestToken)
				if s.activeSessions[username] > 0 {
					s.activeSessions[username]--
				}
			}
		}
		s.activeSessions[username]++
	}

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Sign the token with HMAC-SHA256
	signature := s.signToken(token)

	now := time.Now()
	t := &Token{
		Token:      token,
		Signature:  signature,
		Username:   username,
		Role:       user.Role,
		ExpiresAt:  now.Add(expiry),
		CreatedAt:  now,
		LastAccess: now,
	}

	s.tokens[token] = t
	return t, nil
}

// signToken creates an HMAC-SHA512 signature for a token.
func (s *Store) signToken(token string) string {
	h := hmac.New(sha512.New, s.secret)
	h.Write([]byte(token))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// verifyTokenSignature verifies an HMAC-SHA512 signature for a token.
func (s *Store) verifyTokenSignature(token, signature string) bool {
	expected := s.signToken(token)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func tokenExpiredAt(token *Token, now time.Time) bool {
	return token == nil || !now.Before(token.ExpiresAt)
}

// ValidateToken checks if a token is valid and returns the associated user.
func (s *Store) ValidateToken(tokenStr string) (*User, error) {
	s.mu.RLock()
	token, ok := s.tokens[tokenStr]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("invalid token")
	}

	// Verify HMAC signature to prevent token forgery
	if !s.verifyTokenSignature(tokenStr, token.Signature) {
		s.mu.RUnlock()
		return nil, fmt.Errorf("invalid token signature")
	}

	if tokenExpiredAt(token, time.Now()) {
		s.mu.RUnlock()
		s.mu.Lock()
		// Re-check token presence under the write lock. Two concurrent
		// ValidateToken calls can both observe the expired token under
		// the read lock, both drop and re-acquire the write lock, and
		// both reach this decrement — double-decrementing activeSessions
		// (which can drive the int counter negative and either lock the
		// user out of new sessions via the max-sessions cap or pass it
		// when they shouldn't, depending on signedness handling). Make
		// the cleanup idempotent.
		if _, stillPresent := s.tokens[tokenStr]; stillPresent {
			delete(s.tokens, tokenStr)
			if s.activeSessions[token.Username] > 0 {
				s.activeSessions[token.Username]--
			}
		}
		s.mu.Unlock()
		return nil, fmt.Errorf("token expired")
	}

	// Note: LastAccess is informational only (never used for expiry
	// or revocation decisions). Previously this hot path mutated
	// token.LastAccess under the read lock, which is a data race —
	// time.Time is multi-word (wall, ext, loc) and concurrent
	// validators could read a torn value. Skipping the update keeps
	// the read lock semantics honest; if a future feature needs
	// last-access for idle-session detection, switch the storage to
	// an atomic.Int64 of UnixNano or move the write under s.mu.Lock.

	user, ok := s.users[token.Username]
	publicUser := clonePublicUser(user)
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	return publicUser, nil
}

// RevokeToken invalidates a token.
//
// L-3: pair the decrement with the same gates used elsewhere — both
// the maxSessionsPerUser > 0 condition (which gates the matching
// increment in GenerateToken) and the > 0 sanity guard (which keeps
// the expired-token cleanup path idempotent under concurrent
// invalidation). Without these, a deployment that hasn't enabled
// the session cap silently drives activeSessions[username] negative
// on every revoke; if the operator later turns the cap on, the
// negative counter masks the real session count and either locks
// legitimate users out or lets them past the cap.
func (s *Store) RevokeToken(tokenStr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[tokenStr]; ok {
		if s.maxSessionsPerUser > 0 && s.activeSessions[t.Username] > 0 {
			s.activeSessions[t.Username]--
		}
	}
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
	delete(s.activeSessions, username)
}

// MaxPasswordBytes bounds accepted password size. PBKDF2 iterations run over
// the full input, so an attacker posting a 10 MB password forces ~50× the
// server CPU compared to a normal login (VULN-021).
const MaxPasswordBytes = 128

// ValidatePassword rejects empty passwords, passwords shorter than
// MinPasswordBytes, and passwords larger than MaxPasswordBytes.
func ValidatePassword(password string) error {
	const MinPasswordBytes = 8
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	if len(password) < MinPasswordBytes {
		return fmt.Errorf("password must be at least %d characters", MinPasswordBytes)
	}
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	}
	return nil
}

// ValidateUsername rejects empty usernames and control characters that break
// logs, persistence formats, API paths, or terminal output.
func ValidateUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username must not be empty")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return fmt.Errorf("username must not contain control characters")
		}
	}
	return nil
}

// ValidateRole rejects unknown RBAC roles.
func ValidateRole(role Role) error {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer:
		return nil
	default:
		return fmt.Errorf("invalid role %q", role)
	}
}

// CreateUser creates a new user.
func (s *Store) CreateUser(username, password string, role Role) (*User, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	if err := ValidateRole(role); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return nil, ErrUserExists
	}

	hash, err := HashPasswordWithError(password, nil)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	user := &User{
		Username:  username,
		Hash:      hash,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.users[username] = user
	s.persistUsersLocked()
	return clonePublicUser(user), nil
}

// UpdateUser updates an existing user's password or role.
// Empty password means "do not change" — nonempty passwords go through
// ValidatePassword for size bounds (VULN-021).
func (s *Store) UpdateUser(username, password string, role Role) (*User, error) {
	if password != "" {
		if err := ValidatePassword(password); err != nil {
			return nil, err
		}
	}
	if role != "" {
		if err := ValidateRole(role); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	if role != "" && user.Role == RoleAdmin && role != RoleAdmin && s.adminUserCountLocked() <= 1 {
		return nil, ErrLastAdmin
	}

	if password != "" {
		hash, err := HashPasswordWithError(password, nil)
		if err != nil {
			return nil, fmt.Errorf("hashing password: %w", err)
		}
		user.Hash = hash
	}
	roleChanged := role != "" && user.Role != role
	if role != "" {
		user.Role = role
	}
	user.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Revoke all tokens for this user (password or role changed) (LOW-013).
	if password != "" || roleChanged {
		for token, t := range s.tokens {
			if t.Username == username {
				delete(s.tokens, token)
			}
		}
		delete(s.activeSessions, username)
	}

	s.persistUsersLocked()
	return clonePublicUser(user), nil
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.deleteUserLocked(username)
}

// DeleteUserPreservingLastAdmin removes a user while preventing admin lockout.
func (s *Store) DeleteUserPreservingLastAdmin(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user not found")
	}
	if user.Role == RoleAdmin && s.adminUserCountLocked() <= 1 {
		return ErrLastAdmin
	}
	return s.deleteUserLocked(username)
}

func (s *Store) deleteUserLocked(username string) error {
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
	delete(s.activeSessions, username)
	s.persistUsersLocked()
	return nil
}

func (s *Store) adminUserCountLocked() int {
	count := 0
	for _, user := range s.users {
		if user.Role == RoleAdmin {
			count++
		}
	}
	return count
}

// ListUsers returns all users (without passwords).
func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, clonePublicUser(u))
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
	return clonePublicUser(user), nil
}

func clonePublicUser(user *User) *User {
	if user == nil {
		return nil
	}
	return &User{
		Username:      user.Username,
		Role:          user.Role,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		IsAutoCreated: user.IsAutoCreated,
	}
}

// dummyHash is a pre-computed hash used to equalize login timing when the
// requested username does not exist (VULN-017). Computed once on first call.
var dummyHash = sync.OnceValue(func() []byte {
	hash, err := HashPasswordWithError("timing-equalization-placeholder", []byte("nothingdns-auth-dummy-salt-00001"))
	if err != nil {
		return nil
	}
	return hash
})

// VerifyUserPassword checks username + password against stored credentials.
// On a missing user it still runs VerifyPassword against a fixed dummy hash so
// the response time does not reveal whether the username exists (VULN-017).
func (s *Store) VerifyUserPassword(username, password string) bool {
	s.mu.RLock()
	user, ok := s.users[username]
	s.mu.RUnlock()

	if !ok {
		// Burn the same PBKDF2 rounds a real verification would, then return
		// false. The result is discarded — subtle.ConstantTimeCompare still
		// pays the comparison cost.
		if VerifyPassword(password, dummyHash()) {
			return false
		}
		return false
	}
	return VerifyPassword(password, user.Hash)
}

// UsesAutoCreatedAdmin reports whether the only way in is still the admin
// placeholder with a random, unknown password created by NewStore.
func (s *Store) UsesAutoCreatedAdmin() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	admin, ok := s.users["admin"]
	return ok && admin.IsAutoCreated
}

// EnableUsersFile loads users created at runtime (bootstrap, dashboard, API)
// from path and persists every later user change there, so they survive
// restarts. A missing file is not an error. Users defined in the server config
// take precedence over same-named users in the file, and a successfully loaded
// user replaces the synthetic auto-created admin. Returns the number of users
// loaded.
func (s *Store) EnableUsersFile(path string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersFilePath = path

	data, err := readAuthPersistFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var users map[string]*User
	if err := json.Unmarshal(data, &users); err != nil {
		return 0, fmt.Errorf("parsing users file %s: %w", path, err)
	}
	if len(users) > 0 {
		if err := validateLoadedUsers(users); err != nil {
			return 0, fmt.Errorf("users file %s: %w", path, err)
		}
	}

	loaded := 0
	for name, u := range users {
		if u.IsAutoCreated {
			continue
		}
		if existing, ok := s.users[name]; ok && existing.configured {
			continue
		}
		u.configured = false
		s.users[name] = u
		loaded++
	}
	if loaded > 0 {
		if admin, ok := s.users["admin"]; ok && admin.IsAutoCreated {
			delete(s.users, "admin")
		}
	}
	return loaded, nil
}

// persistUsersLocked writes the runtime-managed users to the users file, if
// one is enabled. Config-defined users and the auto-created admin are left
// out. Must be called with s.mu held. A write failure is logged rather than
// returned: the in-memory change has already been applied.
func (s *Store) persistUsersLocked() {
	if s.usersFilePath == "" {
		return
	}
	users := make(map[string]*User)
	for name, u := range s.users {
		if u.configured || u.IsAutoCreated {
			continue
		}
		users[name] = u
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err == nil {
		err = atomicWriteFile(s.usersFilePath, data, 0600)
	}
	if err != nil {
		util.Warnf("auth: failed to persist users to %s: %v", s.usersFilePath, err)
	}
}

// Save persists users to a file.
func (s *Store) Save(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write via temp + fsync + rename. A torn write to the user
	// database is catastrophic: the daemon on restart sees malformed
	// JSON and Load returns an error, leaving no users (or, worse, a
	// partial set). os.WriteFile alone offers none of the ordering
	// guarantees a crash-recovery sequence needs.
	return atomicWriteFile(path, data, 0600)
}

// Load reads users from a file.
func (s *Store) Load(path string) error {
	data, err := readAuthPersistFile(path)
	if err != nil {
		return err
	}
	var users map[string]*User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	if err := validateLoadedUsers(users); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = users
	return nil
}

func readAuthPersistFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxAuthPersistFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAuthPersistFileSize {
		return nil, fmt.Errorf("auth persistence file exceeds %d bytes", maxAuthPersistFileSize)
	}
	return data, nil
}

func validateLoadedUsers(users map[string]*User) error {
	if len(users) == 0 {
		return fmt.Errorf("users file contains no users")
	}
	for username, u := range users {
		if strings.TrimSpace(username) == "" {
			return fmt.Errorf("users file contains empty username key")
		}
		if u == nil {
			return fmt.Errorf("users file contains nil user for %q", username)
		}
		if u.Username != username {
			return fmt.Errorf("users file key %q does not match embedded username %q", username, u.Username)
		}
		if err := ValidateUsername(u.Username); err != nil {
			return fmt.Errorf("invalid loaded user %q: %w", username, err)
		}
		if err := ValidateRole(u.Role); err != nil {
			return fmt.Errorf("invalid loaded role for user %q: %w", username, err)
		}
		if len(u.Hash) == 0 {
			return fmt.Errorf("loaded user %q has no password hash", username)
		}
	}
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
		RoleViewer:   1,
		RoleOperator: 2,
		RoleAdmin:    3,
	}

	return roleOrder[user.Role] >= roleOrder[required]
}

// SaveTokensSigned persists tokens to a file encrypted with AES-256-GCM.
// The HMAC secret is used as the encryption key (first 32 bytes after HKDF derivation).
// File format: nonce (12 bytes) + AES-256-GCM ciphertext (includes auth tag).
func (s *Store) SaveTokensSigned(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Serialize tokens
	data, err := json.Marshal(s.tokens)
	if err != nil {
		return fmt.Errorf("serializing tokens: %w", err)
	}

	// Derive a 32-byte AES key from the HMAC secret using HKDF-like derivation
	aesKey, err := deriveAESKeyWithError(s.secret)
	if err != nil {
		return fmt.Errorf("deriving token encryption key: %w", err)
	}
	defer clearBytes(aesKey)

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt with AES-256-GCM (provides both confidentiality and integrity)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Combine: nonce (12 bytes) + ciphertext+tag
	encrypted := make([]byte, len(nonce)+len(ciphertext))
	copy(encrypted, nonce)
	copy(encrypted[len(nonce):], ciphertext)

	return atomicWriteFile(path, encrypted, 0600)
}

// atomicWriteFile writes `data` to `path` via the standard
// temp-file + fsync + rename pattern, with a directory fsync at
// the end so the new dirent is durable. Used for the users
// database and the encrypted token store — both are catastrophic
// if a torn write leaves them malformed.
var syncParentDir = func(dir string) error {
	dirFd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFd.Close()
	if err := dirFd.Sync(); err != nil {
		return err
	}
	return nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
				err = fmt.Errorf("remove temp: %w", removeErr)
			}
		}
	}()
	if err := os.Chmod(tmpName, mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := util.WriteFull(tmp, data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	if err := syncParentDir(dir); err != nil {
		return fmt.Errorf("fsync parent dir: %w", err)
	}
	return nil
}

// LoadTokensSigned loads tokens from a file encrypted with AES-256-GCM.
// Returns error if file doesn't exist or decryption/integrity check fails.
func (s *Store) LoadTokensSigned(path string) error {
	data, err := readAuthPersistFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No tokens file yet, that's ok
		}
		return fmt.Errorf("reading tokens file: %w", err)
	}

	// Minimum: 12-byte nonce + 16-byte GCM tag + some JSON
	if len(data) < 12+16+2 {
		return fmt.Errorf("tokens file too short")
	}

	// Derive AES key from HMAC secret
	aesKey, err := deriveAESKeyWithError(s.secret)
	if err != nil {
		return fmt.Errorf("deriving token encryption key: %w", err)
	}
	defer clearBytes(aesKey)

	// Split: nonce (12 bytes) + ciphertext+tag
	nonce := data[:12]
	ciphertext := data[12:]

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("tokens file integrity check failed: %w", err)
	}

	// Deserialize
	var tokens map[string]*Token
	if err := json.Unmarshal(plaintext, &tokens); err != nil {
		return fmt.Errorf("deserializing tokens: %w", err)
	}

	users := s.userTokenValiditySnapshot()
	filteredTokens, activeSessions, err := s.prepareLoadedTokens(tokens, time.Now(), users)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = filteredTokens
	s.activeSessions = activeSessions
	return nil
}

type tokenUserSnapshot struct {
	updatedAt time.Time
	hasUpdate bool
}

func (s *Store) userTokenValiditySnapshot() map[string]tokenUserSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make(map[string]tokenUserSnapshot, len(s.users))
	for username, user := range s.users {
		snapshot := tokenUserSnapshot{}
		if user != nil && user.UpdatedAt != "" {
			if updatedAt, err := time.Parse(time.RFC3339, user.UpdatedAt); err == nil {
				snapshot.updatedAt = updatedAt
				snapshot.hasUpdate = true
			}
		}
		users[username] = snapshot
	}
	return users
}

func (s *Store) prepareLoadedTokens(tokens map[string]*Token, now time.Time, users map[string]tokenUserSnapshot) (map[string]*Token, map[string]int, error) {
	filtered := make(map[string]*Token, len(tokens))
	activeSessions := make(map[string]int)
	for tokenKey, t := range tokens {
		if t == nil {
			return nil, nil, fmt.Errorf("tokens file contains nil token for %q", tokenKey)
		}
		if tokenKey == "" || t.Token == "" {
			return nil, nil, fmt.Errorf("tokens file contains empty token")
		}
		if tokenKey != t.Token {
			return nil, nil, fmt.Errorf("tokens file key does not match embedded token")
		}
		if t.Username == "" {
			return nil, nil, fmt.Errorf("token %q has empty username", tokenKey)
		}
		if err := ValidateUsername(t.Username); err != nil {
			return nil, nil, fmt.Errorf("invalid token username %q: %w", t.Username, err)
		}
		if err := ValidateRole(t.Role); err != nil {
			return nil, nil, fmt.Errorf("invalid token role for user %q: %w", t.Username, err)
		}
		if t.Signature == "" {
			return nil, nil, fmt.Errorf("token %q has empty signature", tokenKey)
		}
		if !s.verifyTokenSignature(t.Token, t.Signature) {
			return nil, nil, fmt.Errorf("token %q has invalid signature", tokenKey)
		}
		userSnapshot, userExists := users[t.Username]
		if !userExists {
			continue
		}
		if userSnapshot.hasUpdate && t.CreatedAt.Before(userSnapshot.updatedAt) {
			continue
		}
		if tokenExpiredAt(t, now) {
			continue
		}
		filtered[tokenKey] = t
		activeSessions[t.Username]++
	}
	return filtered, activeSessions, nil
}

// deriveAESKey derives a 32-byte AES-256 key from the HMAC secret using HKDF (RFC 5869).
// Replaces the previous SHA-512 truncation with a proper extract-and-expand KDF (MED-002).
func deriveAESKey(secret []byte) []byte {
	key, err := deriveAESKeyWithError(secret)
	if err != nil {
		util.Errorf("auth: AES key derivation failed: %v", err)
		return nil
	}
	return key
}

func deriveAESKeyWithError(secret []byte) ([]byte, error) {
	key, err := hkdf.Key(sha512.New, secret, nil, "nothingdns-token-encryption", 32)
	if err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}
	return key, nil
}

// clearBytes securely clears sensitive key material.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SetTokenFilePath sets the path for token persistence.
//
// Operational note (VULN-022): the token map is in-memory only by default.
// cmd/nothingdns never calls SetTokenFilePath, so server restart acts as a
// universal logout — every outstanding session token becomes invalid because
// the HMAC validates but the token is no longer in the map. This is
// deliberate: it removes the need to safeguard a persisted secret file.
// Operators who need continuity across restarts must call this alongside
// SaveTokensSigned / LoadTokensSigned in their own startup wiring.
func (s *Store) SetTokenFilePath(path string) {
	s.tokenFilePath = path
}

// generateSecret generates a random secret for HMAC signing.
func generateSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
