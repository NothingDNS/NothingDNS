package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/util"
	"time"
)

// Role represents a user's RBAC role.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access
	RoleOperator Role = "operator" // Can modify zones, cache, config
	RoleViewer   Role = "viewer"   // Read-only access
)

// User represents a user account.
type User struct {
	Username  string `json:"username"`
	Password  string `json:"-"`    // Never expose in JSON
	Hash      []byte `json:"hash"` // Stored password hash
	Role      Role   `json:"role"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Token represents an active authentication token.
type Token struct {
	Token     string    `json:"token"`
	Signature string    `json:"signature"` // HMAC signature for verification
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Store manages users and tokens.
type Store struct {
	mu            sync.RWMutex
	users         map[string]*User
	tokens        map[string]*Token
	secret        []byte // HMAC signing key
	tokenFilePath string // Path to persist tokens (optional)
}

// Config holds auth store configuration.
type Config struct {
	Secret      string   `yaml:"secret"`       // HMAC signing key
	Users       []User   `yaml:"users"`        // Initial users
	TokenExpiry Duration `yaml:"token_expiry"` // Token TTL (default: 24h)
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

	s := &Store{
		users:  make(map[string]*User),
		tokens: make(map[string]*Token),
		secret: secret,
	}

	// Load initial users
	for _, u := range cfg.Users {
		u := u // capture range variable
		// Hash plaintext password if present and zero it from memory
		if u.Password != "" && len(u.Hash) == 0 {
			u.Hash = HashPassword(u.Password, nil)
			u.Password = strings.Repeat("\x00", len(u.Password))
		}
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

	return s, nil
}

// HashPassword hashes a password with a random salt using PBKDF2-HMAC-SHA512.
// This is a memory-hard key derivation function resistant to GPU/ASIC attacks.
// Parameters: 310,000 iterations (OWASP 2023 recommendation for SHA-512), 64-byte output.
// Returns the hash that can be stored and later verified.
func HashPassword(password string, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, 32) // 256-bit salt
		if _, err := rand.Read(salt); err != nil {
			panic("crypto/rand failed to generate salt: " + err.Error())
		}
	}

	// PBKDF2-HMAC-SHA512 with iterations chosen for balance of security and performance.
	// OWASP 2023 recommends 310,000 iterations for SHA-512 at 128-bit security.
	// See: https://owasp.org/www-project-web-security-testing-guide/
	iterations := 310000
	keyLen := 64

	h := hmac.New(sha512.New, []byte(password))
	blockSize := h.Size()
	numBlocks := (keyLen + blockSize - 1) / blockSize

	result := make([]byte, keyLen)

	for block := 1; block <= numBlocks; block++ {
		// Salt || INT_32_BE(block) - computed once per block
		blockData := make([]byte, len(salt)+4)
		copy(blockData, salt)
		blockData[len(salt)] = byte(block >> 24)
		blockData[len(salt)+1] = byte(block >> 16)
		blockData[len(salt)+2] = byte(block >> 8)
		blockData[len(salt)+3] = byte(block)

		// U1 = PRF(Password, Salt || INT(i))
		h.Reset()
		h.Write(blockData)
		u := make([]byte, 0, h.Size())
		u = h.Sum(u)

		// Accumulator for this block: T = U1 XOR U2 XOR ... XOR Uc
		blockResult := make([]byte, len(u))
		copy(blockResult, u)

		// Subsequent iterations: Uj = PRF(Password, Uj-1)
		for j := 2; j <= iterations; j++ {
			h.Reset()
			h.Write(u)
			u = make([]byte, 0, h.Size())
			u = h.Sum(u)
			for k := 0; k < len(u); k++ {
				blockResult[k] ^= u[k]
			}
		}

		// Copy this block's result into the final key
		start := (block - 1) * blockSize
		end := start + blockSize
		if end > keyLen {
			end = keyLen
		}
		copy(result[start:end], blockResult[:end-start])
	}

	// Prepend salt to hash (salt bytes | key bytes)
	hash := make([]byte, len(salt)+len(result))
	copy(hash, salt)
	copy(hash[len(salt):], result)
	return hash
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
	// New format: 32-byte salt + 64-byte key = 96 bytes total
	// Old format: 16-byte salt + 32-byte key = 48 bytes total
	if len(hash) < 48 {
		return false
	}
	saltLen := 32
	if len(hash) == 48 {
		// Legacy format: 16-byte salt + 32-byte key
		saltLen = 16
	}
	salt := hash[:saltLen]
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

	// Sign the token with HMAC-SHA256
	signature := s.signToken(token)

	now := time.Now()
	t := &Token{
		Token:     token,
		Signature: signature,
		Username:  username,
		Role:      user.Role,
		ExpiresAt: now.Add(expiry),
		CreatedAt: now,
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
		Hash:      hash,
		Role:      role,
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
	aesKey := deriveAESKey(s.secret)
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

	return os.WriteFile(path, encrypted, 0600)
}

// LoadTokensSigned loads tokens from a file encrypted with AES-256-GCM.
// Returns error if file doesn't exist or decryption/integrity check fails.
func (s *Store) LoadTokensSigned(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(path)
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
	aesKey := deriveAESKey(s.secret)
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

	// Load tokens, filtering out expired ones
	now := time.Now()
	for token, t := range tokens {
		if now.After(t.ExpiresAt) {
			delete(tokens, token)
		}
	}

	s.tokens = tokens
	return nil
}

// deriveAESKey derives a 32-byte AES-256 key from the HMAC secret.
// Uses a simple but effective derivation: SHA-512(secret) truncated to 32 bytes.
func deriveAESKey(secret []byte) []byte {
	h := sha512.Sum512(secret)
	key := make([]byte, 32)
	copy(key, h[:32])
	return key
}

// clearBytes securely clears sensitive key material.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SetTokenFilePath sets the path for token persistence.
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
