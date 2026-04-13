// Package odoh implements Oblivious DNS over HTTPS (ODoH) as specified in RFC 9230.
// ODoH provides encrypted DNS queries through an oblivious proxy,
// preventing the resolver from learning the client's identity.
package odoh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"
)

// ODoH (Oblivious DNS over HTTPS) implements RFC 9230.

// maxBodySize is the maximum allowed size for ODoH request/response bodies.
// This prevents OOM attacks from unbounded reads.
const maxBodySize = 4 * 1024 * 1024 // 4MB

// Errors for ODoH operations.
var (
	ErrInvalidKey       = errors.New("invalid HPKE key")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidNonce     = errors.New("invalid nonce")
	ErrTooManyDHPairs   = errors.New("too many DH pairs for this context")
)

// HPKE AEAD algorithms supported by ODoH.
const (
	HPKEAEADAES256GCM        = 1
	HPKEAEADChaCha20Poly1305 = 2
)

// HPKE DH key agreement algorithms.
const (
	HPKEDHP256   = 1 // ECDH P-256
	HPKEDHP384   = 2 // ECDH P-384
	HPKEDHP521   = 3 // ECDH P-521
	HPKEDHX25519 = 4 // X25519
)

// HPKE KDF algorithms.
const (
	HPKEKDFHKDFSHA256 = 1 // HKDF-SHA256
	HPKEKDFHKDFSHA384 = 2 // HKDF-SHA384
	HPKEKDFHKDFSHA512 = 3 // HKDF-SHA512
)

// ODoHConfig contains configuration for ODoH operations.
type ODoHConfig struct {
	TargetName     string // DNS name of the target resolver (e.g., "dns.example.com")
	ProxyName      string // DNS name of the proxy (e.g., "proxy.example.com")
	TargetURL      string // HTTPS URL of the target
	ProxyURL       string // HTTPS URL of the proxy
	HPKEKEM        int    // Key Encapsulation Mechanism (KEM) algorithm
	HPKEKDF        int    // Key Derivation Function (KDF) algorithm
	HPKEAEAD       int    // Authenticated Encryption with Associated Data (AEAD) algorithm
	TargetPublicKey []byte // Target's HPKE public key (required for ODoH client)
}

// ObliviousDNSMessage represents an ODoH message.
type ObliviousDNSMessage struct {
	// Public key used for encapsulation
	PublicKey []byte
	// Encrypted DNS query/response
	Ciphertext []byte
	// Nonce used for encryption
	Nonce []byte
	// Additional authenticated data (AAD)
	AAD []byte
}

// ObliviousClient implements the client side of ODoH.
type ObliviousClient struct {
	config *ODoHConfig
	client *http.Client
}

// ObliviousProxy implements the proxy side of ODoH.
type ObliviousProxy struct {
	config *ODoHConfig
	client *http.Client
}

// ObliviousTarget implements the target resolver side of ODoH.
type ObliviousTarget struct {
	config  *ODoHConfig
	privKey []byte // Target's private key
	pubKey  []byte // Target's public key
}

// NewODoHConfig creates a default ODoH configuration.
func NewODoHConfig(targetName, proxyName string) *ODoHConfig {
	return &ODoHConfig{
		TargetName: targetName,
		ProxyName:  proxyName,
		TargetURL:  "https://" + targetName + "/dns-query",
		ProxyURL:   "https://" + proxyName + "/dns-query",
		HPKEKEM:    HPKEDHX25519,
		HPKEKDF:    1, // HKDF-SHA256
		HPKEAEAD:   HPKEAEADAES256GCM,
	}
}

// NewObliviousClient creates a new ODoH client.
func NewObliviousClient(config *ODoHConfig) (*ObliviousClient, error) {
	return &ObliviousClient{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Query sends an encrypted DNS query through the proxy to the target.
func (c *ObliviousClient) Query(dnsQuery []byte) ([]byte, error) {
	// Generate HPKE key pair for encapsulation
	ephemeralPriv, err := generateEphemeralKey(c.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	defer clearBytes(ephemeralPriv)

	// Get target's public key (in real implementation, this would be fetched via DNS)
	targetPub, err := c.getTargetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting target public key: %w", err)
	}

	// Encapsulate the DNS query to the target
	encapsulated, err := c.encapsulateQuery(dnsQuery, ephemeralPriv, targetPub)
	if err != nil {
		return nil, fmt.Errorf("encapsulating query: %w", err)
	}

	// Send encapsulated message to proxy
	response, err := c.sendToProxy(encapsulated)
	if err != nil {
		return nil, fmt.Errorf("sending to proxy: %w", err)
	}

	// Decapsulate the response
	plaintext, err := c.decapsulateResponse(response, ephemeralPriv)
	if err != nil {
		return nil, fmt.Errorf("decapsulating response: %w", err)
	}

	return plaintext, nil
}

// getTargetPublicKey returns the target's public key.
// The key must be provided via configuration or fetched securely.
// Returns an error if no valid key is configured.
func (c *ObliviousClient) getTargetPublicKey() ([]byte, error) {
	// In a real implementation, the key would be:
	// 1. Fetched from DNS (with DNSSEC validation)
	// 2. Pre-configured by the operator
	// 3. Fetched via a secure channel (HTTPS with pinned certificate)
	//
	// A zeroed key is cryptographically invalid and would fail
	// key agreement - callers must provide a valid key.
	if c.config.TargetPublicKey == nil || len(c.config.TargetPublicKey) == 0 {
		return nil, ErrInvalidKey
	}
	return c.config.TargetPublicKey, nil
}

// encapsulateQuery encrypts a DNS query using HPKE.
func (c *ObliviousClient) encapsulateQuery(query, ephemeralPriv, targetPub []byte) (*ObliviousDNSMessage, error) {
	// Derive shared secret using ECDH
	sharedSecret, err := deriveSharedSecret(ephemeralPriv, targetPub, c.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	// Derive encryption keys using KDF
	kdfInfo := buildKDFInfo(c.config.TargetName)
	keys, err := deriveKeys(sharedSecret, kdfInfo, c.config.HPKEKDF, c.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, 12) // AES-GCM nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt the DNS query
	ciphertext, err := encrypt(query, nonce, keys.SealKey, nil, c.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("encrypting query: %w", err)
	}

	return &ObliviousDNSMessage{
		PublicKey:  derivePublicKey(ephemeralPriv, c.config.HPKEKEM),
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        []byte(c.config.TargetName),
	}, nil
}

// sendToProxy sends the encapsulated message to the proxy.
func (c *ObliviousClient) sendToProxy(msg *ObliviousDNSMessage) (*ObliviousDNSMessage, error) {
	// Build the HTTP request to proxy
	reqBody, err := buildProxyRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("building proxy request: %w", err)
	}

	req, err := http.NewRequest("POST", c.config.ProxyURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseProxyResponse(respBody)
}

// decapsulateResponse decrypts the response from the target.
func (c *ObliviousClient) decapsulateResponse(response *ObliviousDNSMessage, ephemeralPriv []byte) ([]byte, error) {
	// In ODoH, the response is encrypted to the ephemeral key
	// The target encrypts directly to the ephemeral public key

	// Re-derive the shared secret (response uses same ephemeral)
	pubKey := derivePublicKey(ephemeralPriv, c.config.HPKEKEM)
	sharedSecret, err := deriveSharedSecret(ephemeralPriv, pubKey, c.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	// Re-derive keys
	kdfInfo := buildKDFInfo(c.config.TargetName)
	keys, err := deriveKeys(sharedSecret, kdfInfo, c.config.HPKEKDF, c.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// Decrypt the response
	plaintext, err := decrypt(response.Ciphertext, response.Nonce, keys.SealKey, response.AAD, c.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("decrypting response: %w", err)
	}

	return plaintext, nil
}

// NewObliviousProxy creates a new ODoH proxy server.
func NewObliviousProxy(config *ODoHConfig) (*ObliviousProxy, error) {
	return &ObliviousProxy{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// ServeHTTP implements the HTTP handler for the proxy.
func (p *ObliviousProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Parse the oblivious DNS message
	msg, err := parseProxyRequest(body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Forward to target (with target's public key in the message)
	response, err := p.forwardToTarget(msg)
	if err != nil {
		http.Error(w, "Target error", http.StatusBadGateway)
		return
	}

	// Return response to client
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// forwardToTarget forwards the encapsulated message to the target resolver.
func (p *ObliviousProxy) forwardToTarget(msg *ObliviousDNSMessage) ([]byte, error) {
	// Build the HTTP request to forward to the target
	reqBody, err := buildProxyRequest(msg)
	if err != nil {
		return nil, fmt.Errorf("building proxy request: %w", err)
	}

	req, err := http.NewRequest("POST", p.config.TargetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("forwarding to target: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target returned status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading target response: %w", err)
	}

	return respBody, nil
}

// NewObliviousTarget creates a new ODoH target resolver.
func NewObliviousTarget(config *ODoHConfig) (*ObliviousTarget, error) {
	// Generate target's key pair
	priv, pub, err := generateKeyPair(config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}

	return &ObliviousTarget{
		config:  config,
		privKey: priv,
		pubKey:  pub,
	}, nil
}

// ServeHTTP implements the HTTP handler for the target.
func (t *ObliviousTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Parse the oblivious DNS message
	msg, err := parseProxyRequest(body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Decrypt the DNS query
	dnsQuery, err := t.decapsulateQuery(msg)
	if err != nil {
		http.Error(w, "Decryption error", http.StatusBadRequest)
		return
	}

	// Process DNS query (placeholder - would call actual resolver)
	dnsResponse := t.processDNSQuery(dnsQuery)

	// Encrypt the DNS response back to the client
	encryptedResponse, err := t.encapsulateResponse(dnsQuery, dnsResponse, msg)
	if err != nil {
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(encryptedResponse)
}

// decapsulateQuery decrypts a DNS query using HPKE.
func (t *ObliviousTarget) decapsulateQuery(msg *ObliviousDNSMessage) ([]byte, error) {
	// Derive shared secret using recipient's private key and sender's public key
	sharedSecret, err := deriveSharedSecret(t.privKey, msg.PublicKey, t.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	// Derive keys
	kdfInfo := buildKDFInfo(t.config.TargetName)
	keys, err := deriveKeys(sharedSecret, kdfInfo, t.config.HPKEKDF, t.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// Decrypt
	plaintext, err := decrypt(msg.Ciphertext, msg.Nonce, keys.SealKey, msg.AAD, t.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// encapsulateResponse encrypts a DNS response to the client.
func (t *ObliviousTarget) encapsulateResponse(query, response []byte, msg *ObliviousDNSMessage) ([]byte, error) {
	// Use the same shared secret derivation but encrypt with a new nonce
	sharedSecret, err := deriveSharedSecret(t.privKey, msg.PublicKey, t.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	kdfInfo := buildKDFInfo(t.config.TargetName)
	keys, err := deriveKeys(sharedSecret, kdfInfo, t.config.HPKEKDF, t.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}

	// Generate new nonce for response
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt response (AAD includes the original query for binding)
	ciphertext, err := encrypt(response, nonce, keys.SealKey, query, t.config.HPKEAEAD)
	if err != nil {
		return nil, fmt.Errorf("encrypting response: %w", err)
	}

	return buildProxyResponse(&ObliviousDNSMessage{
		PublicKey:  t.pubKey,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        query,
	})
}

// processDNSQuery processes a DNS query and returns a response.
// This is a placeholder - actual implementation would call the resolver.
func (t *ObliviousTarget) processDNSQuery(query []byte) []byte {
	// Placeholder - would actually resolve the DNS query
	return query
}

// HPKE utility functions.

// keyDerivationKeys holds derived key material.
type keyDerivationKeys struct {
	ExpandKey []byte
	SealKey   []byte
}

// generateEphemeralKey generates an ephemeral HPKE key pair.
func generateEphemeralKey(kem int) ([]byte, error) {
	switch kem {
	case HPKEDHX25519:
		priv, _, err := generateKeyPair(HPKEDHX25519)
		return priv, err
	default:
		return nil, ErrInvalidKey
	}
}

// generateKeyPair generates an HPKE key pair for the specified KEM.
func generateKeyPair(kem int) ([]byte, []byte, error) {
	switch kem {
	case HPKEDHX25519:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub := priv.PublicKey()
		return priv.Bytes(), pub.Bytes(), nil
	default:
		return nil, nil, ErrInvalidKey
	}
}

// derivePublicKey derives the public key from a private key.
func derivePublicKey(priv []byte, kem int) []byte {
	switch kem {
	case HPKEDHX25519:
		p, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil
		}
		pub := p.PublicKey()
		return pub.Bytes()
	default:
		return nil
	}
}

// deriveSharedSecret derives a shared secret using ECDH.
func deriveSharedSecret(priv, pub []byte, kem int) ([]byte, error) {
	switch kem {
	case HPKEDHX25519:
		privKey, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pubKey, err := ecdh.X25519().NewPublicKey(pub)
		if err != nil {
			return nil, err
		}
		shared, err := privKey.ECDH(pubKey)
		if err != nil {
			return nil, err
		}
		return shared, nil
	default:
		return nil, ErrInvalidKey
	}
}

// buildKDFInfo builds the KDF info parameter for HPKE.
func buildKDFInfo(suiteID string) []byte {
	var info bytes.Buffer
	info.WriteString("odoh")
	info.WriteString(suiteID)
	info.WriteByte(0)
	return info.Bytes()
}

// deriveKeys derives encryption keys using proper HKDF (RFC 5869).
func deriveKeys(sharedSecret, kdfInfo []byte, kdf, aead int) (*keyDerivationKeys, error) {
	// Select hash constructor based on KDF algorithm
	var hashNew func() hash.Hash
	switch kdf {
	case HPKEKDFHKDFSHA256:
		hashNew = sha256.New
	case HPKEKDFHKDFSHA384:
		hashNew = sha512.New384
	case HPKEKDFHKDFSHA512:
		hashNew = sha512.New
	default:
		return nil, fmt.Errorf("unsupported KDF algorithm: %d", kdf)
	}

	// Use HKDF-Extract to derive pseudorandom key (PRK)
	// HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
	prk, err := hkdf.Extract(hashNew, sharedSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PRK: %w", err)
	}

	// Use HKDF-Expand to derive the expand key
	// info = kdfInfo || 0x01
	expandKeyInfo := append(kdfInfo, 0x01)
	expandKey, err := hkdf.Expand(hashNew, prk, string(expandKeyInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive expand key: %w", err)
	}

	// Use HKDF-Expand to derive the seal key
	// info = kdfInfo || 0x02
	sealKeyInfo := append(kdfInfo, 0x02)
	sealKey, err := hkdf.Expand(hashNew, prk, string(sealKeyInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seal key: %w", err)
	}

	return &keyDerivationKeys{
		ExpandKey: expandKey,
		SealKey:   sealKey,
	}, nil
}

// encrypt encrypts plaintext using the specified AEAD algorithm.
func encrypt(plaintext, nonce, key, aad []byte, aeadAlg int) ([]byte, error) {
	// Currently only AES-256-GCM is supported
	// ChaCha20-Poly1305 will be added when crypto/chacha20poly1305 is available
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonce
	}

	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// decrypt decrypts ciphertext using the specified AEAD algorithm.
func decrypt(ciphertext, nonce, key, aad []byte, aeadAlg int) ([]byte, error) {
	// Currently only AES-256-GCM is supported
	// ChaCha20-Poly1305 will be added when crypto/chacha20poly1305 is available
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonce
	}

	return gcm.Open(nil, nonce, ciphertext, aad)
}

// clearBytes securely clears sensitive key material.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Wire format helpers.

func buildProxyRequest(msg *ObliviousDNSMessage) ([]byte, error) {
	var buf bytes.Buffer

	// Write public key length and value
	binary.Write(&buf, binary.BigEndian, uint16(len(msg.PublicKey)))
	buf.Write(msg.PublicKey)

	// Write ciphertext length and value
	binary.Write(&buf, binary.BigEndian, uint16(len(msg.Ciphertext)))
	buf.Write(msg.Ciphertext)

	// Write nonce
	buf.Write(msg.Nonce)

	return buf.Bytes(), nil
}

func parseProxyRequest(body []byte) (*ObliviousDNSMessage, error) {
	r := bytes.NewReader(body)

	// Read public key
	var pubLen uint16
	if err := binary.Read(r, binary.BigEndian, &pubLen); err != nil {
		return nil, err
	}
	pubKey := make([]byte, pubLen)
	if _, err := r.Read(pubKey); err != nil {
		return nil, err
	}

	// Read ciphertext
	var ctLen uint16
	if err := binary.Read(r, binary.BigEndian, &ctLen); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, ctLen)
	if _, err := r.Read(ciphertext); err != nil {
		return nil, err
	}

	// Read nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := r.Read(nonce); err != nil {
		return nil, err
	}

	return &ObliviousDNSMessage{
		PublicKey:  pubKey,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func buildProxyResponse(msg *ObliviousDNSMessage) ([]byte, error) {
	var buf bytes.Buffer

	// Write public key
	binary.Write(&buf, binary.BigEndian, uint16(len(msg.PublicKey)))
	buf.Write(msg.PublicKey)

	// Write ciphertext
	binary.Write(&buf, binary.BigEndian, uint16(len(msg.Ciphertext)))
	buf.Write(msg.Ciphertext)

	// Write nonce
	buf.Write(msg.Nonce)

	return buf.Bytes(), nil
}

func parseProxyResponse(body []byte) (*ObliviousDNSMessage, error) {
	return parseProxyRequest(body) // Same format
}
