// Package odoh implements Oblivious DNS over HTTPS (ODoH) as specified in RFC 9230.
// ODoH provides encrypted DNS queries through an oblivious proxy,
// preventing the resolver from learning the client's identity.
//
// The conformant RFC 9180 (HPKE) implementation lives in hpke.go +
// rfc9230.go and is exercised end-to-end by TestRFC9230RoundTrip and
// TestRFC9230_ClientProxyTargetRoundTrip. The HPKE math is verified
// against the canonical RFC 9180 §A.1 test vectors in
// hpke_vectors_test.go (DHKEM shared_secret, base_nonce, AEAD seal[0]).
//
// The legacy ObliviousDNSMessage struct and its encapsulate/decapsulate
// helpers in this file are NO LONGER WIRED into ServeHTTP/Query. They
// remain only because pre-RFC-9230 unit tests covered the underlying
// crypto primitives (ECDH, HKDF, AES-GCM). Removing them would delete
// real coverage without changing observable server behavior. Do not
// introduce new callers of these legacy helpers — extend hpke.go /
// rfc9230.go instead.
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

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
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
	errNilConfig        = errors.New("odoh config cannot be nil")
	errBodyTooLarge     = errors.New("odoh body too large")
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
	TargetName      string // DNS name of the target resolver (e.g., "dns.example.com")
	ProxyName       string // DNS name of the proxy (e.g., "proxy.example.com")
	TargetURL       string // HTTPS URL of the target
	ProxyURL        string // HTTPS URL of the proxy
	HPKEKEM         int    // Key Encapsulation Mechanism (KEM) algorithm
	HPKEKDF         int    // Key Derivation Function (KDF) algorithm
	HPKEAEAD        int    // Authenticated Encryption with Associated Data (AEAD) algorithm
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
	handler server.Handler
	// keyPair holds the RFC 9230 / RFC 9180 HPKE state. Generated once
	// in NewObliviousTarget; key rotation requires a fresh target.
	keyPair *odohKeyPair
}

// odohResponseWriter captures the DNS response wire from the handler.
// It implements server.ResponseWriter.
type odohResponseWriter struct {
	// packed holds the response wire, snapshotted at Write time. The inner
	// handler owns its response message's lifecycle — the pipeline Releases
	// pooled responses at stage exit — so the target must not read or
	// Release the message after ServeDNS returns.
	packed []byte
}

func (rw *odohResponseWriter) Write(msg *protocol.Message) (int, error) {
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		return 0, err
	}
	rw.packed = append([]byte(nil), buf[:n]...)
	return n, nil
}

func (rw *odohResponseWriter) ClientInfo() *server.ClientInfo {
	return &server.ClientInfo{Protocol: "odoh"}
}

func (rw *odohResponseWriter) MaxSize() int {
	return 65535
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
	if config == nil {
		return nil, errNilConfig
	}
	return &ObliviousClient{
		config: config,
		client: newODoHHTTPClient(),
	}, nil
}

// Query sends an encrypted DNS query through the proxy to the target,
// conformant with RFC 9230 / RFC 9180 (HPKE base mode).
//
// The client must have a valid ObliviousDoHConfigContents for the
// target in c.config.TargetPublicKey (treated as the raw config bytes,
// not just the X25519 public key — see SetTargetConfig).
func (c *ObliviousClient) Query(dnsQuery []byte) ([]byte, error) {
	targetConfig, err := c.getTargetConfigContents()
	if err != nil {
		return nil, fmt.Errorf("getting target config: %w", err)
	}

	msgBytes, qCtx, err := encryptQueryRFC9230(targetConfig, dnsQuery)
	if err != nil {
		return nil, fmt.Errorf("encapsulating query: %w", err)
	}

	respBytes, err := c.postEncapsulated(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("sending to proxy: %w", err)
	}

	// The response key is now derived from the HPKE exporter secret (bound to
	// the DH shared secret) inside decryptResponse — no query-plaintext reseed.
	plain, err := qCtx.decryptResponse(respBytes)
	if err != nil {
		return nil, fmt.Errorf("decapsulating response: %w", err)
	}
	return plain, nil
}

// getTargetConfigContents returns the marshaled
// ObliviousDoHConfigContents. The client config carries it in
// TargetPublicKey for compatibility with the existing API surface.
func (c *ObliviousClient) getTargetConfigContents() ([]byte, error) {
	if c == nil || c.config == nil {
		return nil, errNilConfig
	}
	if len(c.config.TargetPublicKey) == 0 {
		return nil, ErrInvalidKey
	}
	return c.config.TargetPublicKey, nil
}

// postEncapsulated POSTs the RFC 9230 wire-format message to the
// configured proxy URL and returns the response bytes.
func (c *ObliviousClient) postEncapsulated(body []byte) ([]byte, error) {
	if c == nil || c.config == nil {
		return nil, errNilConfig
	}
	req, err := http.NewRequest("POST", c.config.ProxyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status: %d", resp.StatusCode)
	}
	respBody, err := readLimitedODoHBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading proxy response: %w", err)
	}
	return respBody, nil
}

// getTargetPublicKey returns the target's public key.
// The key must be provided via configuration or fetched securely.
// Returns an error if no valid key is configured.
func (c *ObliviousClient) getTargetPublicKey() ([]byte, error) {
	if c == nil || c.config == nil {
		return nil, errNilConfig
	}
	// In a real implementation, the key would be:
	// 1. Fetched from DNS (with DNSSEC validation)
	// 2. Pre-configured by the operator
	// 3. Fetched via a secure channel (HTTPS with pinned certificate)
	//
	// A zeroed key is cryptographically invalid and would fail
	// key agreement - callers must provide a valid key.
	if len(c.config.TargetPublicKey) == 0 {
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
	kdfInfo := buildKDFInfo(c.config.TargetName, false)
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

	respBody, err := readLimitedODoHBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseProxyResponse(respBody)
}

// decapsulateResponse decrypts the response from the target.
func (c *ObliviousClient) decapsulateResponse(response *ObliviousDNSMessage, ephemeralPriv []byte) ([]byte, error) {
	// SECURITY (V-01 fix): Derive shared secret using the TARGET's static public key,
	// not from self-ECDH. The target encrypts using ECDH(target_priv, client_epk),
	// so the client must use ECDH(client_ephemeral_priv, target_pub) to produce
	// the same shared secret. Previous code did ECDH(self, self) which was trivially
	// computable from the public key sent in the clear.
	targetPub, err := c.getTargetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting target public key: %w", err)
	}
	sharedSecret, err := deriveSharedSecret(ephemeralPriv, targetPub, c.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	// SECURITY (V-02 fix): Use distinct KDF context for response decryption.
	// The response uses a different key derivation context than the query
	// to ensure request and response keys are cryptographically independent.
	kdfInfo := buildKDFInfo(c.config.TargetName, true)
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
	if config == nil {
		return nil, errNilConfig
	}
	return &ObliviousProxy{
		config: config,
		client: newODoHHTTPClient(),
	}, nil
}

func newODoHHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ServeHTTP implements the HTTP handler for the ODoH proxy. The proxy
// is intentionally opaque: it forwards the encrypted body to the
// configured target URL without parsing or modifying it. RFC 9230 §5
// requires the proxy never see the inner DNS message, which is exactly
// what a byte-for-byte pass-through achieves.
func (p *ObliviousProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.config == nil {
		http.Error(w, "ODoH proxy not initialised", http.StatusServiceUnavailable)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readLimitedODoHBody(r.Body)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	respBytes, err := p.forwardRaw(body)
	if err != nil {
		http.Error(w, "Target error", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBytes); err != nil {
		return
	}
}

// forwardRaw POSTs the opaque ODoH message bytes to the configured
// target URL and returns the response bytes verbatim.
func (p *ObliviousProxy) forwardRaw(body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", p.config.TargetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("forwarding to target: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target returned status: %d", resp.StatusCode)
	}
	respBody, err := readLimitedODoHBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading target response: %w", err)
	}
	return respBody, nil
}

// NewObliviousTarget creates a new ODoH target resolver. The target
// generates an RFC 9180 HPKE key pair using the suite specified in the
// config; only DHKEM-X25519 / HKDF-SHA256 / AES-128-GCM or AES-256-GCM
// are supported (zero-dep policy excludes ChaCha20Poly1305).
//
// Returns an error if the requested KEM/KDF/AEAD combination is not
// one of the supported suites.
func NewObliviousTarget(config *ODoHConfig, handler server.Handler) (*ObliviousTarget, error) {
	if err := validateODoHSuite(config); err != nil {
		return nil, fmt.Errorf("unsupported HPKE suite: %w", err)
	}
	suite := defaultHPKESuite()
	if config.HPKEAEAD == HPKEAEADAES256GCM {
		// Honor the configured AEAD: the suite is advertised in the
		// published ODoH config, so clients follow it.
		suite.aeadID = hpkeAEADAES256GCM
	}
	kp, err := newODoHKeyPairWithSuite(suite)
	if err != nil {
		return nil, fmt.Errorf("generating HPKE key pair: %w", err)
	}
	return &ObliviousTarget{
		config:  config,
		privKey: kp.skR.Bytes(),
		pubKey:  kp.pkRBytes,
		handler: handler,
		keyPair: kp,
	}, nil
}

// validateODoHSuite returns an error if the config's KEM/KDF/AEAD does
// not name one of the supported HPKE suites.
func validateODoHSuite(cfg *ODoHConfig) error {
	if cfg == nil {
		return errNilConfig
	}
	if cfg.HPKEKEM != HPKEDHX25519 {
		return fmt.Errorf("KEM %d not supported (only X25519 = %d)", cfg.HPKEKEM, HPKEDHX25519)
	}
	if cfg.HPKEKDF != HPKEKDFHKDFSHA256 {
		return fmt.Errorf("KDF %d not supported (only HKDF-SHA256 = %d)", cfg.HPKEKDF, HPKEKDFHKDFSHA256)
	}
	if cfg.HPKEAEAD != HPKEAEADAES256GCM && cfg.HPKEAEAD != HPKEAEADAES128GCM {
		return fmt.Errorf("AEAD %d not supported (only AES-128/256-GCM)", cfg.HPKEAEAD)
	}
	return nil
}

// HPKEAEADAES128GCM is exposed for callers selecting the AES-128-GCM
// AEAD variant in ODoHConfig.
const HPKEAEADAES128GCM = 3

// ServeHTTP implements the HTTP handler for an ODoH target, conformant
// to RFC 9230 / RFC 9180 (HPKE).
//
// Wire flow:
//
//  1. Proxy POSTs an ObliviousDoHMessage (type=0x01) to /dns-query.
//  2. Target decrypts the inner DNS query via HPKE base mode setup with
//     its long-lived recipient key.
//  3. Target resolves the query through the configured server.Handler.
//  4. Target re-encrypts the DNS response under a fresh AEAD key+nonce
//     derived from the HPKE exporter secret (Context.Export, RFC 9230
//     §4.2) plus a random per-response nonce — never from the query
//     plaintext — and returns it as an ObliviousDoHMessage (type=0x02).
//
// On any decode, decrypt, or resolution failure, HTTP 400 / 500 is
// returned without leaking which step failed.
func (t *ObliviousTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if t == nil {
		http.Error(w, "ODoH target not initialised", http.StatusServiceUnavailable)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if t.keyPair == nil {
		http.Error(w, "ODoH target not initialised", http.StatusServiceUnavailable)
		return
	}

	body, err := readLimitedODoHBody(r.Body)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	dnsQuery, respCtx, err := t.keyPair.decryptQuery(body)
	if err != nil {
		http.Error(w, "Decryption error", http.StatusBadRequest)
		return
	}

	query, err := protocol.UnpackMessage(dnsQuery)
	if err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}
	defer query.Release()

	rw := &odohResponseWriter{}
	(&server.ServeDNSWithRecovery{Handler: t.handler}).ServeDNS(rw, query)
	// The writer snapshotted the response wire at Write time; the inner
	// handler/pipeline owns the response message's lifecycle (the pipeline
	// Releases pooled responses at stage exit — releasing it here would be
	// a double-Release of a pooled message).
	if len(rw.packed) == 0 {
		http.Error(w, "Failed to process query", http.StatusInternalServerError)
		return
	}

	encryptedResponse, err := respCtx.encryptResponse(rw.packed)
	if err != nil {
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(encryptedResponse); err != nil {
		return
	}
}

func readLimitedODoHBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// PublicKey returns the raw X25519 public key bytes. Most clients want
// ConfigContents()/ConfigsObject() instead.
func (t *ObliviousTarget) PublicKey() []byte {
	pubKey := make([]byte, len(t.pubKey))
	copy(pubKey, t.pubKey)
	return pubKey
}

// ConfigContents returns the marshaled ObliviousDoHConfigContents
// (RFC 9230 §3.1) describing this target's HPKE suite and public key.
// Suitable for clients that already know the version wrapper.
func (t *ObliviousTarget) ConfigContents() []byte {
	if t.keyPair == nil {
		return nil
	}
	out := make([]byte, len(t.keyPair.configBytes))
	copy(out, t.keyPair.configBytes)
	return out
}

// ConfigsObject returns the version-wrapped ObliviousDoHConfigs object
// (RFC 9230 §3) suitable for serving over /.well-known/odohconfigs.
func (t *ObliviousTarget) ConfigsObject() []byte {
	if t.keyPair == nil {
		return nil
	}
	cfgs, err := t.keyPair.configsObject()
	if err != nil {
		return nil
	}
	return cfgs
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
	kdfInfo := buildKDFInfo(t.config.TargetName, false)
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
	// Derive shared secret using target's private key and client's ephemeral public key
	sharedSecret, err := deriveSharedSecret(t.privKey, msg.PublicKey, t.config.HPKEKEM)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}
	defer clearBytes(sharedSecret)

	// SECURITY (V-02 fix): Use distinct KDF context for response encryption.
	// The response key derivation uses a different context byte than the query
	// to ensure request and response use cryptographically independent keys,
	// even though they share the same underlying ECDH shared secret.
	kdfInfo := buildKDFInfo(t.config.TargetName, true)
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
// The responseCtx parameter differentiates query vs response key derivation:
//   - false (0x01): query encryption/decryption context
//   - true  (0x02): response encryption/decryption context
//
// This ensures request and response use cryptographically independent keys
// even when derived from the same ECDH shared secret.
func buildKDFInfo(suiteID string, responseCtx bool) []byte {
	var info bytes.Buffer
	info.WriteString("odoh")
	info.WriteString(suiteID)
	if responseCtx {
		info.WriteByte(0x02)
	} else {
		info.WriteByte(0x01)
	}
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

	if err := writeU16Bytes(&buf, "public key", msg.PublicKey); err != nil {
		return nil, err
	}
	if err := writeU16Bytes(&buf, "ciphertext", msg.Ciphertext); err != nil {
		return nil, err
	}

	// Write nonce
	if _, err := buf.Write(msg.Nonce); err != nil {
		return nil, err
	}

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
	if _, err := io.ReadFull(r, pubKey); err != nil {
		return nil, err
	}

	// Read ciphertext
	var ctLen uint16
	if err := binary.Read(r, binary.BigEndian, &ctLen); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, ctLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	// Read nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("trailing data after nonce: %d bytes", r.Len())
	}

	return &ObliviousDNSMessage{
		PublicKey:  pubKey,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func buildProxyResponse(msg *ObliviousDNSMessage) ([]byte, error) {
	var buf bytes.Buffer

	if err := writeU16Bytes(&buf, "public key", msg.PublicKey); err != nil {
		return nil, err
	}
	if err := writeU16Bytes(&buf, "ciphertext", msg.Ciphertext); err != nil {
		return nil, err
	}

	// Write nonce
	if _, err := buf.Write(msg.Nonce); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func parseProxyResponse(body []byte) (*ObliviousDNSMessage, error) {
	return parseProxyRequest(body) // Same format
}

func writeU16Bytes(buf *bytes.Buffer, field string, b []byte) error {
	n, err := u16Length(field, len(b))
	if err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, n); err != nil {
		return err
	}
	_, err = buf.Write(b)
	return err
}
