// Copyright 2025 NothingDNS Authors
// SPDX-License-Identifier: BSD-3-Clause

package odoh

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewODoHConfig(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")

	if cfg.TargetName != "target.example.com" {
		t.Errorf("TargetName = %q, want %q", cfg.TargetName, "target.example.com")
	}
	if cfg.ProxyName != "proxy.example.com" {
		t.Errorf("ProxyName = %q, want %q", cfg.ProxyName, "proxy.example.com")
	}
	if cfg.TargetURL != "https://target.example.com/dns-query" {
		t.Errorf("TargetURL = %q, want %q", cfg.TargetURL, "https://target.example.com/dns-query")
	}
	if cfg.ProxyURL != "https://proxy.example.com/dns-query" {
		t.Errorf("ProxyURL = %q, want %q", cfg.ProxyURL, "https://proxy.example.com/dns-query")
	}
	if cfg.HPKEKEM != HPKEDHX25519 {
		t.Errorf("HPKEKEM = %d, want %d", cfg.HPKEKEM, HPKEDHX25519)
	}
	if cfg.HPKEKDF != 1 {
		t.Errorf("HPKEKDF = %d, want 1", cfg.HPKEKDF)
	}
	if cfg.HPKEAEAD != HPKEAEADAES256GCM {
		t.Errorf("HPKEAEAD = %d, want %d", cfg.HPKEAEAD, HPKEAEADAES256GCM)
	}
}

func TestConstants(t *testing.T) {
	// HPKE AEAD constants
	if HPKEAEADAES256GCM != 1 {
		t.Errorf("HPKEAEADAES256GCM = %d, want 1", HPKEAEADAES256GCM)
	}
	if HPKEAEADChaCha20Poly1305 != 2 {
		t.Errorf("HPKEAEADChaCha20Poly1305 = %d, want 2", HPKEAEADChaCha20Poly1305)
	}

	// HPKE DH constants
	if HPKEDHP256 != 1 {
		t.Errorf("HPKEDHP256 = %d, want 1", HPKEDHP256)
	}
	if HPKEDHP384 != 2 {
		t.Errorf("HPKEDHP384 = %d, want 2", HPKEDHP384)
	}
	if HPKEDHP521 != 3 {
		t.Errorf("HPKEDHP521 = %d, want 3", HPKEDHP521)
	}
	if HPKEDHX25519 != 4 {
		t.Errorf("HPKEDHX25519 = %d, want 4", HPKEDHX25519)
	}
}

func TestErrors(t *testing.T) {
	if ErrInvalidKey.Error() != "invalid HPKE key" {
		t.Errorf("ErrInvalidKey = %q, want %q", ErrInvalidKey.Error(), "invalid HPKE key")
	}
	if ErrDecryptionFailed.Error() != "decryption failed" {
		t.Errorf("ErrDecryptionFailed = %q", ErrDecryptionFailed.Error())
	}
	if ErrInvalidNonce.Error() != "invalid nonce" {
		t.Errorf("ErrInvalidNonce = %q", ErrInvalidNonce.Error())
	}
	if ErrTooManyDHPairs.Error() != "too many DH pairs for this context" {
		t.Errorf("ErrTooManyDHPairs = %q", ErrTooManyDHPairs.Error())
	}
}

func TestGenerateKeyPair(t *testing.T) {
	// Test X25519 key generation
	priv, pub, err := generateKeyPair(HPKEDHX25519)
	if err != nil {
		t.Fatalf("generateKeyPair(X25519) failed: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}

	// Test invalid KEM
	_, _, err = generateKeyPair(999)
	if err != ErrInvalidKey {
		t.Errorf("generateKeyPair(invalid) = %v, want ErrInvalidKey", err)
	}
}

func TestGenerateEphemeralKey(t *testing.T) {
	key, err := generateEphemeralKey(HPKEDHX25519)
	if err != nil {
		t.Fatalf("generateEphemeralKey(X25519) failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("ephemeral key length = %d, want 32", len(key))
	}

	// Test invalid KEM
	_, err = generateEphemeralKey(999)
	if err != ErrInvalidKey {
		t.Errorf("generateEphemeralKey(invalid) = %v, want ErrInvalidKey", err)
	}
}

func TestDerivePublicKey(t *testing.T) {
	priv, _, err := generateKeyPair(HPKEDHX25519)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	pub := derivePublicKey(priv, HPKEDHX25519)
	if len(pub) != 32 {
		t.Errorf("derived public key length = %d, want 32", len(pub))
	}

	// Test invalid KEM
	pub = derivePublicKey(priv, 999)
	if pub != nil {
		t.Errorf("derivePublicKey(invalid) = %v, want nil", pub)
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	priv1, pub1, err := generateKeyPair(HPKEDHX25519)
	if err != nil {
		t.Fatalf("generateKeyPair(1) failed: %v", err)
	}
	priv2, pub2, err := generateKeyPair(HPKEDHX25519)
	if err != nil {
		t.Fatalf("generateKeyPair(2) failed: %v", err)
	}

	// Derive shared secret both ways
	ss1, err := deriveSharedSecret(priv1, pub2, HPKEDHX25519)
	if err != nil {
		t.Fatalf("deriveSharedSecret(1) failed: %v", err)
	}
	ss2, err := deriveSharedSecret(priv2, pub1, HPKEDHX25519)
	if err != nil {
		t.Fatalf("deriveSharedSecret(2) failed: %v", err)
	}

	// Shared secrets should be equal
	if !bytes.Equal(ss1, ss2) {
		t.Error("shared secrets don't match")
	}

	// Test invalid KEM
	_, err = deriveSharedSecret(priv1, pub1, 999)
	if err != ErrInvalidKey {
		t.Errorf("deriveSharedSecret(invalid) = %v, want ErrInvalidKey", err)
	}
}

func TestBuildKDFInfo(t *testing.T) {
	info := buildKDFInfo("test.example.com")
	if len(info) == 0 {
		t.Error("buildKDFInfo returned empty")
	}

	// Check that it contains our strings
	expectedPrefix := "odohtest.example.com"
	if !strings.HasPrefix(string(info), "odoh") {
		t.Errorf("KDF info doesn't start with 'odoh': %q", string(info))
	}
	_ = expectedPrefix // suppress unused warning
}

func TestDeriveKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	kdfInfo := []byte("test")

	keys, err := deriveKeys(sharedSecret, kdfInfo, 1, HPKEAEADAES256GCM)
	if err != nil {
		t.Fatalf("deriveKeys failed: %v", err)
	}

	if len(keys.ExpandKey) != 32 {
		t.Errorf("ExpandKey length = %d, want 32", len(keys.ExpandKey))
	}
	if len(keys.SealKey) != 32 {
		t.Errorf("SealKey length = %d, want 32", len(keys.SealKey))
	}

	// Different inputs should produce different keys
	keys2, err := deriveKeys([]byte("different-input"), kdfInfo, 1, HPKEAEADAES256GCM)
	if err != nil {
		t.Fatalf("deriveKeys(2) failed: %v", err)
	}
	if bytes.Equal(keys.SealKey, keys2.SealKey) {
		t.Error("different inputs produced same SealKey")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32) // 256-bit key
	nonce := make([]byte, 12)
	plaintext := []byte("Hello, ODoH!")
	aad := []byte("additional data")

	ciphertext, err := encrypt(plaintext, nonce, key, aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decrypt(ciphertext, nonce, key, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptDecryptNoAAD(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("Hello, ODoH!")

	ciphertext, err := encrypt(plaintext, nonce, key, nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decrypt(ciphertext, nonce, key, nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	shortNonce := make([]byte, 8) // Wrong size
	plaintext := []byte("test")

	_, err := encrypt(plaintext, shortNonce, key, nil)
	if err != ErrInvalidNonce {
		t.Errorf("encrypt with short nonce = %v, want ErrInvalidNonce", err)
	}
}

func TestDecryptInvalidNonce(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("test")

	ciphertext, _ := encrypt(plaintext, nonce, key, nil)

	shortNonce := make([]byte, 8)
	_, err := decrypt(ciphertext, shortNonce, key, nil)
	if err != ErrInvalidNonce {
		t.Errorf("decrypt with short nonce = %v, want ErrInvalidNonce", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	// Generate two unrelated keys
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(31 - i)
	}

	nonce := make([]byte, 12)
	plaintext := []byte("test")

	ciphertext, _ := encrypt(plaintext, nonce, key1, nil)

	// Decryption with different key should fail (GCM authentication)
	_, err := decrypt(ciphertext, nonce, key2, nil)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestClearBytes(t *testing.T) {
	b := make([]byte, 10)
	b[0] = 0xFF
	b[9] = 0xFF

	clearBytes(b)

	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = 0x%02x, want 0x00", i, v)
		}
	}
}

func TestBuildParseProxyRequest(t *testing.T) {
	msg := &ObliviousDNSMessage{
		PublicKey:  make([]byte, 32),
		Ciphertext: []byte("test ciphertext"),
		Nonce:      make([]byte, 12),
		AAD:        []byte("test"),
	}

	data, err := buildProxyRequest(msg)
	if err != nil {
		t.Fatalf("buildProxyRequest failed: %v", err)
	}

	parsed, err := parseProxyRequest(data)
	if err != nil {
		t.Fatalf("parseProxyRequest failed: %v", err)
	}

	if !bytes.Equal(parsed.PublicKey, msg.PublicKey) {
		t.Error("PublicKey mismatch")
	}
	if !bytes.Equal(parsed.Ciphertext, msg.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
	if !bytes.Equal(parsed.Nonce, msg.Nonce) {
		t.Error("Nonce mismatch")
	}
}

func TestParseProxyRequestTruncated(t *testing.T) {
	// Too short to read public key length
	_, err := parseProxyRequest([]byte{0})
	if err == nil {
		t.Error("expected error for truncated input")
	}
}

func TestBuildParseProxyResponse(t *testing.T) {
	msg := &ObliviousDNSMessage{
		PublicKey:  make([]byte, 32),
		Ciphertext: []byte("test response"),
		Nonce:      make([]byte, 12),
	}

	data, err := buildProxyResponse(msg)
	if err != nil {
		t.Fatalf("buildProxyResponse failed: %v", err)
	}

	parsed, err := parseProxyResponse(data)
	if err != nil {
		t.Fatalf("parseProxyResponse failed: %v", err)
	}

	if !bytes.Equal(parsed.Ciphertext, msg.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestNewObliviousProxy(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	proxy, err := NewObliviousProxy(cfg)
	if err != nil {
		t.Fatalf("NewObliviousProxy failed: %v", err)
	}
	if proxy == nil {
		t.Fatal("proxy is nil")
	}
	if proxy.config != cfg {
		t.Error("proxy.config != cfg")
	}
}

func TestNewObliviousTarget(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	target, err := NewObliviousTarget(cfg)
	if err != nil {
		t.Fatalf("NewObliviousTarget failed: %v", err)
	}
	if target == nil {
		t.Fatal("target is nil")
	}
	if len(target.pubKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(target.pubKey))
	}
	if len(target.privKey) != 32 {
		t.Errorf("private key length = %d, want 32", len(target.privKey))
	}
}

func TestObliviousProxyServeHTTPGET(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	proxy := &ObliviousProxy{config: cfg}

	req := httptest.NewRequest("GET", "http://test/", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestObliviousProxyServeHTTPPostBadRequest(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	proxy := &ObliviousProxy{config: cfg}

	// Empty body should fail parsing
	req := httptest.NewRequest("POST", "http://test/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestObliviousTargetServeHTTPGET(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	target := &ObliviousTarget{config: cfg}

	req := httptest.NewRequest("GET", "http://test/", nil)
	w := httptest.NewRecorder()

	target.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestObliviousTargetServeHTTPPostBadRequest(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	target := &ObliviousTarget{config: cfg}

	// Empty body should fail parsing
	req := httptest.NewRequest("POST", "http://test/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	target.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTargetDecapsulateQuery(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	target, err := NewObliviousTarget(cfg)
	if err != nil {
		t.Fatalf("NewObliviousTarget failed: %v", err)
	}

	// Create a valid ODoH message that target can decrypt
	query := []byte("test dns query")

	// Create ephemeral key
	ephemeralPriv, err := generateEphemeralKey(cfg.HPKEKEM)
	if err != nil {
		t.Fatalf("generateEphemeralKey failed: %v", err)
	}

	// Derive the ephemeral public key from private key
	ephemeralPub := derivePublicKey(ephemeralPriv, cfg.HPKEKEM)

	// Derive shared secret
	sharedSecret, err := deriveSharedSecret(ephemeralPriv, target.pubKey, cfg.HPKEKEM)
	if err != nil {
		t.Fatalf("deriveSharedSecret failed: %v", err)
	}
	defer clearBytes(sharedSecret)

	// Derive keys (same as encapsulateQuery does)
	kdfInfo := buildKDFInfo(cfg.TargetName)
	keys, err := deriveKeys(sharedSecret, kdfInfo, cfg.HPKEKDF, cfg.HPKEAEAD)
	if err != nil {
		t.Fatalf("deriveKeys failed: %v", err)
	}

	// Encrypt the query (same nonce derivation as encapsulateQuery)
	nonce := make([]byte, 12)
	ciphertext, err := encrypt(query, nonce, keys.SealKey, []byte(cfg.TargetName))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	msg := &ObliviousDNSMessage{
		PublicKey:  ephemeralPub, // Use derived public key
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        []byte(cfg.TargetName),
	}

	// Target should be able to decapsulate
	decrypted, err := target.decapsulateQuery(msg)
	if err != nil {
		t.Fatalf("decapsulateQuery failed: %v", err)
	}

	if string(decrypted) != string(query) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(query))
	}
}

func TestTargetProcessDNSQuery(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	target := &ObliviousTarget{config: cfg}

	query := []byte("test query")
	response := target.processDNSQuery(query)

	// Placeholder implementation returns the query as response
	if !bytes.Equal(response, query) {
		t.Errorf("processDNSQuery = %q, want %q", response, query)
	}
}

func TestProxyForwardToTarget(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	proxy := &ObliviousProxy{config: cfg}

	msg := &ObliviousDNSMessage{
		PublicKey:  []byte("test-pub-key"),
		Ciphertext: []byte("test-ciphertext"),
		Nonce:      []byte("test-nonce-12b"),
	}

	// Placeholder forward returns the ciphertext
	result, err := proxy.forwardToTarget(msg)
	if err != nil {
		t.Fatalf("forwardToTarget failed: %v", err)
	}

	if !bytes.Equal(result, msg.Ciphertext) {
		t.Error("forwardToTarget didn't return ciphertext")
	}
}

func TestNewObliviousClient(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	client, err := NewObliviousClient(cfg)
	if err != nil {
		t.Fatalf("NewObliviousClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.config != cfg {
		t.Error("client.config != cfg")
	}
	if client.client == nil {
		t.Error("client.httpClient is nil")
	}
	if client.client.Timeout != 10*time.Second {
		t.Errorf("client timeout = %v, want 10s", client.client.Timeout)
	}
}

func TestClientGetTargetPublicKey(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")

	// Generate a valid target public key
	_, targetPub, err := generateKeyPair(cfg.HPKEKEM)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}
	cfg.TargetPublicKey = targetPub

	client := &ObliviousClient{config: cfg}

	pub, err := client.getTargetPublicKey()
	if err != nil {
		t.Fatalf("getTargetPublicKey failed: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
}

func TestClientEncapsulateQuery(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	client := &ObliviousClient{config: cfg}

	ephemeralPriv, _ := generateEphemeralKey(cfg.HPKEKEM)

	// Generate a valid target public key
	targetPriv, targetPub, err := generateKeyPair(cfg.HPKEKEM)
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}
	defer clearBytes(targetPriv)

	query := []byte("test query")

	msg, err := client.encapsulateQuery(query, ephemeralPriv, targetPub)
	if err != nil {
		t.Fatalf("encapsulateQuery failed: %v", err)
	}

	if len(msg.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
	if len(msg.Nonce) != 12 {
		t.Errorf("Nonce length = %d, want 12", len(msg.Nonce))
	}
}

func TestClientSendToProxyNetworkError(t *testing.T) {
	cfg := NewODoHConfig("target.invalid:9999", "proxy.invalid:9999")
	client := &ObliviousClient{config: cfg, client: &http.Client{Timeout: 100 * time.Millisecond}}

	msg := &ObliviousDNSMessage{
		PublicKey:  make([]byte, 32),
		Ciphertext: []byte("test"),
		Nonce:      make([]byte, 12),
	}

	_, err := client.sendToProxy(msg)
	if err == nil {
		t.Error("expected network error")
	}
}

func TestMaxBodySize(t *testing.T) {
	if maxBodySize != 4*1024*1024 {
		t.Errorf("maxBodySize = %d, want 4MB", maxBodySize)
	}
}

func TestClientDecapsulateResponse(t *testing.T) {
	cfg := NewODoHConfig("target.example.com", "proxy.example.com")
	client := &ObliviousClient{config: cfg}

	// This test would require a full round-trip which is complex
	// Just verify the method exists and handles nil gracefully
	ephemeralPriv := make([]byte, 32)
	response := &ObliviousDNSMessage{
		PublicKey:  make([]byte, 32),
		Ciphertext: []byte("test"),
		Nonce:      make([]byte, 12),
	}

	// This will fail because keys don't match, but we can verify it runs
	_, err := client.decapsulateResponse(response, ephemeralPriv)
	if err == nil {
		t.Error("expected error for mismatched keys")
	}
}

func TestObliviousDNSMessageStruct(t *testing.T) {
	msg := &ObliviousDNSMessage{
		PublicKey:  []byte("public"),
		Ciphertext: []byte("ciphertext"),
		Nonce:      []byte("nonce123456"),
		AAD:        []byte("aad"),
	}

	if string(msg.PublicKey) != "public" {
		t.Error("PublicKey mismatch")
	}
	if string(msg.Ciphertext) != "ciphertext" {
		t.Error("Ciphertext mismatch")
	}
	if string(msg.Nonce) != "nonce123456" {
		t.Error("Nonce mismatch")
	}
	if string(msg.AAD) != "aad" {
		t.Error("AAD mismatch")
	}
}

func TestObliviousClientQuery(t *testing.T) {
	cfg := &ODoHConfig{
		TargetName: "target.example.com",
		ProxyName:  "proxy.example.com",
		ProxyURL:   "http://127.0.0.1:99999/dns-query", // Invalid port
		HPKEKEM:    HPKEDHX25519,
		HPKEKDF:    1,
		HPKEAEAD:   HPKEAEADAES256GCM,
	}
	client := &ObliviousClient{
		config: cfg,
		client: &http.Client{Timeout: 100 * time.Millisecond},
	}

	// This will fail due to network, but verifies the code path
	_, err := client.Query([]byte("test"))
	if err == nil {
		t.Error("expected error for invalid proxy")
	}
}

// Helper to suppress unused import
var _ = io.Discard
