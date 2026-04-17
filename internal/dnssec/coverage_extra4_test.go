package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// Mock KeyStoreBackend
// ---------------------------------------------------------------------------

type mockBucket struct {
	data       map[string][]byte
	subBuckets map[string]*mockBucket
}

func newMockBucket() *mockBucket {
	return &mockBucket{
		data:       make(map[string][]byte),
		subBuckets: make(map[string]*mockBucket),
	}
}

func (b *mockBucket) Get(key []byte) []byte       { return b.data[string(key)] }
func (b *mockBucket) Put(key, value []byte) error  { b.data[string(key)] = value; return nil }
func (b *mockBucket) Delete(key []byte) error      { delete(b.data, string(key)); return nil }
func (b *mockBucket) ForEach(fn func(k, v []byte) error) error {
	for k, v := range b.data {
		if err := fn([]byte(k), v); err != nil {
			return err
		}
	}
	return nil
}
func (b *mockBucket) Bucket(name []byte) KeyStoreBucket {
	if sub, ok := b.subBuckets[string(name)]; ok {
		return sub
	}
	return nil
}
func (b *mockBucket) CreateBucket(name []byte) (KeyStoreBucket, error) {
	sub := newMockBucket()
	b.subBuckets[string(name)] = sub
	return sub, nil
}
func (b *mockBucket) CreateBucketIfNotExists(name []byte) (KeyStoreBucket, error) {
	if sub, ok := b.subBuckets[string(name)]; ok {
		return sub, nil
	}
	return b.CreateBucket(name)
}
func (b *mockBucket) DeleteBucket(name []byte) error {
	delete(b.subBuckets, string(name))
	return nil
}

type mockTx struct {
	root *mockBucket
}

func (tx *mockTx) Bucket(name []byte) KeyStoreBucket        { return tx.root.Bucket(name) }
func (tx *mockTx) CreateBucketIfNotExists(name []byte) (KeyStoreBucket, error) {
	return tx.root.CreateBucketIfNotExists(name)
}

type mockBackend struct {
	root *mockBucket
}

func newMockBackend() *mockBackend {
	return &mockBackend{root: newMockBucket()}
}

func (m *mockBackend) Update(fn func(tx KeyStoreTx) error) error {
	return fn(&mockTx{root: m.root})
}

func (m *mockBackend) View(fn func(tx KeyStoreTx) error) error {
	return fn(&mockTx{root: m.root})
}

// ---------------------------------------------------------------------------
// NewKeyStore
// ---------------------------------------------------------------------------

func TestNewKeyStore(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	if ks == nil {
		t.Fatal("expected non-nil KeyStore")
	}
}

// ---------------------------------------------------------------------------
// NewKeyStoreWithEncryption
// ---------------------------------------------------------------------------

func TestNewKeyStoreWithEncryption_Valid(t *testing.T) {
	key := make([]byte, 32)
	ks, err := NewKeyStoreWithEncryption(newMockBackend(), key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks == nil {
		t.Fatal("expected non-nil KeyStore")
	}
}

func TestNewKeyStoreWithEncryption_InvalidSize(t *testing.T) {
	_, err := NewKeyStoreWithEncryption(newMockBackend(), []byte("short"))
	if err == nil {
		t.Error("expected error for short encryption key")
	}
}

// VULN-038 regression: constructor must copy the caller's key bytes.
// Pre-fix, the buffer was allocated but never populated, so AES-256 ran with
// an all-zero key regardless of what the caller passed.
func TestNewKeyStoreWithEncryption_StoresKeyBytes(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i + 1) // deliberately non-zero
	}

	ks, err := NewKeyStoreWithEncryption(newMockBackend(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ks.mu.RLock()
	stored := make([]byte, len(ks.encryptionKey))
	copy(stored, ks.encryptionKey)
	ks.mu.RUnlock()

	for i := range input {
		if stored[i] != input[i] {
			t.Fatalf("stored key byte %d = %d, want %d (constructor did not copy key)",
				i, stored[i], input[i])
		}
	}
}

// VULN-038 regression: constructor must make a defensive copy so that
// mutating the caller's slice after construction does not change the stored key.
func TestNewKeyStoreWithEncryption_DefensiveCopy(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i + 1)
	}

	ks, err := NewKeyStoreWithEncryption(newMockBackend(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the caller's slice after construction; stored key must not change.
	for i := range input {
		input[i] = 0xFF
	}

	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for i := range ks.encryptionKey {
		if ks.encryptionKey[i] == 0xFF {
			t.Fatalf("stored key was aliased with caller slice (byte %d = 0xFF)", i)
		}
	}
}

// ---------------------------------------------------------------------------
// SetEncryptionKey
// ---------------------------------------------------------------------------

func TestKeyStore_SetEncryptionKey(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	key := make([]byte, 32)
	ks.SetEncryptionKey(key)

	ks.mu.RLock()
	hasKey := ks.encryptionKey != nil
	ks.mu.RUnlock()

	if !hasKey {
		t.Error("expected encryption key to be set")
	}
}

// ---------------------------------------------------------------------------
// encryptPrivateKey / decryptPrivateKey roundtrip
// ---------------------------------------------------------------------------

func TestKeyStore_EncryptDecryptRoundtrip_NoKey(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	plaintext := []byte("hello world")

	encrypted, err := ks.encryptPrivateKey(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Without encryption key, should return plaintext unchanged
	if string(encrypted) != string(plaintext) {
		t.Error("expected plaintext unchanged without encryption key")
	}

	decrypted, err := ks.decryptPrivateKey(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("expected decrypted == plaintext")
	}
}

func TestKeyStore_EncryptDecryptRoundtrip_WithKey(t *testing.T) {
	key := make([]byte, 32)
	ks, _ := NewKeyStoreWithEncryption(newMockBackend(), key)
	plaintext := []byte("secret private key data")

	encrypted, err := ks.encryptPrivateKey(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(encrypted) == string(plaintext) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := ks.decryptPrivateKey(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("decrypted should match original plaintext")
	}
}

func TestKeyStore_DecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	ks, _ := NewKeyStoreWithEncryption(newMockBackend(), key)

	_, err := ks.decryptPrivateKey([]byte("short"))
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
}

func TestKeyStore_DecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	ks, _ := NewKeyStoreWithEncryption(newMockBackend(), key)

	plaintext := []byte("secret data")
	encrypted, _ := ks.encryptPrivateKey(plaintext)

	// Tamper with the ciphertext
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := ks.decryptPrivateKey(encrypted)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

// ---------------------------------------------------------------------------
// encodeStoredKey / decodeStoredKey roundtrip
// ---------------------------------------------------------------------------

func TestEncodeDecodeStoredKey(t *testing.T) {
	sk := &StoredKey{
		KeyTag:         12345,
		Algorithm:      protocol.AlgorithmECDSAP256SHA256,
		Flags:          257,
		IsKSK:          true,
		IsZSK:          false,
		PublicKeyData:  []byte("public-key-data"),
		PrivateKeyData: []byte("private-key-data"),
	}

	encoded := encodeStoredKey(sk)
	decoded, err := decodeStoredKey(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.KeyTag != sk.KeyTag {
		t.Errorf("KeyTag: got %d, want %d", decoded.KeyTag, sk.KeyTag)
	}
	if decoded.Algorithm != sk.Algorithm {
		t.Errorf("Algorithm: got %d, want %d", decoded.Algorithm, sk.Algorithm)
	}
	if decoded.Flags != sk.Flags {
		t.Errorf("Flags: got %d, want %d", decoded.Flags, sk.Flags)
	}
	if decoded.IsKSK != sk.IsKSK {
		t.Errorf("IsKSK: got %v, want %v", decoded.IsKSK, sk.IsKSK)
	}
	if decoded.IsZSK != sk.IsZSK {
		t.Errorf("IsZSK: got %v, want %v", decoded.IsZSK, sk.IsZSK)
	}
	if string(decoded.PublicKeyData) != string(sk.PublicKeyData) {
		t.Error("PublicKeyData mismatch")
	}
	if string(decoded.PrivateKeyData) != string(sk.PrivateKeyData) {
		t.Error("PrivateKeyData mismatch")
	}
}

func TestDecodeStoredKey_TooShort(t *testing.T) {
	_, err := decodeStoredKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestDecodeStoredKey_TruncatedPubkeyLen(t *testing.T) {
	// 9 bytes header but pubkey length field points beyond data
	data := make([]byte, 9)
	data[6] = 0xFF // pubkey len high byte
	data[7] = 0xFF // pubkey len low byte
	_, err := decodeStoredKey(data)
	if err == nil {
		t.Error("expected error for truncated pubkey length")
	}
}

// ---------------------------------------------------------------------------
// marshalPrivateKey / unmarshalPrivateKey roundtrip
// ---------------------------------------------------------------------------

func TestMarshalUnmarshal_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pk := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA256, Key: rsaKey}
	data, err := marshalPrivateKey(pk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := unmarshalPrivateKey(protocol.AlgorithmRSASHA256, data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Algorithm != protocol.AlgorithmRSASHA256 {
		t.Errorf("algorithm = %d, want %d", restored.Algorithm, protocol.AlgorithmRSASHA256)
	}
}

func TestMarshalUnmarshal_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	pk := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: ecKey}
	data, err := marshalPrivateKey(pk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := unmarshalPrivateKey(protocol.AlgorithmECDSAP256SHA256, data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Errorf("algorithm = %d, want %d", restored.Algorithm, protocol.AlgorithmECDSAP256SHA256)
	}
}

func TestMarshalUnmarshal_Ed25519(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	pk := &PrivateKey{Algorithm: protocol.AlgorithmED25519, Key: privKey}
	data, err := marshalPrivateKey(pk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := unmarshalPrivateKey(protocol.AlgorithmED25519, data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Algorithm != protocol.AlgorithmED25519 {
		t.Errorf("algorithm = %d, want %d", restored.Algorithm, protocol.AlgorithmED25519)
	}
}

func TestMarshalPrivateKey_Unsupported(t *testing.T) {
	_, err := marshalPrivateKey(&PrivateKey{Algorithm: 255, Key: "not a key"})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestUnmarshalPrivateKey_UnsupportedAlgorithm(t *testing.T) {
	_, err := unmarshalPrivateKey(255, []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestUnmarshalPrivateKey_Ed25519WrongSize(t *testing.T) {
	_, err := unmarshalPrivateKey(protocol.AlgorithmED25519, []byte("too short"))
	if err == nil {
		t.Error("expected error for wrong Ed25519 key size")
	}
}

// ---------------------------------------------------------------------------
// serializeSigningKey
// ---------------------------------------------------------------------------

func TestSerializeSigningKey(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	stored, err := serializeSigningKey(key)
	if err != nil {
		t.Fatalf("serializeSigningKey: %v", err)
	}
	if stored == nil {
		t.Fatal("expected non-nil StoredKey")
	}
	if stored.KeyTag != key.KeyTag {
		t.Errorf("KeyTag = %d, want %d", stored.KeyTag, key.KeyTag)
	}
	if stored.IsZSK != true {
		t.Error("expected IsZSK=true")
	}
}

// ---------------------------------------------------------------------------
// GeneratePublicKeyData
// ---------------------------------------------------------------------------

func TestGeneratePublicKeyData_RSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pk := &PrivateKey{Algorithm: protocol.AlgorithmRSASHA256, Key: rsaKey}

	data, err := GeneratePublicKeyData(protocol.AlgorithmRSASHA256, pk)
	if err != nil {
		t.Fatalf("GeneratePublicKeyData RSA: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty public key data")
	}
}

func TestGeneratePublicKeyData_ECDSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := &PrivateKey{Algorithm: protocol.AlgorithmECDSAP256SHA256, Key: ecKey}

	data, err := GeneratePublicKeyData(protocol.AlgorithmECDSAP256SHA256, pk)
	if err != nil {
		t.Fatalf("GeneratePublicKeyData ECDSA: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty public key data")
	}
}

func TestGeneratePublicKeyData_Ed25519(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pk := &PrivateKey{Algorithm: protocol.AlgorithmED25519, Key: privKey}

	data, err := GeneratePublicKeyData(protocol.AlgorithmED25519, pk)
	if err != nil {
		t.Fatalf("GeneratePublicKeyData Ed25519: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty public key data")
	}
}

func TestGeneratePublicKeyData_Unsupported(t *testing.T) {
	_, err := GeneratePublicKeyData(255, &PrivateKey{Algorithm: 255, Key: "bad"})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// ---------------------------------------------------------------------------
// RestoreSigningKey
// ---------------------------------------------------------------------------

func TestRestoreSigningKey(t *testing.T) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	stored, err := serializeSigningKey(key)
	if err != nil {
		t.Fatalf("serializeSigningKey: %v", err)
	}

	restored, err := RestoreSigningKey(stored)
	if err != nil {
		t.Fatalf("RestoreSigningKey: %v", err)
	}
	if restored.KeyTag != key.KeyTag {
		t.Errorf("KeyTag = %d, want %d", restored.KeyTag, key.KeyTag)
	}
	if restored.State != KeyStateActive {
		t.Errorf("State = %d, want KeyStateActive", restored.State)
	}
}

func TestRestoreSigningKey_InvalidData(t *testing.T) {
	stored := &StoredKey{
		KeyTag:         1234,
		Algorithm:      255, // unsupported
		PrivateKeyData: []byte("garbage"),
	}
	_, err := RestoreSigningKey(stored)
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

// ---------------------------------------------------------------------------
// SaveKey / LoadKeys / DeleteKey roundtrip
// ---------------------------------------------------------------------------

func TestKeyStore_SaveLoadDeleteRoundtrip(t *testing.T) {
	backend := newMockBackend()
	ks := NewKeyStore(backend)

	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Save
	if err := ks.SaveKey("example.com.", key); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	// Load
	keys, err := ks.LoadKeys("example.com.")
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyTag != key.KeyTag {
		t.Errorf("KeyTag = %d, want %d", keys[0].KeyTag, key.KeyTag)
	}

	// Delete
	if err := ks.DeleteKey("example.com.", key.KeyTag); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Verify deleted
	keys2, err := ks.LoadKeys("example.com.")
	if err != nil {
		t.Fatalf("LoadKeys after delete: %v", err)
	}
	if len(keys2) != 0 {
		t.Errorf("expected 0 keys after delete, got %d", len(keys2))
	}
}

func TestKeyStore_LoadKeys_NoZone(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	_, err := ks.LoadKeys("nonexistent.com.")
	if !errors.Is(err, ErrNoKeysForZone) {
		t.Errorf("expected ErrNoKeysForZone, got %v", err)
	}
}

func TestKeyStore_DeleteKey_NoZone(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	err := ks.DeleteKey("nonexistent.com.", 1234)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SaveKey / LoadKeys with encryption
// ---------------------------------------------------------------------------

func TestKeyStore_SaveLoadWithEncryption(t *testing.T) {
	encKey := make([]byte, 32)
	ks, _ := NewKeyStoreWithEncryption(newMockBackend(), encKey)

	s := NewSigner("example.com.", DefaultSignerConfig())
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true)

	if err := ks.SaveKey("example.com.", key); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	keys, err := ks.LoadKeys("example.com.")
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Restore and verify it works
	restored, err := RestoreSigningKey(keys[0])
	if err != nil {
		t.Fatalf("RestoreSigningKey: %v", err)
	}
	if restored.KeyTag != key.KeyTag {
		t.Errorf("KeyTag mismatch: got %d, want %d", restored.KeyTag, key.KeyTag)
	}
}

// ---------------------------------------------------------------------------
// DeleteZoneKeys
// ---------------------------------------------------------------------------

func TestKeyStore_DeleteZoneKeys(t *testing.T) {
	backend := newMockBackend()
	ks := NewKeyStore(backend)

	s := NewSigner("example.com.", DefaultSignerConfig())
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	ks.SaveKey("example.com.", key)

	if err := ks.DeleteZoneKeys("example.com."); err != nil {
		t.Fatalf("DeleteZoneKeys: %v", err)
	}

	_, err := ks.LoadKeys("example.com.")
	if !errors.Is(err, ErrNoKeysForZone) {
		t.Errorf("expected ErrNoKeysForZone after DeleteZoneKeys, got %v", err)
	}
}

func TestKeyStore_DeleteZoneKeys_NoExisting(t *testing.T) {
	ks := NewKeyStore(newMockBackend())
	// Should not error on nonexistent zone
	if err := ks.DeleteZoneKeys("nonexistent.com."); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DNSSECStatus
// ---------------------------------------------------------------------------

func TestValidator_DNSSECStatus(t *testing.T) {
	v := &Validator{
		config: ValidatorConfig{
			Enabled:       true,
			RequireDNSSEC: true,
		},
		trustAnchors:    NewTrustAnchorStore(),
		validationCache: NewValidationCache(5 * time.Minute),
	}

	status := v.DNSSECStatus()
	if !status.Enabled {
		t.Error("expected Enabled=true")
	}
	if !status.RequireDNSSEC {
		t.Error("expected RequireDNSSEC=true")
	}
}

func TestValidator_DNSSECStatus_Disabled(t *testing.T) {
	v := &Validator{
		config: ValidatorConfig{
			Enabled:       false,
			RequireDNSSEC: false,
		},
		trustAnchors:    NewTrustAnchorStore(),
		validationCache: NewValidationCache(5 * time.Minute),
	}

	status := v.DNSSECStatus()
	if status.Enabled {
		t.Error("expected Enabled=false")
	}
}

// ---------------------------------------------------------------------------
// transitionKey (via RolloverScheduler)
// ---------------------------------------------------------------------------

func newTestRolloverScheduler() (*RolloverScheduler, *Signer) {
	s := NewSigner("example.com.", DefaultSignerConfig())
	cfg := RolloverConfig{
		Enabled:       true,
		ZSKLifetime:   30 * 24 * time.Hour,
		KSKLifetime:   365 * 24 * time.Hour,
		PublishSafety: 1 * time.Hour,
		RetireSafety:  1 * time.Hour,
		Algorithm:     protocol.AlgorithmECDSAP256SHA256,
		CheckInterval: 1 * time.Hour,
	}
	rs := &RolloverScheduler{
		signer: s,
		config: cfg,
		logger: func(string, ...interface{}) {},
	}
	return rs, s
}

func TestRolloverScheduler_TransitionKey_CreatedToPublished(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	now := time.Now()
	key.Timing = &KeyTiming{
		Created: now.Add(-2 * time.Hour),
		Publish: now.Add(-1 * time.Hour),
		Active:  now.Add(1 * time.Hour),
	}
	key.State = KeyStateCreated

	rs.transitionKey(key, now)

	if key.State != KeyStatePublished {
		t.Errorf("expected Published, got %d", key.State)
	}
}

func TestRolloverScheduler_TransitionKey_PublishedToActive(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	now := time.Now()
	key.Timing = &KeyTiming{
		Created: now.Add(-3 * time.Hour),
		Publish: now.Add(-2 * time.Hour),
		Active:  now.Add(-1 * time.Hour),
	}
	key.State = KeyStatePublished

	rs.transitionKey(key, now)

	if key.State != KeyStateActive {
		t.Errorf("expected Active, got %d", key.State)
	}
}

func TestRolloverScheduler_TransitionKey_ActiveToRetired(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	now := time.Now()
	key.Timing = &KeyTiming{
		Created: now.Add(-100 * time.Hour),
		Publish: now.Add(-99 * time.Hour),
		Active:  now.Add(-98 * time.Hour),
		Retire:  now.Add(-1 * time.Hour),
	}
	key.State = KeyStateActive

	rs.transitionKey(key, now)

	if key.State != KeyStateRetired {
		t.Errorf("expected Retired, got %d", key.State)
	}
}

func TestRolloverScheduler_TransitionKey_RetiredToDead(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	now := time.Now()
	key.Timing = &KeyTiming{
		Retire: now.Add(-100 * time.Hour),
		Remove: now.Add(-1 * time.Hour),
	}
	key.State = KeyStateRetired

	rs.transitionKey(key, now)

	if key.State != KeyStateDead {
		t.Errorf("expected Dead, got %d", key.State)
	}
}

func TestRolloverScheduler_TransitionKey_EmptyTiming(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	// Timing exists but all fields are zero — IsZero() checks should prevent transitions
	key.Timing = &KeyTiming{}
	key.State = KeyStateCreated

	rs.transitionKey(key, time.Now())

	// Should remain Created since all timing fields are zero
	if key.State != KeyStateCreated {
		t.Errorf("expected state unchanged (Created), got %d", key.State)
	}
}

func TestRolloverScheduler_TransitionKey_NotYetTime(t *testing.T) {
	rs, s := newTestRolloverScheduler()
	key, _ := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false)
	now := time.Now()
	key.Timing = &KeyTiming{
		Created: now,
		Publish: now.Add(1 * time.Hour), // future
		Active:  now.Add(2 * time.Hour),
	}
	key.State = KeyStateCreated

	rs.transitionKey(key, now)

	// Should remain Created since publish time is in the future
	if key.State != KeyStateCreated {
		t.Errorf("expected state unchanged (Created), got %d", key.State)
	}
}

// ---------------------------------------------------------------------------
// marshalRSAPublicKey — large exponent branch
// ---------------------------------------------------------------------------

func TestMarshalRSAPublicKey_LargeExponent(t *testing.T) {
	// Generate RSA key with a large exponent (> 255 bytes won't happen with standard GenerateKey,
	// but we can test the normal path)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}

	data := marshalRSAPublicKey(&rsaKey.PublicKey)
	if len(data) == 0 {
		t.Error("expected non-empty RSA public key data")
	}
}

// ---------------------------------------------------------------------------
// marshalECDSAPublicKey
// ---------------------------------------------------------------------------

func TestMarshalECDSAPublicKey_P256(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data, err := marshalECDSAPublicKey(protocol.AlgorithmECDSAP256SHA256, &ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal P256: %v", err)
	}
	if len(data) != 64 { // 32 + 32 bytes
		t.Errorf("expected 64 bytes for P256, got %d", len(data))
	}
}

func TestMarshalECDSAPublicKey_P384(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	data, err := marshalECDSAPublicKey(protocol.AlgorithmECDSAP384SHA384, &ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal P384: %v", err)
	}
	if len(data) != 96 { // 48 + 48 bytes
		t.Errorf("expected 96 bytes for P384, got %d", len(data))
	}
}

func TestMarshalECDSAPublicKey_UnsupportedAlgorithm(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := marshalECDSAPublicKey(255, &ecKey.PublicKey)
	if err == nil {
		t.Error("expected error for unsupported ECDSA algorithm")
	}
}

// ---------------------------------------------------------------------------
// SaveKey error paths
// ---------------------------------------------------------------------------

func TestKeyStore_SaveKey_SerializationError(t *testing.T) {
	ks := NewKeyStore(newMockBackend())

	// Create a key with an unsupported private key type
	key := &SigningKey{
		PrivateKey: &PrivateKey{Algorithm: 255, Key: "not-a-real-key"},
		DNSKEY:     &protocol.RDataDNSKEY{Algorithm: 255},
		KeyTag:     1234,
		IsZSK:      true,
	}

	err := ks.SaveKey("example.com.", key)
	if err == nil {
		t.Error("expected error for unsupported key type in SaveKey")
	}
}

// ---------------------------------------------------------------------------
// Set struct helpers
// ---------------------------------------------------------------------------

func TestStoredKey_Fields(t *testing.T) {
	sk := &StoredKey{
		KeyTag:         12345,
		Algorithm:      8,
		Flags:          256,
		IsKSK:          false,
		IsZSK:          true,
		PublicKeyData:  []byte{1, 2, 3},
		PrivateKeyData: []byte{4, 5, 6},
	}

	encoded := encodeStoredKey(sk)
	decoded, err := decodeStoredKey(encoded)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}

	if fmt.Sprintf("%+v", decoded.KeyTag) != fmt.Sprintf("%+v", sk.KeyTag) {
		t.Errorf("roundtrip mismatch")
	}
}
