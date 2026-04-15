// Package dnssec — KeyStore provides persistent DNSSEC key storage.
//
// Keys are stored in a KVStore bucket named "dnssec_keys" with one
// sub-bucket per zone. Each key is identified by its keytag and stored
// as a base64-encoded BIND private key format.
package dnssec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// KeyStore provides persistent storage for DNSSEC signing keys.
// When an encryption key is provided, private key material is encrypted at rest
// using AES-256-GCM. Public key data is stored unencrypted.
type KeyStore struct {
	// store provides bucket-based KV operations. We accept an interface
	// to avoid a circular import with the storage package.
	store         KeyStoreBackend
	mu            sync.RWMutex
	encryptionKey []byte // AES-256 key for encrypting private keys at rest
}

// KeyStoreBackend abstracts the KVStore operations needed by KeyStore.
// This avoids importing the storage package directly.
type KeyStoreBackend interface {
	Update(fn func(tx KeyStoreTx) error) error
	View(fn func(tx KeyStoreTx) error) error
}

// KeyStoreTx abstracts a transaction for the KeyStore.
type KeyStoreTx interface {
	Bucket(name []byte) KeyStoreBucket
	CreateBucketIfNotExists(name []byte) (KeyStoreBucket, error)
}

// KeyStoreBucket abstracts a bucket for the KeyStore.
type KeyStoreBucket interface {
	Get(key []byte) []byte
	Put(key, value []byte) error
	Delete(key []byte) error
	Bucket(name []byte) KeyStoreBucket
	CreateBucket(name []byte) (KeyStoreBucket, error)
	CreateBucketIfNotExists(name []byte) (KeyStoreBucket, error)
	DeleteBucket(name []byte) error
	ForEach(fn func(k, v []byte) error) error
}

// StoredKey represents a DNSSEC key serialized for storage.
type StoredKey struct {
	KeyTag    uint16
	Algorithm uint8
	Flags     uint16 // DNSKEY flags (256 = ZSK, 257 = KSK)
	IsKSK     bool
	IsZSK     bool

	// Serialized key material
	PublicKeyData  []byte // Wire-format DNSKEY public key
	PrivateKeyData []byte // DER-encoded private key
}

var (
	// ErrKeyNotFound is returned when a key is not found in the store.
	ErrKeyNotFound = errors.New("DNSSEC key not found")
	// ErrNoKeysForZone is returned when no keys exist for a zone.
	ErrNoKeysForZone = errors.New("no DNSSEC keys for zone")
)

var keystoreBucket = []byte("dnssec_keys")

// NewKeyStore creates a KeyStore backed by the given store.
func NewKeyStore(store KeyStoreBackend) *KeyStore {
	return &KeyStore{store: store}
}

// NewKeyStoreWithEncryption creates a KeyStore that encrypts private key material at rest.
// The encryptionKey must be exactly 32 bytes (AES-256).
func NewKeyStoreWithEncryption(store KeyStoreBackend, encryptionKey []byte) (*KeyStore, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d", len(encryptionKey))
	}
	return &KeyStore{store: store, encryptionKey: make([]byte, len(encryptionKey))}, nil
}

// SetEncryptionKey enables or changes the encryption key for private keys at rest.
func (ks *KeyStore) SetEncryptionKey(key []byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.encryptionKey = make([]byte, len(key))
	copy(ks.encryptionKey, key)
}

// encryptPrivateKey encrypts private key data using AES-256-GCM.
// Format: nonce(12) + ciphertext+tag.
// Returns plaintext unchanged if no encryption key is set.
func (ks *KeyStore) encryptPrivateKey(plaintext []byte) ([]byte, error) {
	if len(ks.encryptionKey) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(ks.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Prepend nonce to ciphertext
	return append(nonce, aead.Seal(nil, nonce, plaintext, nil)...), nil
}

// decryptPrivateKey decrypts private key data encrypted with AES-256-GCM.
// Returns ciphertext unchanged if no encryption key is set.
func (ks *KeyStore) decryptPrivateKey(ciphertext []byte) ([]byte, error) {
	if len(ks.encryptionKey) == 0 {
		return ciphertext, nil
	}
	block, err := aes.NewCipher(ks.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}

// SaveKey persists a signing key for the given zone.
func (ks *KeyStore) SaveKey(zoneName string, key *SigningKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	stored, err := serializeSigningKey(key)
	if err != nil {
		return fmt.Errorf("serialize key: %w", err)
	}

	// Encrypt private key data at rest
	if len(ks.encryptionKey) > 0 {
		encrypted, encErr := ks.encryptPrivateKey(stored.PrivateKeyData)
		if encErr != nil {
			return fmt.Errorf("encrypt private key: %w", encErr)
		}
		stored.PrivateKeyData = encrypted
	}

	encoded := encodeStoredKey(stored)

	return ks.store.Update(func(tx KeyStoreTx) error {
		root, err := tx.CreateBucketIfNotExists(keystoreBucket)
		if err != nil {
			return err
		}
		zoneBucket, err := root.CreateBucketIfNotExists([]byte(zoneName))
		if err != nil {
			return err
		}

		keyID := make([]byte, 2)
		binary.BigEndian.PutUint16(keyID, key.KeyTag)
		return zoneBucket.Put(keyID, encoded)
	})
}

// LoadKeys loads all signing keys for a zone.
func (ks *KeyStore) LoadKeys(zoneName string) ([]*StoredKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var keys []*StoredKey

	err := ks.store.View(func(tx KeyStoreTx) error {
		root := tx.Bucket(keystoreBucket)
		if root == nil {
			return ErrNoKeysForZone
		}
		zoneBucket := root.Bucket([]byte(zoneName))
		if zoneBucket == nil {
			return ErrNoKeysForZone
		}

		return zoneBucket.ForEach(func(k, v []byte) error {
			stored, err := decodeStoredKey(v)
			if err != nil {
				return fmt.Errorf("decode key %x: %w", k, err)
			}
			// Decrypt private key data if encryption is enabled
			if len(ks.encryptionKey) > 0 {
				decrypted, decErr := ks.decryptPrivateKey(stored.PrivateKeyData)
				if decErr != nil {
					return fmt.Errorf("decrypt key %x: %w", k, decErr)
				}
				stored.PrivateKeyData = decrypted
			}
			keys = append(keys, stored)
			return nil
		})
	})

	return keys, err
}

// DeleteKey removes a key from the store.
func (ks *KeyStore) DeleteKey(zoneName string, keyTag uint16) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	return ks.store.Update(func(tx KeyStoreTx) error {
		root := tx.Bucket(keystoreBucket)
		if root == nil {
			return ErrKeyNotFound
		}
		zoneBucket := root.Bucket([]byte(zoneName))
		if zoneBucket == nil {
			return ErrKeyNotFound
		}

		keyID := make([]byte, 2)
		binary.BigEndian.PutUint16(keyID, keyTag)
		return zoneBucket.Delete(keyID)
	})
}

// DeleteZoneKeys removes all keys for a zone.
func (ks *KeyStore) DeleteZoneKeys(zoneName string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	return ks.store.Update(func(tx KeyStoreTx) error {
		root := tx.Bucket(keystoreBucket)
		if root == nil {
			return nil
		}
		return root.DeleteBucket([]byte(zoneName))
	})
}

// --- Serialization ---

func serializeSigningKey(key *SigningKey) (*StoredKey, error) {
	stored := &StoredKey{
		KeyTag:        key.KeyTag,
		Algorithm:     key.DNSKEY.Algorithm,
		Flags:         key.DNSKEY.Flags,
		IsKSK:         key.IsKSK,
		IsZSK:         key.IsZSK,
		PublicKeyData: key.DNSKEY.PublicKey,
	}

	// Serialize private key to DER format
	privDER, err := marshalPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, err
	}
	stored.PrivateKeyData = privDER

	return stored, nil
}

// marshalPrivateKey serializes a DNSSEC private key to DER bytes.
func marshalPrivateKey(pk *PrivateKey) ([]byte, error) {
	switch k := pk.Key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	case ed25519.PrivateKey:
		// Ed25519 keys are 64 bytes: seed(32) + public(32)
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", pk.Key)
	}
}

// unmarshalPrivateKey deserializes a private key from DER bytes.
func unmarshalPrivateKey(algorithm uint8, data []byte) (*PrivateKey, error) {
	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		key, err := x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key: %w", err)
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	case protocol.AlgorithmECDSAP256SHA256:
		key, err := x509.ParseECPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA P256 key: %w", err)
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	case protocol.AlgorithmECDSAP384SHA384:
		key, err := x509.ParseECPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA P384 key: %w", err)
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	case protocol.AlgorithmED25519:
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key size: %d", len(data))
		}
		return &PrivateKey{Algorithm: algorithm, Key: ed25519.PrivateKey(data)}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

// RestoreSigningKey converts a StoredKey back to a SigningKey.
func RestoreSigningKey(stored *StoredKey) (*SigningKey, error) {
	privKey, err := unmarshalPrivateKey(stored.Algorithm, stored.PrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("restore private key: %w", err)
	}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     stored.Flags,
		Protocol:  3, // Always 3 per RFC 4034
		Algorithm: stored.Algorithm,
		PublicKey: stored.PublicKeyData,
	}

	return &SigningKey{
		PrivateKey: privKey,
		DNSKEY:     dnskey,
		KeyTag:     stored.KeyTag,
		IsKSK:      stored.IsKSK,
		IsZSK:      stored.IsZSK,
		State:      KeyStateActive,
	}, nil
}

// --- Binary encoding for StoredKey ---
// Format: [2 keytag][1 algorithm][2 flags][1 isKSK][1 isZSK]
//
//	[2 pubKeyLen][pubKey][4 privKeyLen][privKey]
func encodeStoredKey(sk *StoredKey) []byte {
	size := 2 + 1 + 2 + 1 + 1 + 2 + len(sk.PublicKeyData) + 4 + len(sk.PrivateKeyData)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint16(buf[offset:], sk.KeyTag)
	offset += 2
	buf[offset] = sk.Algorithm
	offset++
	binary.BigEndian.PutUint16(buf[offset:], sk.Flags)
	offset += 2
	if sk.IsKSK {
		buf[offset] = 1
	}
	offset++
	if sk.IsZSK {
		buf[offset] = 1
	}
	offset++

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(sk.PublicKeyData)))
	offset += 2
	copy(buf[offset:], sk.PublicKeyData)
	offset += len(sk.PublicKeyData)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(sk.PrivateKeyData)))
	offset += 4
	copy(buf[offset:], sk.PrivateKeyData)

	return buf
}

func decodeStoredKey(data []byte) (*StoredKey, error) {
	if len(data) < 9 { // minimum header
		return nil, fmt.Errorf("stored key too short: %d bytes", len(data))
	}

	sk := &StoredKey{}
	offset := 0

	sk.KeyTag = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	sk.Algorithm = data[offset]
	offset++
	sk.Flags = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	sk.IsKSK = data[offset] == 1
	offset++
	sk.IsZSK = data[offset] == 1
	offset++

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated at pubkey length")
	}
	pubKeyLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+pubKeyLen > len(data) {
		return nil, fmt.Errorf("truncated at pubkey data")
	}
	sk.PublicKeyData = make([]byte, pubKeyLen)
	copy(sk.PublicKeyData, data[offset:offset+pubKeyLen])
	offset += pubKeyLen

	if offset+4 > len(data) {
		return nil, fmt.Errorf("truncated at privkey length")
	}
	privKeyLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+privKeyLen > len(data) {
		return nil, fmt.Errorf("truncated at privkey data")
	}
	sk.PrivateKeyData = make([]byte, privKeyLen)
	copy(sk.PrivateKeyData, data[offset:offset+privKeyLen])

	return sk, nil
}

// GeneratePublicKeyData generates wire-format public key data from a private key.
// This is needed when restoring keys that may only have the private key stored.
func GeneratePublicKeyData(algorithm uint8, privKey *PrivateKey) ([]byte, error) {
	switch k := privKey.Key.(type) {
	case *rsa.PrivateKey:
		return marshalRSAPublicKey(&k.PublicKey), nil
	case *ecdsa.PrivateKey:
		return marshalECDSAPublicKey(algorithm, &k.PublicKey)
	case ed25519.PrivateKey:
		pub := k.Public().(ed25519.PublicKey)
		return []byte(pub), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privKey.Key)
	}
}

func marshalRSAPublicKey(pub *rsa.PublicKey) []byte {
	expBytes := big.NewInt(int64(pub.E)).Bytes()
	modBytes := pub.N.Bytes()

	var buf []byte
	if len(expBytes) <= 255 {
		buf = make([]byte, 1+len(expBytes)+len(modBytes))
		buf[0] = byte(len(expBytes))
		copy(buf[1:], expBytes)
		copy(buf[1+len(expBytes):], modBytes)
	} else {
		buf = make([]byte, 3+len(expBytes)+len(modBytes))
		buf[0] = 0
		binary.BigEndian.PutUint16(buf[1:3], uint16(len(expBytes)))
		copy(buf[3:], expBytes)
		copy(buf[3+len(expBytes):], modBytes)
	}
	return buf
}

func marshalECDSAPublicKey(algorithm uint8, pub *ecdsa.PublicKey) ([]byte, error) {
	var keyLen int
	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		keyLen = 32
	case protocol.AlgorithmECDSAP384SHA384:
		keyLen = 48
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %d", algorithm)
	}

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	buf := make([]byte, keyLen*2)
	// Pad to fixed length
	copy(buf[keyLen-len(xBytes):keyLen], xBytes)
	copy(buf[2*keyLen-len(yBytes):2*keyLen], yBytes)
	return buf, nil
}

// Ensure we use elliptic (imported but used only in unmarshal path via x509)
var _ = elliptic.P256
