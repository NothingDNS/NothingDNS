package cluster

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// initEncryption initializes AES-256-GCM from a 32-byte key.
func (gp *GossipProtocol) initEncryption(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("gossip encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("gossip encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gossip encryption GCM: %w", err)
	}
	gp.aead = aead
	gp.encKey = make([]byte, 32)
	copy(gp.encKey, key)
	return nil
}

// IsEncrypted returns whether gossip encryption is enabled.
func (gp *GossipProtocol) IsEncrypted() bool {
	return gp.aead != nil
}

// encrypt encrypts data using AES-256-GCM.
// Output format: nonce (12 bytes) + ciphertext + tag.
func (gp *GossipProtocol) encrypt(plaintext []byte) ([]byte, error) {
	if gp.aead == nil {
		return plaintext, nil
	}
	nonce := make([]byte, gp.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gossip encrypt nonce: %w", err)
	}
	return gp.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts AES-256-GCM encrypted data.
func (gp *GossipProtocol) decrypt(ciphertext []byte) ([]byte, error) {
	if gp.aead == nil {
		return ciphertext, nil
	}
	if len(ciphertext) < gp.aead.NonceSize()+gp.aead.Overhead() {
		return nil, fmt.Errorf("gossip decrypt: ciphertext too short")
	}
	nonce := ciphertext[:gp.aead.NonceSize()]
	data := ciphertext[gp.aead.NonceSize():]
	return gp.aead.Open(nil, nonce, data, nil)
}

// encryptWithAAD encrypts with additional authenticated data for replay/cross-peer protection.
//
// When gossip encryption is disabled (gp.aead == nil) it passes the plaintext
// through unchanged, exactly like its encrypt/decrypt siblings. Callers cannot
// distinguish an unencrypted frame by return value alone, so the peers must be
// mutually authenticated for AAD binding to mean anything — see the AAD check
// in gossip_handlers.decodeMessage. The guard also prevents a nil-interface
// dereference on gp.aead.NonceSize() when encryption is off.
func (gp *GossipProtocol) encryptWithAAD(plaintext []byte, aad []byte) ([]byte, error) {
	if gp.aead == nil {
		return plaintext, nil
	}
	nonce := make([]byte, gp.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gossip encrypt nonce: %w", err)
	}
	return gp.aead.Seal(nonce, nonce, plaintext, aad), nil
}
