package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"crypto/tls"
)

// Cipher suite constants.
const (
	TLSCipherAES128GCM_SHA256 = tls.TLS_AES_128_GCM_SHA256       // 0x1301
	TLSCipherAES256GCM_SHA384 = tls.TLS_AES_256_GCM_SHA384       // 0x1302
	TLSCipherChaCha20_SHA256  = tls.TLS_CHACHA20_POLY1305_SHA256 // 0x1303
)

// QUIC HKDF label prefixes per RFC 8446 Section 7.1.
const hkdfLabelPrefix = "tls13 "

// QUIC-specific label suffixes per RFC 9001.
const (
	hkdfLabelKey = "quic key"
	hkdfLabelIV  = "quic iv"
	hkdfLabelHP  = "quic hp"
)

// cipherSuiteInfo returns the key length and hash function for a TLS 1.3 cipher suite.
func cipherSuiteInfo(suite uint16) (keyLen int, hash func() hash.Hash, err error) {
	switch suite {
	case TLSCipherAES128GCM_SHA256:
		return 16, sha256.New, nil
	case TLSCipherAES256GCM_SHA384:
		return 32, sha512.New384, nil
	case TLSCipherChaCha20_SHA256:
		return 32, sha256.New, nil
	default:
		return 0, nil, fmt.Errorf("quic: unsupported cipher suite 0x%04x", suite)
	}
}

// hkdfExpandLabel derives keying material using the TLS 1.3 HKDF-Expand-Label
// function (RFC 8446 Section 7.1). The label is automatically prefixed with
// "tls13 " per the spec.
func hkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	// Build HKDF label: length | label_len | "tls13 " + label | context_len | context
	fullLabel := hkdfLabelPrefix + label
	labelLen := len(fullLabel)
	contextLen := len(context)

	hkdfLabel := make([]byte, 2+1+labelLen+1+contextLen)
	binary.BigEndian.PutUint16(hkdfLabel, uint16(length))
	hkdfLabel[2] = byte(labelLen)
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+labelLen] = byte(contextLen)
	if contextLen > 0 {
		copy(hkdfLabel[3+labelLen+1:], context)
	}

	return hkdf.Expand(hash, secret, string(hkdfLabel), length)
}

// DeriveAEADKeyAndIV derives the AEAD cipher and IV from a 1-RTT traffic secret.
// Returns a cipher.AEAD (AES-GCM for AES suites) and a 12-byte IV.
func DeriveAEADKeyAndIV(suite uint16, secret []byte) (cipher.AEAD, []byte, error) {
	keyLen, hash, err := cipherSuiteInfo(suite)
	if err != nil {
		return nil, nil, err
	}

	// Derive key: HKDF-Expand-Label(secret, "quic key", "", keyLen)
	key, err := hkdfExpandLabel(hash, secret, hkdfLabelKey, nil, keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: derive key: %w", err)
	}

	// Derive IV: HKDF-Expand-Label(secret, "quic iv", "", 12)
	iv, err := hkdfExpandLabel(hash, secret, hkdfLabelIV, nil, 12)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: derive iv: %w", err)
	}

	// Construct AEAD: AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: create aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: create gcm: %w", err)
	}

	return aead, iv, nil
}

// DeriveHeaderProtectionKey derives the header protection key from a 1-RTT
// traffic secret. Returns raw key bytes (caller creates AES block).
func DeriveHeaderProtectionKey(suite uint16, secret []byte) ([]byte, error) {
	keyLen, hash, err := cipherSuiteInfo(suite)
	if err != nil {
		return nil, err
	}

	// Derive HP key: HKDF-Expand-Label(secret, "quic hp", "", keyLen)
	hpKey, err := hkdfExpandLabel(hash, secret, hkdfLabelHP, nil, keyLen)
	if err != nil {
		return nil, fmt.Errorf("quic: derive hp key: %w", err)
	}

	return hpKey, nil
}

// RemoveHeaderProtection removes AES-GCM header protection from a QUIC short
// header packet (RFC 9001 Section 5.4). The data slice must start with the
// short header byte and include the DCID, PN, and at least 16 bytes of
// encrypted payload. cidLen is the length of the destination connection ID.
// Returns the decoded packet number, or an error.
func RemoveHeaderProtection(hpKey []byte, data []byte, cidLen, pnLen int) (uint64, error) {
	// Sample is 16 bytes from encrypted payload, starting after header+DCID+PN.
	sampleOffset := 1 + cidLen + pnLen
	if len(data) < sampleOffset+16 {
		return 0, errors.New("quic: packet too short for header protection sample")
	}

	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return 0, fmt.Errorf("quic: create aes cipher: %w", err)
	}

	sample := data[sampleOffset : sampleOffset+16]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample) // AES-ECB single block encryption

	// Unmask the header byte: for short header, mask[0] lower 4 bits contain PN length
	data[0] ^= mask[0] & 0x0f

	// Decode and restore packet number: PN starts after header byte + DCID
	pnOffset := 1 + cidLen
	var pn uint64
	for i := 0; i < pnLen; i++ {
		orig := data[pnOffset+i] ^ mask[1+i]
		data[pnOffset+i] = orig // restore original PN byte
		pn = (pn << 8) | uint64(orig)
	}

	return pn, nil
}

// Decrypt1RTTPacket decrypts a QUIC 1-RTT packet payload using AEAD.
// The nonce is constructed as IV XOR packet_number (8-byte big-endian in
// last 8 bytes of 12-byte IV). The header is used as additional data.
func Decrypt1RTTPacket(aead cipher.AEAD, iv []byte, pn uint64, header, ciphertext []byte) ([]byte, error) {
	// Construct nonce: IV XOR packet_number
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (i * 8))
	}

	// AEAD decrypt: AAD = header, ciphertext = encrypted payload
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("quic: decrypt: %w", err)
	}

	return plaintext, nil
}

// ApplyHeaderProtection applies AES-GCM header protection to a QUIC short
// header packet (RFC 9001 Section 5.4). The data slice must contain the
// complete packet (header + DCID + PN + encrypted payload). cidLen is the
// length of the destination connection ID.
func ApplyHeaderProtection(hpKey []byte, data []byte, cidLen, pnLen int) error {
	// Sample is 16 bytes of encrypted payload starting after header+DCID+PN.
	sampleOffset := 1 + cidLen + pnLen
	if len(data) < sampleOffset+16 {
		return errors.New("quic: packet too short for header protection sample")
	}

	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return fmt.Errorf("quic: create aes cipher: %w", err)
	}

	sample := data[sampleOffset : sampleOffset+16]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample) // AES-ECB single block encryption

	// Mask the header byte: for short header, mask[0] lower 4 bits hide PN length
	data[0] ^= mask[0] & 0x0f

	// Encrypt packet number bytes (PN starts after header byte + DCID)
	pnOffset := 1 + cidLen
	for i := 0; i < pnLen; i++ {
		data[pnOffset+i] ^= mask[1+i]
	}

	return nil
}

// Encrypt1RTTPacket encrypts a QUIC 1-RTT packet payload using AEAD.
// The nonce is constructed as IV XOR packet_number (8-byte big-endian in
// last 8 bytes of 12-byte IV). The header is used as additional data.
// Returns the ciphertext with AEAD tag appended.
func Encrypt1RTTPacket(aead cipher.AEAD, iv []byte, pn uint64, header, plaintext []byte) ([]byte, error) {
	// Construct nonce: IV XOR packet_number
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (i * 8))
	}

	// AEAD encrypt: AAD = header, plaintext = decrypted payload
	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	return ciphertext, nil
}
