package odoh

// RFC 9230 wire format and HPKE-based encapsulation on top of hpke.go.
//
// References:
//   - RFC 9230 §3: ObliviousDoHConfigContents / KeyConfig
//   - RFC 9230 §4: ObliviousDoHMessage framing + HPKE labels
//
// The wire format uses fixed labels for HPKE info:
//   query:    "odoh query"
//   response: "odoh response"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ODoH application labels (RFC 9230 §4).
var (
	odohQueryLabel    = []byte("odoh query")
	odohResponseLabel = []byte("odoh response")
)

// ObliviousDoHMessageType per RFC 9230 §6:
//
//	0x01 = query
//	0x02 = response
const (
	odohMsgTypeQuery    byte = 0x01
	odohMsgTypeResponse byte = 0x02
)

// odohKeyPair holds the target's HPKE key material plus the serialized
// ObliviousDoHConfigContents that clients receive over a trusted
// channel.
type odohKeyPair struct {
	suite       hpkeSuite
	skR         *ecdh.PrivateKey
	pkRBytes    []byte
	configBytes []byte // serialized ObliviousDoHConfigContents
	keyID       []byte // 32-byte SHA-256 of the config (used as AAD in responses)
}

// newODoHKeyPair generates a fresh target key pair using the default
// suite (DHKEM-X25519, HKDF-SHA256, AES-128-GCM).
func newODoHKeyPair() (*odohKeyPair, error) {
	return newODoHKeyPairWithSuite(defaultHPKESuite())
}

// newODoHKeyPairWithSuite generates a fresh target key pair for the given
// HPKE suite. The suite's AEAD ID is advertised in the published
// ObliviousDoHConfigContents, so clients encrypt with the AEAD the
// operator actually configured (previously the config's AEAD choice was
// silently ignored and AES-128-GCM was always used).
func newODoHKeyPairWithSuite(suite hpkeSuite) (*odohKeyPair, error) {
	skR, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("odoh: gen target key: %w", err)
	}
	pk := skR.PublicKey().Bytes()

	// ObliviousDoHConfigContents per RFC 9230 §3.1:
	//   kem_id (2) || kdf_id (2) || aead_id (2)
	//   public_key_len (2) || public_key (...)
	var cfg bytes.Buffer
	cfg.Write(u16BE(suite.kemID))
	cfg.Write(u16BE(suite.kdfID))
	cfg.Write(u16BE(suite.aeadID))
	cfg.Write(u16BE(uint16(len(pk))))
	cfg.Write(pk)

	keyID, err := suite.odohKeyID(cfg.Bytes())
	if err != nil {
		return nil, fmt.Errorf("odoh: key_id: %w", err)
	}
	return &odohKeyPair{
		suite:       suite,
		skR:         skR,
		pkRBytes:    pk,
		configBytes: cfg.Bytes(),
		keyID:       keyID,
	}, nil
}

// configBytes returns the marshaled ObliviousDoHConfig framing the
// contents:
//
//	ObliviousDoHConfig: u16 version (0x0001) || u16 length || contents
//	ObliviousDoHConfigs: u16 total_length || one or more configs
//
// Most clients fetch the ObliviousDoHConfigs object, so we return the
// outer-wrapped form ready to serve over /.well-known/odohconfigs.
func (kp *odohKeyPair) configsObject() ([]byte, error) {
	configLen, err := u16Length("config contents", len(kp.configBytes))
	if err != nil {
		return nil, err
	}

	// One config inside ObliviousDoHConfigs.
	inner := make([]byte, 0, 4+len(kp.configBytes))
	inner = append(inner, u16BE(0x0001)...) // version
	inner = append(inner, u16BE(configLen)...)
	inner = append(inner, kp.configBytes...)

	innerLen, err := u16Length("config list", len(inner))
	if err != nil {
		return nil, err
	}
	outer := make([]byte, 0, 2+len(inner))
	outer = append(outer, u16BE(innerLen)...)
	outer = append(outer, inner...)
	return outer, nil
}

// odohMessage is the wire form for both query and response (RFC 9230
// §6.1):
//
//	u8  message_type           (0x01 query, 0x02 response)
//	u16 key_id_len             (32 for SHA-256)
//	u8[]  key_id
//	u16 encrypted_message_len
//	u8[]  encrypted_message
type odohMessage struct {
	msgType          byte
	keyID            []byte
	encryptedMessage []byte
}

func marshalODoHMessage(m *odohMessage) ([]byte, error) {
	keyIDLen, err := u16Length("key_id", len(m.keyID))
	if err != nil {
		return nil, err
	}
	encryptedLen, err := u16Length("encrypted_message", len(m.encryptedMessage))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+2+len(m.keyID)+2+len(m.encryptedMessage))
	out = append(out, m.msgType)
	out = append(out, u16BE(keyIDLen)...)
	out = append(out, m.keyID...)
	out = append(out, u16BE(encryptedLen)...)
	out = append(out, m.encryptedMessage...)
	return out, nil
}

func parseODoHMessage(b []byte) (*odohMessage, error) {
	if len(b) < 1+2 {
		return nil, errors.New("odoh: message truncated (header)")
	}
	m := &odohMessage{msgType: b[0]}
	r := b[1:]
	keyIDLen := binary.BigEndian.Uint16(r[:2])
	r = r[2:]
	if len(r) < int(keyIDLen)+2 {
		return nil, errors.New("odoh: message truncated (key_id)")
	}
	m.keyID = make([]byte, keyIDLen)
	copy(m.keyID, r[:keyIDLen])
	r = r[keyIDLen:]
	encLen := binary.BigEndian.Uint16(r[:2])
	r = r[2:]
	if len(r) < int(encLen) {
		return nil, errors.New("odoh: message truncated (encrypted)")
	}
	m.encryptedMessage = make([]byte, encLen)
	copy(m.encryptedMessage, r[:encLen])
	return m, nil
}

// encryptQueryRFC9230 produces an ObliviousDoHMessage that the target
// can decrypt. Returns the wire bytes to POST to the proxy and the
// HPKE context preserved for response decryption.
func encryptQueryRFC9230(targetConfig []byte, dnsQuery []byte) (msgBytes []byte, queryCtx *queryContext, err error) {
	suite, pkR, err := parseConfigContents(targetConfig)
	if err != nil {
		return nil, nil, err
	}
	dnsLen, err := u16Length("dns query", len(dnsQuery))
	if err != nil {
		return nil, nil, err
	}

	keyID, err := suite.odohKeyID(targetConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: key_id: %w", err)
	}

	enc, ctx, err := suite.hpkeSetupSender(rand.Reader, pkR, odohQueryLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: setup sender: %w", err)
	}

	// AAD for the query is: 0x01 || u16(keyIDLen) || key_id (RFC 9230 §4.1.1).
	aad := make([]byte, 0, 3+len(keyID))
	aad = append(aad, odohMsgTypeQuery)
	aad = append(aad, u16BE(uint16(len(keyID)))...)
	aad = append(aad, keyID...)

	// plaintext: DNS message + padding (padding optional; we add none).
	// RFC 9230 §6.2 plaintext format:
	//   u16 dns_message_len || dns_message || u16 padding_len || padding
	pt := make([]byte, 0, 4+len(dnsQuery))
	pt = append(pt, u16BE(dnsLen)...)
	pt = append(pt, dnsQuery...)
	pt = append(pt, u16BE(0)...) // padding_len = 0

	// encrypted_message = enc || aead.Seal(...)
	ct, err := ctx.seal(aad, pt)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: seal: %w", err)
	}
	encrypted := make([]byte, 0, len(enc)+len(ct))
	encrypted = append(encrypted, enc...)
	encrypted = append(encrypted, ct...)

	msg := &odohMessage{
		msgType:          odohMsgTypeQuery,
		keyID:            keyID,
		encryptedMessage: encrypted,
	}
	msgBytes, err = marshalODoHMessage(msg)
	if err != nil {
		return nil, nil, err
	}
	return msgBytes, &queryContext{suite: suite, ctx: ctx, qPlain: pt, keyID: keyID}, nil
}

type queryContext struct {
	suite  hpkeSuite
	ctx    *hpkeContext
	qPlain []byte // this client's query plaintext; part of the RFC 9230 §6.2 response salt
	keyID  []byte
}

// parseConfigContents parses a single ObliviousDoHConfigContents (NOT
// the outer ObliviousDoHConfigs wrapper) and returns the suite and
// recipient public key.
func parseConfigContents(b []byte) (hpkeSuite, *ecdh.PublicKey, error) {
	if len(b) < 8 {
		return hpkeSuite{}, nil, errors.New("odoh: config too short")
	}
	suite := hpkeSuite{
		kemID:  binary.BigEndian.Uint16(b[0:2]),
		kdfID:  binary.BigEndian.Uint16(b[2:4]),
		aeadID: binary.BigEndian.Uint16(b[4:6]),
	}
	pkLen := binary.BigEndian.Uint16(b[6:8])
	if len(b) < 8+int(pkLen) {
		return hpkeSuite{}, nil, errors.New("odoh: config truncated")
	}
	if len(b) != 8+int(pkLen) {
		// key_id is derived over the whole buffer, so trailing bytes would
		// yield a key_id the target can never match.
		return hpkeSuite{}, nil, fmt.Errorf("odoh: %d trailing bytes after config public_key", len(b)-8-int(pkLen))
	}
	pk, err := ecdh.X25519().NewPublicKey(b[8 : 8+pkLen])
	if err != nil {
		return hpkeSuite{}, nil, fmt.Errorf("odoh: parse pk: %w", err)
	}
	if suite.kemID != hpkeKEMX25519HKDFSHA256 ||
		suite.kdfID != hpkeKDFHKDFSHA256 ||
		(suite.aeadID != hpkeAEADAES128GCM && suite.aeadID != hpkeAEADAES256GCM) {
		return hpkeSuite{}, nil, errors.New("odoh: unsupported suite")
	}
	return suite, pk, nil
}

// decryptQueryRFC9230 is the target side of encryptQueryRFC9230. Takes
// the marshaled ObliviousDoHMessage from the proxy and returns the
// plaintext DNS query plus a response context.
func (kp *odohKeyPair) decryptQuery(msgBytes []byte) (dnsQuery []byte, respCtx *responseContext, err error) {
	msg, err := parseODoHMessage(msgBytes)
	if err != nil {
		return nil, nil, err
	}
	if msg.msgType != odohMsgTypeQuery {
		return nil, nil, fmt.Errorf("odoh: wrong message type %d", msg.msgType)
	}
	if !bytes.Equal(msg.keyID, kp.keyID) {
		return nil, nil, errors.New("odoh: unknown key_id")
	}

	// encrypted_message = enc || ct, where len(enc) = X25519 pub key = 32 bytes.
	if len(msg.encryptedMessage) < 32 {
		return nil, nil, errors.New("odoh: ciphertext too short")
	}
	enc := msg.encryptedMessage[:32]
	ct := msg.encryptedMessage[32:]

	ctx, err := kp.suite.hpkeSetupRecipient(enc, kp.skR, odohQueryLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: setup recipient: %w", err)
	}

	aad := make([]byte, 0, 3+len(kp.keyID))
	aad = append(aad, odohMsgTypeQuery)
	aad = append(aad, u16BE(uint16(len(kp.keyID)))...)
	aad = append(aad, kp.keyID...)

	pt, err := ctx.open(aad, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: open: %w", err)
	}

	// Parse the plaintext envelope:  u16 dns_len || dns || u16 pad_len || pad
	dnsQuery, err = parsePlaintextEnvelope(pt)
	if err != nil {
		return nil, nil, err
	}

	// Capture the context needed to derive the response AEAD later
	// (deriveResponseAEAD). Per RFC 9230 §6.2 the IKM is
	// Context.Export("odoh response", Nk) — bound to the HPKE DH shared
	// secret — and the HKDF salt folds in the exact serialized Q_plain plus
	// a fresh random response_nonce per response, so every response gets a
	// unique (key, nonce) even for a byte-identical replayed query. Q_plain
	// must be preserved byte-for-byte: it is part of that salt, and a peer
	// deriving with a different form fails AEAD authentication.
	respCtx = &responseContext{
		suite:         kp.suite,
		ctx:           ctx,
		qPlain:        append([]byte(nil), pt...),
		responseLabel: odohResponseLabel,
	}
	return dnsQuery, respCtx, nil
}

// responseContext carries everything the target needs to AEAD-seal a
// response to the same client.
type responseContext struct {
	suite         hpkeSuite
	ctx           *hpkeContext
	qPlain        []byte // serialized query plaintext; part of the RFC 9230 §6.2 response salt
	responseLabel []byte
}

// encryptResponse seals dnsResponse and produces the wire-format
// ObliviousDoHMessage bytes to return to the proxy.
func (rc *responseContext) encryptResponse(dnsResponse []byte) ([]byte, error) {
	// RFC 9230 §4.2: response_nonce = random(max(Nk, Nn)). Nk >= Nn for every
	// supported AEAD, so aeadKeyLen() is that maximum.
	responseNonce := make([]byte, rc.suite.aeadKeyLen())
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, fmt.Errorf("odoh: response nonce: %w", err)
	}

	odohSecret, err := rc.ctx.export(rc.responseLabel, rc.suite.aeadKeyLen())
	if err != nil {
		return nil, fmt.Errorf("odoh: export response secret: %w", err)
	}
	aead, nonce, err := rc.suite.deriveResponseAEAD(rc.qPlain, odohSecret, responseNonce)
	if err != nil {
		return nil, err
	}
	dnsLen, err := u16Length("dns response", len(dnsResponse))
	if err != nil {
		return nil, err
	}

	// Response AAD binds the random response_nonce (carried in the message's
	// key_id field) so a proxy can't detach the nonce from the ciphertext.
	aad := responseAAD(responseNonce)

	// Plaintext envelope:  u16 dns_len || dns || u16 pad_len || pad
	pt := make([]byte, 0, 4+len(dnsResponse))
	pt = append(pt, u16BE(dnsLen)...)
	pt = append(pt, dnsResponse...)
	pt = append(pt, u16BE(0)...) // padding_len = 0

	ct := aead.Seal(nil, nonce, pt, aad)

	msg := &odohMessage{
		msgType:          odohMsgTypeResponse,
		keyID:            responseNonce, // RFC 9230 §4.2: response_nonce on the wire
		encryptedMessage: ct,
	}
	return marshalODoHMessage(msg)
}

// responseAAD builds the RFC 9230 §4.1.2 response AAD:
// msg_type(0x02) || u16(len(response_nonce)) || response_nonce.
func responseAAD(responseNonce []byte) []byte {
	aad := make([]byte, 0, 3+len(responseNonce))
	aad = append(aad, odohMsgTypeResponse)
	aad = append(aad, u16BE(uint16(len(responseNonce)))...)
	aad = append(aad, responseNonce...)
	return aad
}

// decryptResponse is the client side of encryptResponse.
func (qc *queryContext) decryptResponse(msgBytes []byte) ([]byte, error) {
	msg, err := parseODoHMessage(msgBytes)
	if err != nil {
		return nil, err
	}
	if msg.msgType != odohMsgTypeResponse {
		return nil, fmt.Errorf("odoh: wrong response type %d", msg.msgType)
	}
	// The response carries response_nonce in its key_id field (RFC 9230 §4.2),
	// which must equal max(Nk, Nn) = aeadKeyLen for the negotiated suite.
	responseNonce := msg.keyID
	if len(responseNonce) != qc.suite.aeadKeyLen() {
		return nil, fmt.Errorf("odoh: response_nonce length %d, want %d", len(responseNonce), qc.suite.aeadKeyLen())
	}

	odohSecret, err := qc.ctx.export(odohResponseLabel, qc.suite.aeadKeyLen())
	if err != nil {
		return nil, fmt.Errorf("odoh: export response secret: %w", err)
	}
	aead, nonce, err := qc.suite.deriveResponseAEAD(qc.qPlain, odohSecret, responseNonce)
	if err != nil {
		return nil, err
	}

	aad := responseAAD(responseNonce)
	pt, err := aead.Open(nil, nonce, msg.encryptedMessage, aad)
	if err != nil {
		return nil, fmt.Errorf("odoh: open response: %w", err)
	}

	dnsResponse, err := parsePlaintextEnvelope(pt)
	if err != nil {
		return nil, fmt.Errorf("odoh: response: %w", err)
	}
	return dnsResponse, nil
}

// parsePlaintextEnvelope parses an ObliviousDoHMessagePlaintext (RFC 9230
// §4): u16 dns_len || dns_message<1..2^16-1> || u16 pad_len || padding.
// The padding must be present in full and all zeros, and nothing may follow
// it. Returns a copy of dns_message.
func parsePlaintextEnvelope(pt []byte) ([]byte, error) {
	if len(pt) < 4 {
		return nil, errors.New("odoh: plaintext too short")
	}
	dnsLen := int(binary.BigEndian.Uint16(pt[0:2]))
	if dnsLen == 0 {
		return nil, errors.New("odoh: empty dns_message")
	}
	if len(pt) < 2+dnsLen+2 {
		return nil, errors.New("odoh: plaintext truncated")
	}
	padLen := int(binary.BigEndian.Uint16(pt[2+dnsLen : 4+dnsLen]))
	padding := pt[4+dnsLen:]
	if len(padding) != padLen {
		return nil, fmt.Errorf("odoh: padding length %d, have %d bytes", padLen, len(padding))
	}
	for _, b := range padding {
		if b != 0 {
			return nil, errors.New("odoh: non-zero padding")
		}
	}
	return append([]byte(nil), pt[2:2+dnsLen]...), nil
}

// deriveResponseAEAD turns (Q_plain, odoh_secret, response_nonce) into the
// fresh AEAD key+nonce for the response transit, per RFC 9230 §6.2:
//
//	secret = context.Export("odoh response", Nk)  (passed in as odohSecret)
//	salt   = Q_plain || u16(len(resp_nonce)) || resp_nonce
//	prk    = Extract(salt, secret)
//	key    = Expand(prk, "odoh key", Nk)
//	nonce  = Expand(prk, "odoh nonce", Nn)
//
// The IKM stays bound to the HPKE DH shared secret; Q_plain and the random
// per-response nonce only salt the extraction, so every response gets a
// unique (key, nonce) even for a byte-identical replayed query. Q_plain must
// match the peer's serialized plaintext envelope byte-for-byte, or the
// derived keys differ and AEAD authentication fails on both ends. This
// matches the odoh-rs reference implementation; the previous derivation
// (salt = enc || resp_nonce, HPKE-labeled "key"/"nonce" expands) produced
// keys no conformant peer could derive, so the ODoH target and client could
// only talk to themselves.
func (s hpkeSuite) deriveResponseAEAD(qPlain, odohSecret, responseNonce []byte) (cipher.AEAD, []byte, error) {
	hash := s.hkdfHash()
	salt := make([]byte, 0, len(qPlain)+2+len(responseNonce))
	salt = append(salt, qPlain...)
	var nl [2]byte
	binary.BigEndian.PutUint16(nl[:], uint16(len(responseNonce)))
	salt = append(salt, nl[:]...)
	salt = append(salt, responseNonce...)

	prk, err := hkdf.Extract(hash, odohSecret, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response hkdf extract: %w", err)
	}
	key, err := hkdf.Expand(hash, prk, "odoh key", s.aeadKeyLen())
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead key: %w", err)
	}
	nonce, err := hkdf.Expand(hash, prk, "odoh nonce", s.aeadNonceLen())
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead nonce: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: response aead init: %w", err)
	}
	return gcm, nonce, nil
}

// odohKeyID is RFC 9230 §6.1: key_id = Expand(Extract("", config),
// "odoh key id", Nh) with the suite's KDF. It was an HPKE LabeledExtract
// ("HPKE-v1" || suite_id || "key_id"), so the target rejected every query
// from a conformant client as "unknown key_id" (F649).
func (s hpkeSuite) odohKeyID(config []byte) ([]byte, error) {
	hash := s.hkdfHash()
	prk, err := hkdf.Extract(hash, config, nil)
	if err != nil {
		return nil, err
	}
	return hkdf.Expand(hash, prk, "odoh key id", hash().Size())
}

func u16BE(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func u16Length(field string, n int) (uint16, error) {
	if n > 0xffff {
		return 0, fmt.Errorf("odoh: %s too large: %d bytes (max 65535)", field, n)
	}
	return uint16(n), nil
}
