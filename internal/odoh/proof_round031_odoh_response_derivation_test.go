// Regression tests for round 031: the ODoH response AEAD derivation must
// follow RFC 9230 §6.2 derive_secrets exactly —
//
//	salt = serialize(Q_plain) || u16(len(resp_nonce)) || resp_nonce
//	prk  = Extract(salt, Context.Export("odoh response", Nk))
//	key  = Expand(prk, "odoh key", Nk); nonce = Expand(prk, "odoh nonce", Nn)
//
// — as implemented by the odoh-rs reference crate. The previous derivation
// (salt = enc || resp_nonce, HPKE-labeled "key"/"nonce" expands) produced
// keys no conformant peer could derive, so NothingDNS's ODoH target produced
// responses undecryptable by every RFC 9230 client, and its ODoH client
// rejected every conformant target's response — while in-package round trips
// (both sides sharing the deviation) stayed green. These tests derive keys
// independently from the production deriveResponseAEAD and must keep both
// interop directions working.
package odoh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// rfcDeriveResponseKeys implements RFC 9230 §6.2 derive_secrets independently
// of the production deriveResponseAEAD, byte-for-byte as odoh-rs does.
func rfcDeriveResponseKeys(t *testing.T, odohSecret, qPlain, responseNonce []byte, keyLen, nonceLen int) (cipher.AEAD, []byte) {
	t.Helper()
	hash := defaultHPKESuite().hkdfHash()
	salt := make([]byte, 0, len(qPlain)+2+len(responseNonce))
	salt = append(salt, qPlain...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(responseNonce)))
	salt = append(salt, l[:]...)
	salt = append(salt, responseNonce...)

	prk, err := hkdf.Extract(hash, odohSecret, salt)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	key, err := hkdf.Expand(hash, prk, "odoh key", keyLen)
	if err != nil {
		t.Fatalf("expand key: %v", err)
	}
	nonce, err := hkdf.Expand(hash, prk, "odoh nonce", nonceLen)
	if err != nil {
		t.Fatalf("expand nonce: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aead key: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	return gcm, nonce
}

// rfcEnvelope builds the ObliviousDoHMessagePlaintext wire form exactly as
// odoh-rs compose() does for padding_len 0: u16 dnsLen || dns || u16 0.
func rfcEnvelope(dns []byte) []byte {
	out := make([]byte, 0, 4+len(dns))
	out = append(out, u16BE(uint16(len(dns)))...)
	out = append(out, dns...)
	out = append(out, u16BE(0)...)
	return out
}

var rfc031DNSQuery = append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, []byte("\x07example\x03com\x00")...)
var rfc031DNSResponse = append([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, []byte("\x07example\x03com\x00")...)

// rfcConformantQueryMessage encrypts Q_plain the way a conformant ODoH client
// (RFC 9230 §6.2 encrypt_query_body) does, using the package's own
// RFC 9180-verified HPKE primitives. Returns the wire message and the
// sender's HPKE context (the client's exporter lives there).
func rfcConformantQueryMessage(t *testing.T, kp *odohKeyPair, qPlain []byte) ([]byte, *hpkeContext) {
	t.Helper()
	_, pkR, err := parseConfigContents(kp.configBytes)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	enc, ctx, err := kp.suite.hpkeSetupSender(rand.Reader, pkR, odohQueryLabel)
	if err != nil {
		t.Fatalf("setup sender: %v", err)
	}
	aad := make([]byte, 0, 3+len(kp.keyID))
	aad = append(aad, odohMsgTypeQuery)
	aad = append(aad, u16BE(uint16(len(kp.keyID)))...)
	aad = append(aad, kp.keyID...)
	ct, err := ctx.seal(aad, qPlain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	encrypted := append(append([]byte{}, enc...), ct...)
	msg, err := marshalODoHMessage(&odohMessage{msgType: odohMsgTypeQuery, keyID: kp.keyID, encryptedMessage: encrypted})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return msg, ctx
}

// Control: the query path is conformant in both directions — the production
// target accepts a conformant client query, and the production client's query
// is acceptable to a conformant target.
func TestODoHQueryPathIsConformant(t *testing.T) {
	kp, err := newODoHKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	qPlain := rfcEnvelope(rfc031DNSQuery)

	msg, _ := rfcConformantQueryMessage(t, kp, qPlain)
	dns, _, err := kp.decryptQuery(msg)
	if err != nil {
		t.Fatalf("production target rejected a RFC 9230 conformant query: %v", err)
	}
	if !bytes.Equal(dns, rfc031DNSQuery) {
		t.Fatalf("decrypted query mismatch")
	}

	clientMsg, _, err := encryptQueryRFC9230(kp.configBytes, rfc031DNSQuery)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	dns2, _, err := kp.decryptQuery(clientMsg)
	if err != nil {
		t.Fatalf("production client query not acceptable as a conformant message: %v", err)
	}
	if !bytes.Equal(dns2, rfc031DNSQuery) {
		t.Fatalf("client query mismatch")
	}
}

// The production target's encrypted response must be decryptable by a peer
// that derives keys per RFC 9230 §6.2.
func TestODoHTargetResponseDecryptableByRFC9230Peer(t *testing.T) {
	kp, err := newODoHKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	qPlain := rfcEnvelope(rfc031DNSQuery)

	msg, senderCtx := rfcConformantQueryMessage(t, kp, qPlain)
	dns, respCtx, err := kp.decryptQuery(msg)
	if err != nil {
		t.Fatalf("target rejected conformant query: %v", err)
	}
	if !bytes.Equal(dns, rfc031DNSQuery) {
		t.Fatalf("query mismatch")
	}

	respBytes, err := respCtx.encryptResponse(rfc031DNSResponse)
	if err != nil {
		t.Fatalf("encryptResponse: %v", err)
	}
	respMsg, err := parseODoHMessage(respBytes)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	odohSecret, err := senderCtx.export(odohResponseLabel, kp.suite.aeadKeyLen())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	gcm, nonce := rfcDeriveResponseKeys(t, odohSecret, qPlain, respMsg.keyID, kp.suite.aeadKeyLen(), kp.suite.aeadNonceLen())
	plain, err := gcm.Open(nil, nonce, respMsg.encryptedMessage, responseAAD(respMsg.keyID))
	if err != nil {
		t.Fatalf("ODoH target response is not decryptable by an RFC 9230 conformant peer: %v", err)
	}
	if !bytes.Equal(plain, rfcEnvelope(rfc031DNSResponse)) {
		t.Fatalf("decrypted response plaintext mismatch")
	}
}

// The production client must decrypt a response produced by a conformant
// target (RFC 9230 §6.2 derivation).
func TestODoHClientDecryptsRFC9230ConformantResponse(t *testing.T) {
	kp, err := newODoHKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	msgBytes, qc, err := encryptQueryRFC9230(kp.configBytes, rfc031DNSQuery)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	qPlain := rfcEnvelope(rfc031DNSQuery)

	_, respCtx, err := kp.decryptQuery(msgBytes)
	if err != nil {
		t.Fatalf("target rejected production client query: %v", err)
	}
	odohSecret, err := respCtx.ctx.export(odohResponseLabel, kp.suite.aeadKeyLen())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	responseNonce := make([]byte, kp.suite.aeadKeyLen()) // max(Nk, Nn)
	if _, err := rand.Read(responseNonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	gcm, nonce := rfcDeriveResponseKeys(t, odohSecret, qPlain, responseNonce, kp.suite.aeadKeyLen(), kp.suite.aeadNonceLen())
	ct := gcm.Seal(nil, nonce, rfcEnvelope(rfc031DNSResponse), responseAAD(responseNonce))
	respMsg, err := marshalODoHMessage(&odohMessage{msgType: odohMsgTypeResponse, keyID: responseNonce, encryptedMessage: ct})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := qc.decryptResponse(respMsg)
	if err != nil {
		t.Fatalf("ODoH client cannot decrypt an RFC 9230 conformant target response: %v", err)
	}
	if !bytes.Equal(got, rfc031DNSResponse) {
		t.Fatalf("decrypted response mismatch")
	}
}
