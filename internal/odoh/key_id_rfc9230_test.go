package odoh

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"
)

// F649: key_id must be RFC 9230 §6.1's Expand(Extract("", config),
// "odoh key id", Nh); an HPKE LabeledExtract made the target reject every
// query from a conformant client as "unknown key_id".
func TestKeyIDMatchesRFC9230(t *testing.T) {
	for _, aead := range []uint16{hpkeAEADAES128GCM, hpkeAEADAES256GCM} {
		suite := defaultHPKESuite()
		suite.aeadID = aead
		kp, err := newODoHKeyPairWithSuite(suite)
		if err != nil {
			t.Fatal(err)
		}
		prk, err := hkdf.Extract(sha256.New, kp.configBytes, nil)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hkdf.Expand(sha256.New, prk, "odoh key id", sha256.Size)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kp.keyID, want) {
			t.Errorf("aead %#04x: target key_id %x, RFC 9230 key_id %x", aead, kp.keyID, want)
		}
		// The package's own client must address the same key_id.
		msg, _, err := encryptQueryRFC9230(kp.configBytes, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseODoHMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.keyID, want) {
			t.Errorf("aead %#04x: client key_id %x, want %x", aead, parsed.keyID, want)
		}
	}
}
