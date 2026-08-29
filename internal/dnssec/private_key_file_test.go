package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// bindEnvelope wraps key material the way a ".private" file does.
func bindEnvelope(algorithm uint8, body string) []byte {
	return []byte(fmt.Sprintf(
		"Private-key-format: v1.3\nAlgorithm: %d (TEST)\nKeyTag: 12345\nCreated: 20260828000000\n%s\n",
		algorithm, body))
}

// TestParsePrivateKeyFile_DNSCTLEnvelope is the regression for the daemon
// being unable to load the keys its own CLI produced. `dnsctl dnssec
// generate-key` writes a BIND-style envelope whose PrivateKey field holds
// PKCS#8 DER; the daemon fed the whole text file to x509.ParseECPrivateKey and
// failed with an asn1 tag error, so zone signing could not be reached through
// the project's documented workflow at all.
func TestParsePrivateKeyFile_DNSCTLEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		gen       func(t *testing.T) any
	}{
		{"ECDSA P-256", protocol.AlgorithmECDSAP256SHA256, func(t *testing.T) any {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			return k
		}},
		{"ECDSA P-384", protocol.AlgorithmECDSAP384SHA384, func(t *testing.T) any {
			k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			return k
		}},
		{"Ed25519", protocol.AlgorithmED25519, func(t *testing.T) any {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			return k
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.gen(t)
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			data := bindEnvelope(tc.algorithm,
				"PrivateKey: "+base64.StdEncoding.EncodeToString(der))

			got, err := ParsePrivateKeyFile(data, tc.algorithm)
			if err != nil {
				t.Fatalf("ParsePrivateKeyFile: %v", err)
			}
			if got.Algorithm != tc.algorithm {
				t.Errorf("algorithm = %d, want %d", got.Algorithm, tc.algorithm)
			}
			if got.Key == nil {
				t.Fatal("no key material returned")
			}
		})
	}
}

// TestParsePrivateKeyFile_RealBINDEnvelope covers what BIND's own
// dnssec-keygen writes: the bare private scalar (ECDSA) or seed (Ed25519),
// not DER. Neither reader in the tree handled this, so BIND key files could
// not be used at all.
func TestParsePrivateKeyFile_RealBINDEnvelope(t *testing.T) {
	t.Run("ECDSA P-256 raw scalar", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		scalar, err := key.Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		data := bindEnvelope(protocol.AlgorithmECDSAP256SHA256,
			"PrivateKey: "+base64.StdEncoding.EncodeToString(scalar))

		got, err := ParsePrivateKeyFile(data, protocol.AlgorithmECDSAP256SHA256)
		if err != nil {
			t.Fatalf("ParsePrivateKeyFile: %v", err)
		}
		parsed, ok := got.Key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("key is %T, want *ecdsa.PrivateKey", got.Key)
		}
		// Equal compares the scalar and the derived public point together, so
		// this also catches a public key that was not recomputed from it.
		if !parsed.Equal(key) {
			t.Error("raw scalar did not reproduce the same key")
		}
	})

	t.Run("Ed25519 seed", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		data := bindEnvelope(protocol.AlgorithmED25519,
			"PrivateKey: "+base64.StdEncoding.EncodeToString(priv.Seed()))

		got, err := ParsePrivateKeyFile(data, protocol.AlgorithmED25519)
		if err != nil {
			t.Fatalf("ParsePrivateKeyFile: %v", err)
		}
		parsed, ok := got.Key.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("key is %T, want ed25519.PrivateKey", got.Key)
		}
		if !parsed.Public().(ed25519.PublicKey).Equal(pub) {
			t.Error("seed did not reproduce the same key pair")
		}
	})
}

// TestParsePrivateKeyFile_RSAComponents covers BIND's component encoding. The
// previous reader rebuilt RSA keys from Modulus and PrivateExponent alone and
// called the result "approximate"; Go signs through the CRT values derived
// from the primes, so such a key cannot sign at all.
func TestParsePrivateKeyFile_RSAComponents(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	key.Precompute()

	b64 := base64.StdEncoding.EncodeToString
	body := strings.Join([]string{
		"Modulus: " + b64(key.N.Bytes()),
		"PublicExponent: 65537",
		"PrivateExponent: " + b64(key.D.Bytes()),
		"Prime1: " + b64(key.Primes[0].Bytes()),
		"Prime2: " + b64(key.Primes[1].Bytes()),
	}, "\n")

	got, err := ParsePrivateKeyFile(bindEnvelope(protocol.AlgorithmRSASHA256, body),
		protocol.AlgorithmRSASHA256)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFile: %v", err)
	}
	parsed, ok := got.Key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key is %T, want *rsa.PrivateKey", got.Key)
	}
	if err := parsed.Validate(); err != nil {
		t.Errorf("reassembled key does not validate: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.D.Cmp(key.D) != 0 {
		t.Error("key components were not recovered")
	}
}

func TestParsePrivateKeyFile_RSAComponentsBase64Exponent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString
	body := strings.Join([]string{
		"Modulus: " + b64(key.N.Bytes()),
		"PublicExponent: " + b64([]byte{0x01, 0x00, 0x01}), // BIND encodes it like every other field
		"PrivateExponent: " + b64(key.D.Bytes()),
		"Prime1: " + b64(key.Primes[0].Bytes()),
		"Prime2: " + b64(key.Primes[1].Bytes()),
	}, "\n")

	got, err := ParsePrivateKeyFile(bindEnvelope(protocol.AlgorithmRSASHA256, body),
		protocol.AlgorithmRSASHA256)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFile: %v", err)
	}
	if got.Key.(*rsa.PrivateKey).E != 65537 {
		t.Errorf("public exponent = %d, want 65537", got.Key.(*rsa.PrivateKey).E)
	}
}

// TestParsePrivateKeyFile_RejectsWrongCurve guards the algorithm check from
// being lost in the move to one reader.
func TestParsePrivateKeyFile_RejectsWrongCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data := bindEnvelope(protocol.AlgorithmECDSAP384SHA384,
		"PrivateKey: "+base64.StdEncoding.EncodeToString(der))

	if _, err := ParsePrivateKeyFile(data, protocol.AlgorithmECDSAP384SHA384); err == nil {
		t.Error("a P-256 key was accepted for ECDSAP384SHA384")
	}
}

// TestParsePrivateKeyFile_StillAcceptsBareDER: the envelope support must not
// cost the formats that already worked.
func TestParsePrivateKeyFile_StillAcceptsBareDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := ParsePrivateKeyFile(der, protocol.AlgorithmECDSAP256SHA256)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFile: %v", err)
	}
	if !got.Key.(*ecdsa.PrivateKey).Equal(key) {
		t.Error("bare DER key was not recovered")
	}
}

func TestParsePrivateKeyFile_Rejects(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		algorithm uint8
	}{
		{"garbage", []byte("not a key at all"), protocol.AlgorithmECDSAP256SHA256},
		{"empty", nil, protocol.AlgorithmECDSAP256SHA256},
		{"unsupported algorithm", bindEnvelope(99, "PrivateKey: AAAA"), 99},
		{"scalar out of range", bindEnvelope(protocol.AlgorithmECDSAP256SHA256,
			"PrivateKey: "+base64.StdEncoding.EncodeToString(make([]byte, 32))),
			protocol.AlgorithmECDSAP256SHA256},
		{"RSA components without primes", bindEnvelope(protocol.AlgorithmRSASHA256,
			"Modulus: AQAB\nPrivateExponent: AQAB"), protocol.AlgorithmRSASHA256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrivateKeyFile(tc.data, tc.algorithm); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
