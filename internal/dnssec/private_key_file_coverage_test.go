// NothingDNS - Coverage: private key file parsing
//
// Moved here from cmd/nothingdns when the daemon and dnsctl were unified onto
// one reader; the functions under test live in this package now.
package dnssec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestParseRSAPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("PKCS1", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		key, err := parseRSADER(der)
		if err != nil {
			t.Fatalf("parseRSAPrivateKey: %v", err)
		}
		if key.N.BitLen() != 2048 {
			t.Fatalf("key size=%d want=2048", key.N.BitLen())
		}
	})

	t.Run("PKCS8", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		key, err := parseRSADER(der)
		if err != nil {
			t.Fatalf("parseRSAPrivateKey: %v", err)
		}
		if key.N.BitLen() != 2048 {
			t.Fatalf("key size=%d want=2048", key.N.BitLen())
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		_, err := parseRSADER([]byte("bogus"))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		_, err = parseRSADER(der)
		if err == nil {
			t.Fatal("expected error for non-RSA key")
		}
	})
}

func TestParseEd25519PrivateKey(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	t.Run("PKCS8", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		key, err := parseEd25519DER(der)
		if err != nil {
			t.Fatalf("parseEd25519: %v", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			t.Fatalf("key size=%d want=%d", len(key), ed25519.PrivateKeySize)
		}
	})

	t.Run("raw seed", func(t *testing.T) {
		seed := make([]byte, ed25519.PrivateKeySize)
		rand.Read(seed)
		key, err := parseEd25519DER(seed)
		if err != nil {
			t.Fatalf("parseEd25519: %v", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			t.Fatalf("key size=%d want=%d", len(key), ed25519.PrivateKeySize)
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		_, err := parseEd25519DER([]byte("bogus"))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("wrong PKCS8 type", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		_, err = parseEd25519DER(der)
		if err == nil {
			t.Fatal("expected error for non-Ed25519 key")
		}
	})

	t.Run("wrong size raw", func(t *testing.T) {
		_, err := parseEd25519DER([]byte("short"))
		if err == nil {
			t.Fatal("expected error for wrong size")
		}
	})
}

func TestParseECDSAPrivateKey(t *testing.T) {
	t.Run("P-256 EC DER", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey: %v", err)
		}
		key, err := parseECDSADER(der, protocol.AlgorithmECDSAP256SHA256)
		if err != nil {
			t.Fatalf("parseECDSAPrivateKey: %v", err)
		}
		if key.Curve != elliptic.P256() {
			t.Fatal("expected P-256")
		}
	})

	t.Run("P-384 PKCS8", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		key, err := parseECDSADER(der, protocol.AlgorithmECDSAP384SHA384)
		if err != nil {
			t.Fatalf("parseECDSAPrivateKey: %v", err)
		}
		if key.Curve != elliptic.P384() {
			t.Fatal("expected P-384")
		}
	})

	t.Run("wrong PKCS8 type", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		_, err = parseECDSADER(der, protocol.AlgorithmECDSAP256SHA256)
		if err == nil {
			t.Fatal("expected error for non-ECDSA")
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		_, err := parseECDSADER([]byte("bogus"), protocol.AlgorithmECDSAP256SHA256)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestValidateECDSAPrivateKeyCurve(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa P256: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa P384: %v", err)
	}

	t.Run("P256 ok", func(t *testing.T) {
		_, err := checkECDSACurve(p256Key, protocol.AlgorithmECDSAP256SHA256)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("P384 ok", func(t *testing.T) {
		_, err := checkECDSACurve(p384Key, protocol.AlgorithmECDSAP384SHA384)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("P256 wrong algo", func(t *testing.T) {
		_, err := checkECDSACurve(p256Key, protocol.AlgorithmECDSAP384SHA384)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("P384 wrong algo", func(t *testing.T) {
		_, err := checkECDSACurve(p384Key, protocol.AlgorithmECDSAP256SHA256)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unsupported algo", func(t *testing.T) {
		_, err := checkECDSACurve(p256Key, 255)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParseDNSSECPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa P384: %v", err)
	}

	t.Run("RSA SHA-256 PKCS1", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		pk, err := ParsePrivateKeyFile(der, protocol.AlgorithmRSASHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmRSASHA256 {
			t.Fatalf("Algorithm=%d want=%d", pk.Algorithm, protocol.AlgorithmRSASHA256)
		}
		_, ok := pk.Key.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("expected *rsa.PrivateKey")
		}
	})

	t.Run("RSA SHA-512 PKCS8", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		pk, err := ParsePrivateKeyFile(der, protocol.AlgorithmRSASHA512)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmRSASHA512 {
			t.Fatalf("Algorithm=%d want=%d", pk.Algorithm, protocol.AlgorithmRSASHA512)
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey: %v", err)
		}
		pk, err := ParsePrivateKeyFile(der, protocol.AlgorithmECDSAP256SHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
			t.Fatalf("Algorithm=%d want=%d", pk.Algorithm, protocol.AlgorithmECDSAP256SHA256)
		}
	})

	t.Run("ECDSA P-384", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(ecKey384)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		pk, err := ParsePrivateKeyFile(der, protocol.AlgorithmECDSAP384SHA384)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmECDSAP384SHA384 {
			t.Fatalf("Algorithm=%d want=%d", pk.Algorithm, protocol.AlgorithmECDSAP384SHA384)
		}
	})

	t.Run("Ed25519 PEM", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		pemData := pemBlock("PRIVATE KEY", der)
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmED25519)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmED25519 {
			t.Fatalf("Algorithm=%d want=%d", pk.Algorithm, protocol.AlgorithmED25519)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := ParsePrivateKeyFile([]byte("anything"), 255)
		if err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
	})
}

func TestParseDNSSECPrivateKey_PEM_AllAlgorithms(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("RSA PEM", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemData := pemBlock("RSA PRIVATE KEY", der)
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmRSASHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmRSASHA256 {
			t.Fatalf("Algorithm=%d", pk.Algorithm)
		}
	})

	t.Run("EC PEM", func(t *testing.T) {
		der, _ := x509.MarshalECPrivateKey(ecKey)
		pemData := pemBlock("EC PRIVATE KEY", der)
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmECDSAP256SHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
			t.Fatalf("Algorithm=%d", pk.Algorithm)
		}
	})

	t.Run("Ed25519 PEM", func(t *testing.T) {
		der, _ := x509.MarshalPKCS8PrivateKey(edKey)
		pemData := pemBlock("PRIVATE KEY", der)
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmED25519)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmED25519 {
			t.Fatalf("Algorithm=%d", pk.Algorithm)
		}
	})
}

// TestValidateECDSAPrivateKeyCurvePEM tests curve validation with PEM-wrapped keys
func TestValidateECDSAPrivateKeyCurvePEM(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// PEM wrap around PKCS8
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	pemData := pemBlock("PRIVATE KEY", der)

	pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmECDSAP256SHA256)
	if err != nil {
		t.Fatalf("parseDNSSECPrivateKey: %v", err)
	}
	if pk.Algorithm != protocol.AlgorithmECDSAP256SHA256 {
		t.Fatalf("Algorithm=%d", pk.Algorithm)
	}
}

// TestParseRSAPrivateKeyPEM tests PEM-wrapped RSA key parsing
func TestParseRSAPrivateKeyPEM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// PKCS1 PEM
	t.Run("PKCS1 PEM", func(t *testing.T) {
		der := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemData := pemBlock("RSA PRIVATE KEY", der)
		// parseDNSSECPrivateKey will strip PEM and call parseRSAPrivateKey
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmRSASHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		if pk.Algorithm != protocol.AlgorithmRSASHA256 {
			t.Fatalf("Algorithm=%d", pk.Algorithm)
		}
	})

	// PKCS8 PEM
	t.Run("PKCS8 PEM", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("MarshalPKCS8: %v", err)
		}
		pemData := pemBlock("PRIVATE KEY", der)
		pk, err := ParsePrivateKeyFile(pemData, protocol.AlgorithmRSASHA256)
		if err != nil {
			t.Fatalf("parseDNSSECPrivateKey: %v", err)
		}
		_, ok := pk.Key.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("expected *rsa.PrivateKey")
		}
	})
}

// TestParseDNSSECPrivateKey_Ed25519RSAMismatch tests that RSA PEM fails for Ed25519 algorithm
func TestParseDNSSECPrivateKey_Ed25519RSAMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Try to parse as Ed25519 - should fail type assertion
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	_, err = ParsePrivateKeyFile(der, protocol.AlgorithmED25519)
	if err == nil {
		t.Fatal("expected error for RSA key parsed as Ed25519")
	}
}

// TestParseDNSSECPrivateKey_ECDSAEd25519Mismatch tests Ed25519 algorithm with EC key
func TestParseDNSSECPrivateKey_ECDSAEd25519Mismatch(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	// Try Ed25519 path with ECDSA key - will hit PKCS8 parse failure, then wrong size
	_, err = ParsePrivateKeyFile(der, protocol.AlgorithmED25519)
	if err == nil {
		t.Fatal("expected error for ECDSA key parsed as Ed25519")
	}
}

// pemBlock is a test helper for PEM encoding.
func pemBlock(typ string, der []byte) []byte {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: typ, Bytes: der})
	return buf.Bytes()
}
