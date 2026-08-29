package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Private key file loading.
//
// A DNSSEC signing key on disk is conventionally a BIND-style ".private" file
// — a small text envelope of "Field: value" lines — and the config example
// names exactly such a path (Kexample.com.+013+12345.private). Two readers of
// that format existed: dnsctl parsed the envelope, while the daemon fed the
// whole text file straight to x509.ParseECPrivateKey. So `dnsctl dnssec
// generate-key` produced keys the server could not load:
//
//	Error: creating zone manager: loading zone signer for sec.test.:
//	loading private key "Ksec.test.+013+05772.private":
//	parsing ECDSA private key: asn1: structure error: tags don't match
//
// Zone signing was unreachable through the project's own documented workflow.
// This is the single reader both now use, and it also accepts genuine BIND
// files (raw scalar/seed, full RSA components), which neither reader did.

// ParsePrivateKeyFile decodes DNSSEC signing key material for the given
// algorithm. It accepts, in order of preference:
//
//   - a BIND-style ".private" envelope, whose PrivateKey field holds either
//     PKCS#8 DER (what dnsctl writes) or the raw scalar/seed (what BIND
//     writes), or whose RSA component fields describe the key directly;
//   - a PEM block;
//   - bare DER.
func ParsePrivateKeyFile(data []byte, algorithm uint8) (*PrivateKey, error) {
	if fields, ok := parseBINDPrivateKeyFields(data); ok {
		key, err := privateKeyFromBINDFields(fields, algorithm)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil
	}

	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return privateKeyFromDER(der, algorithm)
}

// parseBINDPrivateKeyFields splits a ".private" envelope into its fields.
// Reports false when the input does not look like one, so the caller can fall
// through to PEM/DER instead of reporting a confusing parse error.
func parseBINDPrivateKeyFields(data []byte) (map[string]string, bool) {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			// A PEM header or raw DER byte lands here; not an envelope.
			return nil, false
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if _, ok := fields["PrivateKey"]; ok {
		return fields, true
	}
	if _, ok := fields["Modulus"]; ok {
		return fields, true
	}
	return nil, false
}

func privateKeyFromBINDFields(fields map[string]string, algorithm uint8) (any, error) {
	if raw, ok := fields["PrivateKey"]; ok {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding PrivateKey field: %w", err)
		}
		// dnsctl stores PKCS#8 DER in this field; BIND stores the raw scalar
		// or seed. Try the structured form first — a raw scalar will not parse
		// as DER, and DER is far too long to be mistaken for a scalar.
		if key, err := privateKeyFromDER(decoded, algorithm); err == nil {
			return key.Key, nil
		}
		return rawPrivateKey(decoded, algorithm)
	}

	if algorithm != protocol.AlgorithmRSASHA256 && algorithm != protocol.AlgorithmRSASHA512 {
		return nil, fmt.Errorf("private key file has RSA component fields but algorithm is %d", algorithm)
	}
	return rsaPrivateKeyFromBINDFields(fields)
}

// rawPrivateKey builds a key from BIND's bare scalar (ECDSA) or seed (Ed25519).
func rawPrivateKey(raw []byte, algorithm uint8) (any, error) {
	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		curve := elliptic.P256()
		if algorithm == protocol.AlgorithmECDSAP384SHA384 {
			curve = elliptic.P384()
		}
		// BIND writes the scalar zero-padded to the curve's byte length,
		// which is exactly the SEC 1 §2.3.6 raw encoding. ParseRawPrivateKey
		// range-checks it and derives the public point itself; assembling the
		// key by hand from big.Int coordinates is both deprecated and easy to
		// get subtly wrong.
		size := (curve.Params().BitSize + 7) / 8
		if len(raw) > size {
			return nil, fmt.Errorf("ECDSA private key is %d bytes, want at most %d", len(raw), size)
		}
		padded := make([]byte, size)
		copy(padded[size-len(raw):], raw)
		key, err := ecdsa.ParseRawPrivateKey(curve, padded)
		if err != nil {
			return nil, fmt.Errorf("parsing raw ECDSA private key: %w", err)
		}
		return key, nil

	case protocol.AlgorithmED25519:
		switch len(raw) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(raw), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
		default:
			return nil, fmt.Errorf("Ed25519 private key is %d bytes, want %d or %d",
				len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
		}

	default:
		return nil, fmt.Errorf("algorithm %d has no raw private key encoding", algorithm)
	}
}

// rsaPrivateKeyFromBINDFields reassembles an RSA key from BIND's component
// fields. Primes are required: Go computes signatures through the CRT values
// derived from them, so a key carrying only Modulus and PrivateExponent — as
// dnsctl's own reader used to produce — cannot sign.
func rsaPrivateKeyFromBINDFields(fields map[string]string) (*rsa.PrivateKey, error) {
	num := func(name string) (*big.Int, error) {
		raw, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("private key file is missing the %s field", name)
		}
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding %s field: %w", name, err)
		}
		return new(big.Int).SetBytes(decoded), nil
	}

	modulus, err := num("Modulus")
	if err != nil {
		return nil, err
	}
	privateExp, err := num("PrivateExponent")
	if err != nil {
		return nil, err
	}
	prime1, err := num("Prime1")
	if err != nil {
		return nil, err
	}
	prime2, err := num("Prime2")
	if err != nil {
		return nil, err
	}

	// BIND writes the public exponent base64-encoded like every other field;
	// dnsctl writes it as a decimal integer. Accept both.
	publicExp := 65537
	if raw, ok := fields["PublicExponent"]; ok {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			publicExp = n
		} else {
			decoded, decErr := base64.StdEncoding.DecodeString(raw)
			if decErr != nil {
				return nil, fmt.Errorf("decoding PublicExponent field: %w", decErr)
			}
			e := new(big.Int).SetBytes(decoded)
			if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
				return nil, fmt.Errorf("RSA public exponent is out of range")
			}
			publicExp = int(e.Int64())
		}
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: modulus, E: publicExp},
		D:         privateExp,
		Primes:    []*big.Int{prime1, prime2},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("reassembled RSA private key is inconsistent: %w", err)
	}
	return key, nil
}

// privateKeyFromDER parses PKCS#1/PKCS#8/SEC1 DER for the given algorithm and
// checks that the key actually matches it.
func privateKeyFromDER(der []byte, algorithm uint8) (*PrivateKey, error) {
	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		key, err := parseRSADER(der)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	case protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384:
		key, err := parseECDSADER(der, algorithm)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	case protocol.AlgorithmED25519:
		key, err := parseEd25519DER(der)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{Algorithm: algorithm, Key: key}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

func parseRSADER(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", key)
	}
	return rsaKey, nil
}

func parseECDSADER(der []byte, algorithm uint8) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return checkECDSACurve(key, algorithm)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDSA private key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not ECDSA", key)
	}
	return checkECDSACurve(ecdsaKey, algorithm)
}

func checkECDSACurve(key *ecdsa.PrivateKey, algorithm uint8) (*ecdsa.PrivateKey, error) {
	switch algorithm {
	case protocol.AlgorithmECDSAP256SHA256:
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ECDSAP256SHA256 requires a P-256 private key")
		}
	case protocol.AlgorithmECDSAP384SHA384:
		if key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ECDSAP384SHA384 requires a P-384 private key")
		}
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %d", algorithm)
	}
	return key, nil
}

func parseEd25519DER(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, not Ed25519", key)
		}
		return edKey, nil
	}
	if len(der) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), der...)), nil
	}
	return nil, fmt.Errorf("parsing Ed25519 private key: %w", err)
}
