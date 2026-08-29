package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

const (
	maxDNSCTLKeyFileSize  = 1 << 20
	maxDNSCTLZoneFileSize = 64 << 20
)

func cmdDNSSEC(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dnssec subcommand required (status, keys, generate-key, ds-from-dnskey, sign-zone, verify-anchor, validate-zone)")
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "status":
		return cmdDNSSECStatus(subArgs)
	case "keys":
		return cmdDNSSECKeys(subArgs)
	case "generate-key":
		return cmdDNSSECGenerateKey(subArgs)
	case "ds-from-dnskey":
		return cmdDNSSECDSFromDNSKEY(subArgs)
	case "sign-zone":
		return cmdDNSSECSignZone(subArgs)
	case "verify-anchor":
		return cmdDNSSECVerifyAnchor(subArgs)
	case "validate-zone":
		return cmdDNSSECValidateZone(subArgs)
	default:
		return fmt.Errorf("unknown dnssec subcommand: %s (supported: status, keys, generate-key, ds-from-dnskey, sign-zone, verify-anchor, validate-zone)", subcmd)
	}
}

func newDNSSECFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func readDNSCTLFile(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSize)
	}
	return data, nil
}

// cmdDNSSECStatus queries the live daemon's validator state via
// GET /api/v1/dnssec/status — reports whether DNSSEC validation is
// enabled, the configured trust anchor count, and the validation
// cache hit/miss counters.
func cmdDNSSECStatus(_ []string) error {
	result, err := apiGet("/api/v1/dnssec/status")
	if err != nil {
		return err
	}
	fmt.Println("DNSSEC Status:")
	printJSON("dnssec", result, "  ")
	return nil
}

// cmdDNSSECKeys queries the daemon's per-zone signer keys via
// GET /api/v1/dnssec/keys. Admin role is required by the server.
func cmdDNSSECKeys(_ []string) error {
	result, err := apiGet("/api/v1/dnssec/keys")
	if err != nil {
		return err
	}
	zones, _ := result["zones"].([]interface{})
	if len(zones) == 0 {
		fmt.Println("No DNSSEC keys configured.")
		return nil
	}
	fmt.Printf("%-30s %-8s %-9s %-5s %-5s\n", "ZONE", "KEY-TAG", "ALGORITHM", "KSK", "ZSK")
	fmt.Printf("%-30s %-8s %-9s %-5s %-5s\n",
		strings.Repeat("-", 30), strings.Repeat("-", 8),
		strings.Repeat("-", 9), strings.Repeat("-", 5), strings.Repeat("-", 5))
	for _, z := range zones {
		k, ok := z.(map[string]interface{})
		if !ok {
			continue
		}
		zone, _ := k["zone"].(string)
		keyTag := fmt.Sprintf("%v", k["key_tag"])
		algo := fmt.Sprintf("%v", k["algorithm"])
		ksk := fmt.Sprintf("%v", k["is_ksk"])
		zsk := fmt.Sprintf("%v", k["is_zsk"])
		fmt.Printf("%-30s %-8s %-9s %-5s %-5s\n", zone, keyTag, algo, ksk, zsk)
	}
	return nil
}

func cmdDNSSECGenerateKey(args []string) error {
	fs := newDNSSECFlagSet("generate-key")
	algorithm := fs.Int("algorithm", 13, "DNSSEC algorithm (8=RSASHA256, 10=RSASHA512, 13=ECDSAP256SHA256, 14=ECDSAP384SHA384, 15=ED25519)")
	keyType := fs.String("type", "ZSK", "Key type (KSK or ZSK)")
	zone := fs.String("zone", "", "Zone name (required)")
	outputDir := fs.String("output", ".", "Output directory for key files")
	keySize := fs.Int("keysize", 0, "Key size in bits (for RSA: 2048, 3072, 4096)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" {
		return fmt.Errorf("zone name is required")
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Normalize key type
	*keyType = strings.ToUpper(*keyType)
	isKSK := *keyType == "KSK"

	alg, err := validateGeneratedKeyAlgorithm(*algorithm)
	if err != nil {
		return err
	}

	// Generate key pair
	signingKey, err := generateKeyPair(alg, isKSK, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate key file names
	keyTag := signingKey.KeyTag
	algStr := fmt.Sprintf("%03d", alg)
	baseName := fmt.Sprintf("K%s+%s+%05d", *zone, algStr, keyTag)

	// Write private key file
	privateKeyPath := filepath.Join(*outputDir, baseName+".private")
	if err := writePrivateKey(privateKeyPath, signingKey); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key file (DNSKEY format)
	publicKeyPath := filepath.Join(*outputDir, baseName+".key")
	if err := writePublicKey(publicKeyPath, *zone, signingKey); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Printf("Generated %s key for %s:\n", *keyType, *zone)
	fmt.Printf("  Algorithm: %d (%s)\n", alg, algorithmName(alg))
	fmt.Printf("  Key Tag: %d\n", keyTag)
	fmt.Printf("  Private key: %s\n", privateKeyPath)
	fmt.Printf("  Public key: %s\n", publicKeyPath)

	// If KSK, print DS record info
	if isKSK {
		ds, err := dnssec.CreateDS(*zone, signingKey.DNSKEY, 2) // SHA-256
		if err != nil {
			return fmt.Errorf("failed to create DS: %w", err)
		}
		fmt.Printf("\nDS record (SHA-256):\n")
		fmt.Printf("  %s IN DS %d %d %d %s\n", *zone, ds.KeyTag, ds.Algorithm, ds.DigestType, hexEncode(ds.Digest))
	}

	return nil
}

func cmdDNSSECDSFromDNSKEY(args []string) error {
	fs := newDNSSECFlagSet("ds-from-dnskey")
	zone := fs.String("zone", "", "Zone name (required)")
	keyFile := fs.String("keyfile", "", "Public key file path (required)")
	digestType := fs.Int("digest", 2, "Digest type (1=SHA-1, 2=SHA-256, 4=SHA-384)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" || *keyFile == "" {
		return fmt.Errorf("zone and keyfile are required")
	}

	digest, err := validateDSDigestType(*digestType)
	if err != nil {
		return err
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Read DNSKEY from file
	dnskey, err := readDNSKEYFromFile(*keyFile)
	if err != nil {
		return fmt.Errorf("failed to read DNSKEY: %w", err)
	}

	// Create DS record
	ds, err := dnssec.CreateDS(*zone, dnskey, digest)
	if err != nil {
		return fmt.Errorf("failed to create DS: %w", err)
	}

	fmt.Printf("DS record for %s:\n", *zone)
	fmt.Printf("  %s IN DS %d %d %d %s\n", *zone, ds.KeyTag, ds.Algorithm, ds.DigestType, hexEncode(ds.Digest))

	return nil
}

func cmdDNSSECSignZone(args []string) error {
	fs := newDNSSECFlagSet("sign-zone")
	zone := fs.String("zone", "", "Zone name (required)")
	inputFile := fs.String("input", "", "Input zone file (required)")
	outputFile := fs.String("output", "", "Output signed zone file (default: <input>.signed)")
	keyDir := fs.String("keydir", ".", "Directory containing key files")
	algorithm := fs.Int("algorithm", 13, "DNSSEC algorithm for generated keys (3-16, default: 13=ECDSAP256SHA256)")
	keySize := fs.Int("keysize", 0, "Key size in bits for RSA algorithms (must be > 0 for RSA)")
	nsec3 := fs.Bool("nsec3", false, "Use NSEC3 instead of NSEC")
	nsec3Iterations := fs.Int("iterations", 0, "NSEC3 iterations")
	nsec3Salt := fs.String("salt", "", "NSEC3 salt (hex string)")
	validity := fs.String("validity", "720h", "Signature validity (Go duration)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" || *inputFile == "" {
		return fmt.Errorf("zone and input are required")
	}

	// Validate algorithm
	if *algorithm < 3 || *algorithm > 16 {
		return fmt.Errorf("invalid algorithm %d: must be in range 3-16", *algorithm)
	}

	// Validate keysize for RSA algorithms
	isRSA := *algorithm == int(protocol.AlgorithmRSASHA1) ||
		*algorithm == int(protocol.AlgorithmRSASHA1NSEC3) ||
		*algorithm == int(protocol.AlgorithmRSASHA256) ||
		*algorithm == int(protocol.AlgorithmRSASHA512) ||
		*algorithm == int(protocol.AlgorithmRSAMD5)
	if isRSA && *keySize <= 0 {
		return fmt.Errorf("keysize must be > 0 for RSA algorithms (recommended: 2048, 3072, or 4096)")
	}
	nsec3Iter := uint16(0)
	if *nsec3 {
		iter, err := validateNSEC3Iterations(*nsec3Iterations)
		if err != nil {
			return err
		}
		nsec3Iter = iter
	}

	if *outputFile == "" {
		*outputFile = *inputFile + ".signed"
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Parse signature validity
	sigValidity, err := time.ParseDuration(*validity)
	if err != nil {
		return fmt.Errorf("invalid validity duration %q: %w", *validity, err)
	}

	fmt.Printf("Signing zone %s...\n", *zone)
	fmt.Printf("  Input:      %s\n", *inputFile)
	fmt.Printf("  Output:     %s\n", *outputFile)
	fmt.Printf("  Algorithm:  %d (%s)\n", *algorithm, algorithmName(uint8(*algorithm)))
	fmt.Printf("  NSEC3:      %v\n", *nsec3)
	fmt.Printf("  Validity:   %s\n", sigValidity)

	// Create signer
	signerCfg := dnssec.DefaultSignerConfig()
	signerCfg.SignatureValidity = sigValidity
	if *nsec3 {
		signerCfg.NSEC3Enabled = true
		signerCfg.NSEC3Iterations = nsec3Iter
		if *nsec3Salt != "" {
			salt, err := hex.DecodeString(*nsec3Salt)
			if err != nil {
				return fmt.Errorf("invalid NSEC3 salt: %w", err)
			}
			signerCfg.NSEC3Salt = salt
		}
	}

	signer := dnssec.NewSigner(*zone, signerCfg)

	// Load key files from key directory
	keyFiles, err := findKeyFiles(*keyDir, *zone)
	if err != nil {
		return fmt.Errorf("finding key files: %w", err)
	}

	for _, kf := range keyFiles {
		key, err := loadSigningKey(kf, *zone)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load key %s: %v\n", kf, err)
			continue
		}
		signer.AddKey(key)
		fmt.Printf("  Loaded key: %s (tag=%d, %s)\n", filepath.Base(kf), key.KeyTag, keyType(key))
	}

	// If no key files found, generate KSK + ZSK pair using the specified algorithm
	if len(signer.GetKeys()) == 0 {
		fmt.Printf("  No key files found; generating KSK + ZSK with algorithm %d (%s)\n",
			*algorithm, algorithmName(uint8(*algorithm)))

		ksk, err := signer.GenerateKeyPair(uint8(*algorithm), true)
		if err != nil {
			return fmt.Errorf("generating KSK: %w", err)
		}
		fmt.Printf("  Generated KSK: tag=%d\n", ksk.KeyTag)

		zsk, err := signer.GenerateKeyPair(uint8(*algorithm), false)
		if err != nil {
			return fmt.Errorf("generating ZSK: %w", err)
		}
		fmt.Printf("  Generated ZSK: tag=%d\n", zsk.KeyTag)
	}

	keys := signer.GetKeys()
	if len(keys) == 0 {
		return fmt.Errorf("no valid signing keys available")
	}

	// Parse zone file into resource records
	content, err := readDNSCTLFile(*inputFile, maxDNSCTLZoneFileSize)
	if err != nil {
		return fmt.Errorf("reading zone file: %w", err)
	}

	records, err := parseZoneRecords(string(content), *zone)
	if err != nil {
		return fmt.Errorf("parsing zone file: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("no valid records found in zone file %s", *inputFile)
	}
	fmt.Printf("  Parsed %d records from zone file\n", len(records))

	// Sign the zone
	signedRecords, err := signer.SignZone(records)
	if err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	// Format signed zone as BIND zone file
	var output strings.Builder
	output.WriteString(fmt.Sprintf("; Signed zone: %s\n", *zone))
	output.WriteString(fmt.Sprintf("; Signed at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("; Algorithm: %d (%s)\n", *algorithm, algorithmName(uint8(*algorithm))))
	output.WriteString(fmt.Sprintf("; Keys: %d, Validity: %s\n;\n", len(keys), sigValidity))

	for _, rr := range signedRecords {
		output.WriteString(rr.String())
		output.WriteByte('\n')
	}

	if err := writeDNSCTLFile(*outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("writing signed zone: %w", err)
	}

	fmt.Printf("\nZone signed successfully: %s\n", *outputFile)
	fmt.Printf("  Input records:   %d\n", len(records))
	fmt.Printf("  Signed records:  %d (includes DNSKEY, RRSIG, NSEC)\n", len(signedRecords))
	fmt.Printf("  Keys used:       %d\n", len(keys))

	return nil
}

// parseZoneRecords parses a BIND-format zone file into resource records.
//
// KNOWN LIMITATION: this is a deliberately minimal line-by-line parser
// for sign-zone / validate-zone. It ignores `$TTL`, `$ORIGIN`,
// `$GENERATE`, and multi-line parens — every record must be on one
// line with explicit `name TTL IN TYPE rdata` columns. For BIND zone
// files that rely on those directives, pre-expand the file with
// `named-checkzone -D <origin> <zonefile>` (or any other YAML/zone
// expander) and feed the result here.
//
// The daemon's loader (internal/zone.ParseFile) supports the full
// BIND grammar; switching this CLI to it would change the behavior
// asserted by ~14 existing unit tests, so the migration is its own
// task. Smoke-tested 2026-05-22: dnsctl dnssec sign-zone on a vanilla
// `$ORIGIN example.com. / $TTL 3600 / @ IN SOA ...` zone file errors
// with "no valid records found" because the `$` directives and the
// explicit-TTL-less SOA fail this parser's `name TTL IN TYPE rdata`
// format check.
func parseZoneRecords(data, origin string) ([]*protocol.ResourceRecord, error) {
	var records []*protocol.ResourceRecord
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Determine field positions: name ttl class type rdata
		name := fields[0]
		ttlStr := fields[1]
		classStr := fields[2]
		typeStr := strings.ToUpper(fields[3])
		rdata := ""
		if len(fields) > 4 {
			rdata = strings.Join(fields[4:], " ")
		}

		ttl, err := strconv.ParseUint(ttlStr, 10, 32)
		if err != nil {
			continue
		}

		if !strings.EqualFold(classStr, "IN") {
			continue
		}

		// Expand @ to origin
		if name == "@" {
			name = origin
		} else if !strings.HasSuffix(name, ".") {
			// Relative name: append origin
			name = name + "." + origin
		}

		owner, err := protocol.ParseName(name)
		if err != nil {
			continue
		}

		rrtype, ok := protocol.StringToType[typeStr]
		if !ok || rrtype == 0 {
			continue
		}

		rdataObj, err := parseRDataFromZone(rrtype, rdata)
		if err != nil {
			continue
		}

		records = append(records, &protocol.ResourceRecord{
			Name:  owner,
			Type:  rrtype,
			Class: protocol.ClassIN,
			TTL:   uint32(ttl),
			Data:  rdataObj,
		})
	}

	return records, nil
}

func cmdDNSSECVerifyAnchor(args []string) error {
	fs := newDNSSECFlagSet("verify-anchor")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("trust anchor file path is required")
	}

	anchorFile := fs.Arg(0)

	// Parse trust anchor file
	store := dnssec.NewTrustAnchorStore()
	if err := store.LoadFromFile(anchorFile); err != nil {
		return fmt.Errorf("failed to parse trust anchor file: %w", err)
	}

	zones := store.GetAllZones()
	fmt.Printf("Trust anchor file verified: %s\n", anchorFile)
	fmt.Printf("  Zones: %d\n", len(zones))
	for _, zone := range zones {
		anchors := store.GetAnchorsForZone(zone)
		fmt.Printf("  %s: %d anchor(s)\n", zone, len(anchors))
		for _, a := range anchors {
			valid := "valid"
			if !a.IsValid() {
				valid = "INVALID"
			}
			fmt.Printf("    - KeyTag: %d, Algorithm: %d (%s), %s\n",
				a.KeyTag, a.Algorithm, algorithmName(a.Algorithm), valid)
		}
	}

	return nil
}

// Helper functions

// rrsigTimeState classifies an RRSIG's validity window at time now using the
// shared RFC 1982 serial arithmetic in internal/protocol. A signature that is
// not yet valid is reported as such even if its window is also in the past.
func rrsigTimeState(rrsig *protocol.RDataRRSIG, now uint32) (notYetValid, expired bool) {
	if !rrsig.IsInceptionValidAt(now) {
		return true, false
	}
	if rrsig.IsExpiredAt(now) {
		return false, true
	}
	return false, false
}

func validateGeneratedKeyAlgorithm(algorithm int) (uint8, error) {
	switch algorithm {
	case int(protocol.AlgorithmRSASHA256),
		int(protocol.AlgorithmRSASHA512),
		int(protocol.AlgorithmECDSAP256SHA256),
		int(protocol.AlgorithmECDSAP384SHA384),
		int(protocol.AlgorithmED25519):
		return uint8(algorithm), nil
	default:
		return 0, fmt.Errorf("invalid algorithm %d: supported key generation algorithms are 8, 10, 13, 14, and 15", algorithm)
	}
}

func validateDSDigestType(digestType int) (uint8, error) {
	switch digestType {
	case 1, 2, 4:
		return uint8(digestType), nil
	default:
		return 0, fmt.Errorf("invalid digest type %d: must be one of 1, 2, or 4", digestType)
	}
}

func validateNSEC3Iterations(iterations int) (uint16, error) {
	if iterations < 0 || iterations > 65535 {
		return 0, fmt.Errorf("invalid NSEC3 iterations %d: must be in range 0-65535", iterations)
	}
	return uint16(iterations), nil
}

func generateKeyPair(algorithm uint8, isKSK bool, keySize int) (*dnssec.SigningKey, error) {
	const maxKeyTagAttempts = 16

	for attempt := 0; attempt < maxKeyTagAttempts; attempt++ {
		key, err := generateKeyPairOnce(algorithm, isKSK, keySize)
		if err != nil {
			return nil, err
		}
		if key.KeyTag != 0 {
			return key, nil
		}
	}

	return nil, fmt.Errorf("generated DNSSEC key tag was zero after %d attempts", maxKeyTagAttempts)
}

func generateKeyPairOnce(algorithm uint8, isKSK bool, keySize int) (*dnssec.SigningKey, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var err error

	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		size := 2048
		if keySize > 0 {
			size = keySize
		}
		rsaKey, rsaErr := rsa.GenerateKey(rand.Reader, size)
		if rsaErr != nil {
			return nil, rsaErr
		}
		privKey = rsaKey
		pubKey = &rsaKey.PublicKey

	case protocol.AlgorithmECDSAP256SHA256:
		ecKey, ecErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if ecErr != nil {
			return nil, ecErr
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey

	case protocol.AlgorithmECDSAP384SHA384:
		ecKey, ecErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if ecErr != nil {
			return nil, ecErr
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey

	case protocol.AlgorithmED25519:
		// Ed25519 keys are 32-byte fixed; keySize is ignored.
		pub, priv, edErr := ed25519.GenerateKey(rand.Reader)
		if edErr != nil {
			return nil, edErr
		}
		privKey = priv
		pubKey = pub

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}

	// Create DNSKEY record
	flags := uint16(protocol.DNSKEYFlagZone)
	if isKSK {
		flags |= protocol.DNSKEYFlagSEP
	}

	// Pack the public key using dnssec.PublicKey wrapper
	dnssecPubKey := &dnssec.PublicKey{
		Algorithm: algorithm,
		Key:       pubKey,
	}
	publicKey, err := dnssec.PackDNSKEYPublicKey(dnssecPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to pack public key: %w", err)
	}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	return &dnssec.SigningKey{
		PrivateKey: &dnssec.PrivateKey{Algorithm: algorithm, Key: privKey},
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}, nil
}

func writePrivateKey(path string, key *dnssec.SigningKey) error {
	var content strings.Builder
	content.WriteString("Private-key-format: v1.3\n")
	content.WriteString(fmt.Sprintf("Algorithm: %d (%s)\n", key.DNSKEY.Algorithm, algorithmName(key.DNSKEY.Algorithm)))
	content.WriteString(fmt.Sprintf("KeyTag: %d\n", key.KeyTag))
	content.WriteString(fmt.Sprintf("Created: %s\n", time.Now().UTC().Format(time.RFC3339)))

	// Serialize private key based on algorithm
	switch k := key.PrivateKey.Key.(type) {
	case *rsa.PrivateKey:
		content.WriteString(fmt.Sprintf("Modulus: %s\n", base64.StdEncoding.EncodeToString(k.N.Bytes())))
		content.WriteString(fmt.Sprintf("PublicExponent: %d\n", k.E))
		content.WriteString(fmt.Sprintf("PrivateExponent: %s\n", base64.StdEncoding.EncodeToString(k.D.Bytes())))
		if len(k.Primes) >= 2 {
			content.WriteString(fmt.Sprintf("Prime1: %s\n", base64.StdEncoding.EncodeToString(k.Primes[0].Bytes())))
			content.WriteString(fmt.Sprintf("Prime2: %s\n", base64.StdEncoding.EncodeToString(k.Primes[1].Bytes())))
			k.Precompute()
			content.WriteString(fmt.Sprintf("Exponent1: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Dp.Bytes())))
			content.WriteString(fmt.Sprintf("Exponent2: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Dq.Bytes())))
			content.WriteString(fmt.Sprintf("Coefficient: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Qinv.Bytes())))
		}

	case *ecdsa.PrivateKey:
		// Write in PKCS8 DER format (base64 encoded)
		derBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("marshaling ECDSA key: %w", err)
		}
		content.WriteString(fmt.Sprintf("PrivateKey: %s\n", base64.StdEncoding.EncodeToString(derBytes)))

	default:
		// Fallback: write as PKCS8
		derBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("marshaling private key: %w", err)
		}
		content.WriteString(fmt.Sprintf("PrivateKey: %s\n", base64.StdEncoding.EncodeToString(derBytes)))
	}

	return writeDNSCTLFile(path, []byte(content.String()), 0600)
}

func writePublicKey(path string, zone string, key *dnssec.SigningKey) error {
	// DNSKEY format
	content := fmt.Sprintf("; DNSKEY record for %s\n", zone)
	content += fmt.Sprintf("%s IN DNSKEY %d %d %d %s\n",
		zone,
		key.DNSKEY.Flags,
		key.DNSKEY.Protocol,
		key.DNSKEY.Algorithm,
		base64.StdEncoding.EncodeToString(key.DNSKEY.PublicKey))

	return writeDNSCTLFile(path, []byte(content), 0644)
}

func writeDNSCTLFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			os.Remove(tmpPath)
		}
	}()

	if err := util.WriteFull(tmp, data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keepTemp = true
	return nil
}

func readDNSKEYFromFile(path string) (*protocol.RDataDNSKEY, error) {
	data, err := readDNSCTLFile(path, maxDNSCTLKeyFileSize)
	if err != nil {
		return nil, err
	}

	// Parse DNSKEY from file
	// Format: name IN DNSKEY flags protocol algorithm base64key
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Find DNSKEY keyword
		dnskeyIdx := -1
		for i, p := range parts {
			if strings.ToUpper(p) == "DNSKEY" {
				dnskeyIdx = i
				break
			}
		}

		if dnskeyIdx == -1 || len(parts) < dnskeyIdx+4 {
			continue
		}

		flags, err := strconv.ParseUint(parts[dnskeyIdx+1], 10, 16)
		if err != nil {
			continue
		}

		protocol_val, err := strconv.ParseUint(parts[dnskeyIdx+2], 10, 8)
		if err != nil {
			continue
		}

		algorithm, err := strconv.ParseUint(parts[dnskeyIdx+3], 10, 8)
		if err != nil {
			continue
		}

		publicKey, err := base64.StdEncoding.DecodeString(parts[dnskeyIdx+4])
		if err != nil {
			continue
		}

		return &protocol.RDataDNSKEY{
			Flags:     uint16(flags),
			Protocol:  uint8(protocol_val),
			Algorithm: uint8(algorithm),
			PublicKey: publicKey,
		}, nil
	}

	return nil, fmt.Errorf("no valid DNSKEY found in file")
}

func algorithmName(alg uint8) string {
	names := map[uint8]string{
		1:  "RSAMD5",
		5:  "RSASHA1",
		7:  "RSASHA1NSEC3SHA1",
		8:  "RSASHA256",
		10: "RSASHA512",
		13: "ECDSAP256SHA256",
		14: "ECDSAP384SHA384",
		15: "ED25519",
		16: "ED448",
	}
	if name, ok := names[alg]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", alg)
}

func hexEncode(data []byte) string {
	return fmt.Sprintf("%X", data)
}

// findKeyFiles discovers DNSSEC key files in the given directory for a zone.
// Key files follow the BIND naming convention: K<zone>+<algorithm>+<keytag>.key
//
// generate-key emits the trailing-dot form (`Kexample.com.+013+12345.key`)
// since the zone name is normalised with a trailing dot before key
// generation. Earlier this function stripped the trailing dot and the
// pattern `Kexample.com+*.key` failed to match the actual files —
// every sign-zone run claimed "No key files found" and regenerated
// fresh keys, defeating key reuse entirely. We now try the FQDN
// form first, falling back to the dot-less form for files produced
// by external tools that don't normalise.
func findKeyFiles(dir, zone string) ([]string, error) {
	// Try FQDN form (with trailing dot) first.
	fqdn := zone
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	pattern := fmt.Sprintf("K%s+*.key", fqdn)
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}
	if len(matches) > 0 {
		return matches, nil
	}

	// Fall back to dot-less form for files from other tooling.
	zoneName := strings.TrimSuffix(zone, ".")
	pattern = fmt.Sprintf("K%s+*.key", zoneName)
	return filepath.Glob(filepath.Join(dir, pattern))
}

// loadSigningKey loads a signing key from a .key/.private file pair.
func loadSigningKey(keyPath, zone string) (*dnssec.SigningKey, error) {
	// Read the public key file
	dnskey, err := readDNSKEYFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading DNSKEY: %w", err)
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	isKSK := dnskey.Flags&protocol.DNSKEYFlagSEP != 0

	// Read private key file
	privatePath := strings.TrimSuffix(keyPath, ".key") + ".private"
	privKey, err := loadPrivateKey(privatePath, dnskey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	return &dnssec.SigningKey{
		PrivateKey: &dnssec.PrivateKey{Algorithm: dnskey.Algorithm, Key: privKey},
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}, nil
}

// loadPrivateKey reads a private key from a BIND-format ".private" file.
//
// The daemon reads the same files, so both go through one parser — this
// command's own version accepted only PKCS#8 DER in the PrivateKey field and
// reassembled RSA keys without their primes, producing keys that cannot sign.
func loadPrivateKey(path string, algorithm uint8) (crypto.PrivateKey, error) {
	data, err := readDNSCTLFile(path, maxDNSCTLKeyFileSize)
	if err != nil {
		return nil, err
	}
	key, err := dnssec.ParsePrivateKeyFile(data, algorithm)
	if err != nil {
		return nil, err
	}
	return key.Key, nil
}

// keyType returns "KSK" or "ZSK" for a signing key.
func keyType(key *dnssec.SigningKey) string {
	if key.IsKSK {
		return "KSK"
	}
	return "ZSK"
}

func cmdDNSSECValidateZone(args []string) error {
	fs := newDNSSECFlagSet("validate-zone")
	zoneFile := fs.String("zone", "", "Zone file to validate (required)")
	ignoreTime := fs.Bool("ignore-time", false, "Ignore signature timestamps (for testing)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zoneFile == "" {
		return fmt.Errorf("zone file is required (-zone)")
	}

	// Read the zone file
	data, err := readDNSCTLFile(*zoneFile, maxDNSCTLZoneFileSize)
	if err != nil {
		return fmt.Errorf("reading zone file: %w", err)
	}

	// Parse zone records
	lines := strings.Split(string(data), "\n")
	var records []*protocol.ResourceRecord
	var dnskeyRRs []*protocol.ResourceRecord
	var rrsigRRs []*protocol.ResourceRecord

	for lineNo, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		ttlStr := fields[1]
		classStr := fields[2]
		typeStr := strings.ToUpper(fields[3])
		rdata := strings.Join(fields[4:], " ")

		ttl, err := strconv.ParseUint(ttlStr, 10, 32)
		if err != nil {
			continue
		}

		if !strings.EqualFold(classStr, "IN") {
			continue
		}

		owner, err := protocol.ParseName(name)
		if err != nil {
			continue
		}

		rrtype := protocol.StringToType[typeStr]
		if rrtype == 0 {
			continue
		}

		rdataObj, err := parseRDataFromZone(rrtype, rdata)
		if err != nil {
			if rrtype == protocol.TypeDNSKEY || rrtype == protocol.TypeRRSIG || rrtype == protocol.TypeNSEC || rrtype == protocol.TypeNSEC3 {
				return fmt.Errorf("line %d: invalid %s RDATA: %w", lineNo+1, typeStr, err)
			}
			continue
		}

		rr := &protocol.ResourceRecord{
			Name:  owner,
			Type:  rrtype,
			Class: protocol.ClassIN,
			TTL:   uint32(ttl),
			Data:  rdataObj,
		}
		records = append(records, rr)

		switch rrtype {
		case protocol.TypeDNSKEY:
			dnskeyRRs = append(dnskeyRRs, rr)
		case protocol.TypeRRSIG:
			rrsigRRs = append(rrsigRRs, rr)
		}
	}

	fmt.Printf("Zone file: %s\n", *zoneFile)
	fmt.Printf("Records found: %d (DNSKEY: %d, RRSIG: %d)\n", len(records), len(dnskeyRRs), len(rrsigRRs))

	if len(records) == 0 {
		return fmt.Errorf("no valid records found in zone file")
	}

	if len(dnskeyRRs) == 0 {
		fmt.Println("WARNING: No DNSKEY records found - zone may be unsigned")
		return nil
	}

	if len(rrsigRRs) == 0 {
		fmt.Println("WARNING: No RRSIG records found - zone is not signed")
		return nil
	}

	// Build DNSKEY map for verification
	dnskeyMap := make(map[uint16]*protocol.RDataDNSKEY)
	for _, rr := range dnskeyRRs {
		if dnskey, ok := rr.Data.(*protocol.RDataDNSKEY); ok {
			keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
			dnskeyMap[keyTag] = dnskey
			fmt.Printf("  DNSKEY: keytag=%d algorithm=%d flags=%d\n", keyTag, dnskey.Algorithm, dnskey.Flags)
		}
	}

	// Verify each RRSIG
	validSigs := 0
	invalidSigs := 0
	expiredSigs := 0

	for _, rr := range rrsigRRs {
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok {
			fmt.Printf("  ERROR: Invalid RRSIG record at %s\n", rr.Name.String())
			invalidSigs++
			continue
		}

		dnskey, ok := dnskeyMap[rrsig.KeyTag]
		if !ok {
			fmt.Printf("  ERROR: No DNSKEY found for keytag %d (covering %s type %d)\n",
				rrsig.KeyTag, rr.Name.String(), rrsig.TypeCovered)
			invalidSigs++
			continue
		}

		// Check timestamps
		if !*ignoreTime {
			now := uint32(time.Now().Unix())
			notYetValid, expired := rrsigTimeState(rrsig, now)
			if notYetValid {
				fmt.Printf("  WARNING: Signature not yet valid for %s type %d (inception: %d)\n",
					rr.Name.String(), rrsig.TypeCovered, rrsig.Inception)
				expiredSigs++
				continue
			}
			if expired {
				fmt.Printf("  ERROR: Signature expired for %s type %d (expired: %d)\n",
					rr.Name.String(), rrsig.TypeCovered, rrsig.Expiration)
				expiredSigs++
				continue
			}
		}

		// Find matching records covered by this RRSIG
		var coveredRecords []*protocol.ResourceRecord
		for _, rec := range records {
			if rec.Type == rrsig.TypeCovered &&
				strings.EqualFold(rec.Name.String(), rr.Name.String()) {
				coveredRecords = append(coveredRecords, rec)
			}
		}

		if len(coveredRecords) == 0 {
			fmt.Printf("  WARNING: No records found for RRSIG covering %s type %d\n",
				rr.Name.String(), rrsig.TypeCovered)
			continue
		}

		// Verify the signature using the dnssec package
		pubKey, err := dnssec.ParseDNSKEYPublicKey(dnskey.Algorithm, dnskey.PublicKey)
		if err != nil {
			fmt.Printf("  ERROR: Failed to parse DNSKEY for %s type %d: %v\n",
				rr.Name.String(), rrsig.TypeCovered, err)
			invalidSigs++
			continue
		}

		// Build signed data for verification
		signedData, err := buildSignedDataForValidation(coveredRecords, rrsig)
		if err != nil {
			fmt.Printf("  ERROR: Failed to build signed data for %s type %d: %v\n",
				rr.Name.String(), rrsig.TypeCovered, err)
			invalidSigs++
			continue
		}

		err = dnssec.VerifySignature(rrsig, signedData, pubKey)
		if err != nil {
			fmt.Printf("  FAIL: %s type %d keytag=%d: %v\n",
				rr.Name.String(), rrsig.TypeCovered, rrsig.KeyTag, err)
			invalidSigs++
		} else {
			fmt.Printf("  OK: %s type %d signed by keytag %d\n",
				rr.Name.String(), rrsig.TypeCovered, rrsig.KeyTag)
			validSigs++
		}
	}

	fmt.Printf("\n=== Validation Summary ===\n")
	fmt.Printf("Total RRSIGs: %d\n", len(rrsigRRs))
	fmt.Printf("Valid: %d\n", validSigs)
	fmt.Printf("Invalid: %d\n", invalidSigs)
	fmt.Printf("Expired/Not-yet-valid: %d\n", expiredSigs)

	if invalidSigs > 0 {
		return fmt.Errorf("zone validation failed: %d invalid signatures", invalidSigs)
	}

	return nil
}

// buildSignedDataForValidation constructs the signed data blob for RRSIG verification.
// This mirrors the Signer.createSignedData logic but for standalone validation.
//
// RFC 4034 §6.2 requires the RRSet to be sorted in canonical order
// (byte-wise ascending on RDATA wire form) before being included in
// the signed data. For an RRSet with multiple records of the same
// owner+type — most commonly DNSKEY with KSK + ZSK — the order
// matters because the signer sorted them too. Skipping the sort
// here caused every KSK-over-DNSKEY-RRSet signature to fail
// verification (zone-file order ≠ canonical order in general).
func buildSignedDataForValidation(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) ([]byte, error) {
	if rrsig == nil {
		return nil, fmt.Errorf("nil RRSIG")
	}
	if rrsig.SignerName == nil {
		return nil, fmt.Errorf("nil RRSIG signer name")
	}

	var data []byte

	// RRSIG RDATA prefix (without signature)
	data = append(data, byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered))
	data = append(data, rrsig.Algorithm)
	data = append(data, rrsig.Labels)
	data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
		byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))
	data = append(data, byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16),
		byte(rrsig.Expiration>>8), byte(rrsig.Expiration))
	data = append(data, byte(rrsig.Inception>>24), byte(rrsig.Inception>>16),
		byte(rrsig.Inception>>8), byte(rrsig.Inception))
	data = append(data, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag))

	// Signer name in wire format
	signerWire := protocol.CanonicalWireName(rrsig.SignerName.String())
	data = append(data, signerWire...)

	// Pre-pack each record's RDATA and sort by RDATA wire form
	// (canonical RRSet order per RFC 4034 §6.2).
	type packed struct {
		rr    *protocol.ResourceRecord
		rdata []byte
	}
	packedSet := make([]packed, 0, len(rrSet))
	for _, rr := range rrSet {
		if rr == nil {
			return nil, fmt.Errorf("nil RR in RRSet")
		}
		if rr.Name == nil {
			return nil, fmt.Errorf("nil RR owner name")
		}
		var rdata []byte
		if rr.Data != nil {
			buf := make([]byte, 65535)
			n, err := rr.Data.Pack(buf, 0)
			if err != nil {
				return nil, fmt.Errorf("pack RR RDATA: %w", err)
			}
			if n > 65535 {
				return nil, fmt.Errorf("RR RDATA too large: %d bytes", n)
			}
			rdata = append([]byte(nil), buf[:n]...)
		}
		packedSet = append(packedSet, packed{rr: rr, rdata: rdata})
	}
	sort.Slice(packedSet, func(i, j int) bool {
		return bytes.Compare(packedSet[i].rdata, packedSet[j].rdata) < 0
	})

	for _, p := range packedSet {
		ownerWire := protocol.CanonicalWireName(p.rr.Name.String())
		data = append(data, ownerWire...)
		data = append(data, byte(p.rr.Type>>8), byte(p.rr.Type))
		data = append(data, byte(p.rr.Class>>8), byte(p.rr.Class))
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))
		data = append(data, byte(len(p.rdata)>>8), byte(len(p.rdata)))
		data = append(data, p.rdata...)
	}

	return data, nil
}

// parseRDataFromZone converts one record's RDATA text from a zone file into
// its wire-format RData by delegating to the shared presentation-format
// parser (protocol.ParseRDataText). Zone-file normalization (comments,
// @-origin substitution, relative owner names, column splitting) happens in
// the line readers above (parseZoneRecords / cmdDNSSECValidateZone); only the
// rdata→RData conversion lives here.
//
// RRSIG inception/expiration accept both RFC 4034 §3.2 presentation times
// (YYYYMMDDHHMMSS, 14 digits, UTC) and bare uint32 Unix seconds — the shared
// parser handles both and rejects out-of-range values, so a malformed time
// now fails the whole record instead of silently loading as time 0.
func parseRDataFromZone(rrtype uint16, rdata string) (protocol.RData, error) {
	typeName, ok := protocol.TypeToString[rrtype]
	if !ok {
		// No known mnemonic means no presentation grammar to parse with;
		// carry the text verbatim so the record is still visible to the
		// caller (matches the pre-delegation behavior for unknown types).
		return &protocol.RDataRaw{TypeVal: rrtype, Data: []byte(rdata)}, nil
	}
	rd := protocol.ParseRDataText(typeName, rdata)
	if rd == nil {
		return nil, fmt.Errorf("invalid %s RDATA: %q", typeName, rdata)
	}
	// RFC 4034 §2.1.2: a DNSKEY's protocol field MUST be 3 and the key MUST
	// be treated as invalid otherwise. The shared parser deliberately accepts
	// any protocol value (the wire form is well-defined and the server may
	// need to serve such records verbatim); this offline DNSSEC tool is
	// stricter and rejects non-3 keys up front so they can never be used for
	// signature verification. Scoped to DNSKEY only — KEY (RFC 2535) records
	// legitimately use other protocol values.
	if rrtype == protocol.TypeDNSKEY {
		if dnskey, ok := rd.(*protocol.RDataDNSKEY); ok && dnskey.Protocol != 3 {
			return nil, fmt.Errorf("DNSKEY protocol must be 3, got %d", dnskey.Protocol)
		}
	}
	return rd, nil
}
