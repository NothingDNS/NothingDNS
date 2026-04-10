package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

func cmdDNSSEC(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dnssec subcommand required (generate-key, ds-from-dnskey, sign-zone, verify-anchor, validate-zone)")
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
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
		return fmt.Errorf("unknown dnssec subcommand: %s", subcmd)
	}
}

func cmdDNSSECGenerateKey(args []string) error {
	fs := flag.NewFlagSet("generate-key", flag.ExitOnError)
	algorithm := fs.Int("algorithm", 13, "DNSSEC algorithm (8=RSASHA256, 10=RSASHA512, 13=ECDSAP256SHA256, 14=ECDSAP384SHA384)")
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

	// Generate key pair
	signingKey, err := generateKeyPair(uint8(*algorithm), isKSK, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate key file names
	keyTag := signingKey.KeyTag
	algStr := fmt.Sprintf("%03d", *algorithm)
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
	fmt.Printf("  Algorithm: %d (%s)\n", *algorithm, algorithmName(uint8(*algorithm)))
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
	fs := flag.NewFlagSet("ds-from-dnskey", flag.ExitOnError)
	zone := fs.String("zone", "", "Zone name (required)")
	keyFile := fs.String("keyfile", "", "Public key file path (required)")
	digestType := fs.Int("digest", 2, "Digest type (1=SHA-1, 2=SHA-256, 4=SHA-384)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" || *keyFile == "" {
		return fmt.Errorf("zone and keyfile are required")
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
	ds, err := dnssec.CreateDS(*zone, dnskey, uint8(*digestType))
	if err != nil {
		return fmt.Errorf("failed to create DS: %w", err)
	}

	fmt.Printf("DS record for %s:\n", *zone)
	fmt.Printf("  %s IN DS %d %d %d %s\n", *zone, ds.KeyTag, ds.Algorithm, ds.DigestType, hexEncode(ds.Digest))

	return nil
}

func cmdDNSSECSignZone(args []string) error {
	fs := flag.NewFlagSet("sign-zone", flag.ExitOnError)
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
		signerCfg.NSEC3Iterations = uint16(*nsec3Iterations)
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
	f, err := os.Open(*inputFile)
	if err != nil {
		return fmt.Errorf("opening zone file: %w", err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
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

	if err := os.WriteFile(*outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("writing signed zone: %w", err)
	}

	fmt.Printf("\nZone signed successfully: %s\n", *outputFile)
	fmt.Printf("  Input records:   %d\n", len(records))
	fmt.Printf("  Signed records:  %d (includes DNSKEY, RRSIG, NSEC)\n", len(signedRecords))
	fmt.Printf("  Keys used:       %d\n", len(keys))

	return nil
}

// parseZoneRecords parses a BIND-format zone file into resource records.
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

		rdataObj, err := parseRDataFromZone(rrtype, rdata, owner.String())
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
	fs := flag.NewFlagSet("verify-anchor", flag.ExitOnError)
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

func generateKeyPair(algorithm uint8, isKSK bool, keySize int) (*dnssec.SigningKey, error) {
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

	return os.WriteFile(path, []byte(content.String()), 0600)
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

	return os.WriteFile(path, []byte(content), 0644)
}

func readDNSKEYFromFile(path string) (*protocol.RDataDNSKEY, error) {
	data, err := os.ReadFile(path)
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
func findKeyFiles(dir, zone string) ([]string, error) {
	// Strip trailing dot for file matching
	zoneName := strings.TrimSuffix(zone, ".")

	pattern := fmt.Sprintf("K%s+*.key", zoneName)
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}
	return matches, nil
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

// loadPrivateKey reads a private key from BIND-format private key file.
func loadPrivateKey(path string, algorithm uint8) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var privateKeyB64 string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey: ") {
			privateKeyB64 = strings.TrimPrefix(line, "PrivateKey: ")
			break
		}
	}

	if privateKeyB64 != "" {
		derBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decoding private key: %w", err)
		}
		return x509.ParsePKCS8PrivateKey(derBytes)
	}

	// Try RSA component-based format
	var modulus, privateExp string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Modulus: ") {
			modulus = strings.TrimPrefix(line, "Modulus: ")
		}
		if strings.HasPrefix(line, "PrivateExponent: ") {
			privateExp = strings.TrimPrefix(line, "PrivateExponent: ")
		}
	}

	if modulus != "" && privateExp != "" {
		modBytes, err := base64.StdEncoding.DecodeString(modulus)
		if err != nil {
			return nil, fmt.Errorf("decoding modulus: %w", err)
		}
		expBytes, err := base64.StdEncoding.DecodeString(privateExp)
		if err != nil {
			return nil, fmt.Errorf("decoding exponent: %w", err)
		}
		n := new(big.Int).SetBytes(modBytes)
		d := new(big.Int).SetBytes(expBytes)
		// Reconstruct RSA key - this is approximate
		return &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: 65537},
			D:         d,
		}, nil
	}

	return nil, fmt.Errorf("no private key data found in %s", path)
}

// keyType returns "KSK" or "ZSK" for a signing key.
func keyType(key *dnssec.SigningKey) string {
	if key.IsKSK {
		return "KSK"
	}
	return "ZSK"
}

func cmdDNSSECValidateZone(args []string) error {
	fs := flag.NewFlagSet("validate-zone", flag.ExitOnError)
	zoneFile := fs.String("zone", "", "Zone file to validate (required)")
	ignoreTime := fs.Bool("ignore-time", false, "Ignore signature timestamps (for testing)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zoneFile == "" {
		return fmt.Errorf("zone file is required (-zone)")
	}

	// Read the zone file
	data, err := os.ReadFile(*zoneFile)
	if err != nil {
		return fmt.Errorf("reading zone file: %w", err)
	}

	// Parse zone records
	lines := strings.Split(string(data), "\n")
	var records []*protocol.ResourceRecord
	var dnskeyRRs []*protocol.ResourceRecord
	var rrsigRRs []*protocol.ResourceRecord

	for _, line := range lines {
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

		rdataObj, err := parseRDataFromZone(rrtype, rdata, owner.String())
		if err != nil {
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
			if now < rrsig.Inception {
				fmt.Printf("  WARNING: Signature not yet valid for %s type %d (inception: %d)\n",
					rr.Name.String(), rrsig.TypeCovered, rrsig.Inception)
				expiredSigs++
				continue
			}
			if now > rrsig.Expiration {
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
		signedData := buildSignedDataForValidation(coveredRecords, rrsig)

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
func buildSignedDataForValidation(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) []byte {
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
	signerWire := canonicalWireName(rrsig.SignerName.String())
	data = append(data, signerWire...)

	for _, rr := range rrSet {
		ownerWire := canonicalWireName(rr.Name.String())
		data = append(data, ownerWire...)
		data = append(data, byte(rr.Type>>8), byte(rr.Type))
		data = append(data, byte(rr.Class>>8), byte(rr.Class))
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

		buf := make([]byte, 65535)
		n, _ := rr.Data.Pack(buf, 0)
		rdata := buf[:n]
		data = append(data, byte(len(rdata)>>8), byte(len(rdata)))
		data = append(data, rdata...)
	}

	return data
}

// canonicalWireName converts a domain name to lowercase wire format
func canonicalWireName(name string) []byte {
	name = strings.ToLower(name)
	var result []byte
	if name == "." || name == "" {
		return []byte{0}
	}
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0)
	return result
}

// parseRDataFromZone parses RDATA from a zone file line
func parseRDataFromZone(rrtype uint16, rdata, origin string) (protocol.RData, error) {
	switch rrtype {
	case protocol.TypeA:
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil, fmt.Errorf("invalid A record: %s", rdata)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("a record requires IPv4 address")
		}
		var addr [4]byte
		copy(addr[:], ipv4)
		return &protocol.RDataA{Address: addr}, nil

	case protocol.TypeAAAA:
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil, fmt.Errorf("invalid AAAA record: %s", rdata)
		}
		var addr [16]byte
		copy(addr[:], ip.To16())
		return &protocol.RDataAAAA{Address: addr}, nil

	case protocol.TypeCNAME:
		name, err := protocol.ParseName(rdata)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataCNAME{CName: name}, nil

	case protocol.TypeNS:
		name, err := protocol.ParseName(rdata)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataNS{NSDName: name}, nil

	case protocol.TypeMX:
		var pref uint16
		var exchange string
		_, err := fmt.Sscanf(rdata, "%d %s", &pref, &exchange)
		if err != nil {
			return nil, fmt.Errorf("invalid MX record: %s", rdata)
		}
		name, err := protocol.ParseName(exchange)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataMX{Preference: pref, Exchange: name}, nil

	case protocol.TypeTXT:
		text := strings.Trim(rdata, "\"")
		return &protocol.RDataTXT{Strings: []string{text}}, nil

	case protocol.TypeDNSKEY:
		fields := strings.Fields(rdata)
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid DNSKEY record")
		}
		flags, _ := strconv.ParseUint(fields[0], 10, 16)
		alg, _ := strconv.ParseUint(fields[2], 10, 8)
		pubKeyB64 := strings.Join(fields[3:], "")
		pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decoding DNSKEY public key: %w", err)
		}
		return &protocol.RDataDNSKEY{
			Flags:     uint16(flags),
			Protocol:  3,
			Algorithm: uint8(alg),
			PublicKey: pubKey,
		}, nil

	case protocol.TypeRRSIG:
		fields := strings.Fields(rdata)
		if len(fields) < 9 {
			return nil, fmt.Errorf("invalid RRSIG record")
		}
		typeStr := strings.ToUpper(fields[0])
		covered := protocol.StringToType[typeStr]
		alg, _ := strconv.ParseUint(fields[1], 10, 8)
		labels, _ := strconv.ParseUint(fields[2], 10, 8)
		origTTL, _ := strconv.ParseUint(fields[3], 10, 32)
		expiration, _ := strconv.ParseUint(fields[4], 10, 32)
		inception, _ := strconv.ParseUint(fields[5], 10, 32)
		keyTag, _ := strconv.ParseUint(fields[6], 10, 16)
		signerName := fields[7]
		sigB64 := strings.Join(fields[8:], "")
		signature, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, fmt.Errorf("decoding RRSIG signature: %w", err)
		}
		signer, err := protocol.ParseName(signerName)
		if err != nil {
			return nil, fmt.Errorf("parsing signer name: %w", err)
		}
		return &protocol.RDataRRSIG{
			TypeCovered: covered,
			Algorithm:   uint8(alg),
			Labels:      uint8(labels),
			OriginalTTL: uint32(origTTL),
			Expiration:  uint32(expiration),
			Inception:   uint32(inception),
			KeyTag:      uint16(keyTag),
			SignerName:  signer,
			Signature:   signature,
		}, nil

	default:
		return &protocol.RDataRaw{TypeVal: rrtype, Data: []byte(rdata)}, nil
	}
}
