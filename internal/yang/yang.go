// Package yang implements YANG models for DNS as specified in RFC 9108.
// YANG is a data modeling language used for NETCONF-based network management.
package yang

import (
	"fmt"
	"strings"
)

// YANG DNSSEC Types as defined in RFC 9108.

// DnskeyFlags represents DNSKEY record flags.
type DnskeyFlags uint16

const (
	DnskeyFlagZoneKey  DnskeyFlags = 0x0001  // Zone key
	DnskeyFlagSecureEntryPoint DnskeyFlags = 0x0002  // SEP
	DnskeyFlagRevoke DnskeyFlags = 0x0080  // Revoked key
)

// DnskeyProtocol is the DNSKEY protocol version.
const DnskeyProtocol uint8 = 3

// DnskeyAlgorithm represents DNSSEC algorithm identifiers.
type DnskeyAlgorithm uint8

const (
	DnskeyAlgRSAMD5     DnskeyAlgorithm = 1  // RFC 3110 (deprecated)
	DnskeyAlgRSASHA1    DnskeyAlgorithm = 5  // RSASHA1 (RFC 4034)
	DnskeyAlgDSNSHA1    DnskeyAlgorithm = 6  // DSASHA1 (RFC 3755)
	DnskeyAlgRSASHA1NSEC3SHA1 DnskeyAlgorithm = 7  // RSASHA1-NSEC3-SHA1 (RFC 5155)
	DnskeyAlgRSASHA256  DnskeyAlgorithm = 8  // RSASHA256 (RFC 5702)
	DnskeyAlgRSASHA512  DnskeyAlgorithm = 10 // RSASHA512 (RFC 5702)
	DnskeyAlgECDSAP256  DnskeyAlgorithm = 13 // ECDSAP256SHA256 (RFC 6605)
	DnskeyAlgECDSAP384  DnskeyAlgorithm = 14 // ECDSAP384SHA384 (RFC 6605)
	DnskeyAlgED25519    DnskeyAlgorithm = 15  // ED25519 (RFC 8080)
	DnskeyAlgED448      DnskeyAlgorithm = 16  // ED448 (RFC 8080)
)

// DnskeyAlgorithmString returns the YANG string representation of an algorithm.
func (a DnskeyAlgorithm) String() string {
	switch a {
	case DnskeyAlgRSAMD5:
		return "rsamd5"
	case DnskeyAlgRSASHA1:
		return "rsasha1"
	case DnskeyAlgDSNSHA1:
		return "dsasha1"
	case DnskeyAlgRSASHA1NSEC3SHA1:
		return "rsasha1-nsec3-sha1"
	case DnskeyAlgRSASHA256:
		return "rsasha256"
	case DnskeyAlgRSASHA512:
		return "rsasha512"
	case DnskeyAlgECDSAP256:
		return "ecdsap256sha256"
	case DnskeyAlgECDSAP384:
		return "ecdsap384sha384"
	case DnskeyAlgED25519:
		return "ed25519"
	case DnskeyAlgED448:
		return "ed448"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// DnskeyAlgorithmFromString parses a YANG algorithm string.
func DnskeyAlgorithmFromString(s string) (DnskeyAlgorithm, error) {
	switch strings.ToLower(s) {
	case "rsamd5":
		return DnskeyAlgRSAMD5, nil
	case "rsasha1":
		return DnskeyAlgRSASHA1, nil
	case "dsasha1":
		return DnskeyAlgDSNSHA1, nil
	case "rsasha1-nsec3-sha1":
		return DnskeyAlgRSASHA1NSEC3SHA1, nil
	case "rsasha256":
		return DnskeyAlgRSASHA256, nil
	case "rsasha512":
		return DnskeyAlgRSASHA512, nil
	case "ecdsap256sha256":
		return DnskeyAlgECDSAP256, nil
	case "ecdsap384sha384":
		return DnskeyAlgECDSAP384, nil
	case "ed25519":
		return DnskeyAlgED25519, nil
	case "ed448":
		return DnskeyAlgED448, nil
	default:
		return 0, fmt.Errorf("unknown DNSSEC algorithm: %s", s)
	}
}

// DS digest types.
type DsDigestType uint8

const (
	DsDigestSHA1   DsDigestType = 1  // RFC 3658
	DsDigestSHA256 DsDigestType = 2  // RFC 4509
	DsDigestSHA384 DsDigestType = 4  // RFC 6605
)

// DsDigestTypeString returns the YANG string representation.
func (d DsDigestType) String() string {
	switch d {
	case DsDigestSHA1:
		return "sha-1"
	case DsDigestSHA256:
		return "sha-256"
	case DsDigestSHA384:
		return "sha-384"
	default:
		return fmt.Sprintf("unknown(%d)", d)
	}
}

// NSEC3 algorithm identifiers.
type Nsec3Algorithm uint8

const (
	Nsec3AlgSHA1 Nsec3Algorithm = 1  // RFC 5155 (only defined)
)

// Nsec3AlgorithmString returns the YANG string representation.
func (a Nsec3Algorithm) String() string {
	switch a {
	case Nsec3AlgSHA1:
		return "sha-1"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// DNS Record Types as YANG identities.
const (
	// Core record types
	YangRecordTypeA     = "a"
	YangRecordTypeNS    = "ns"
	YangRecordTypeCNAME = "cname"
	YangRecordTypeSOA   = "soa"
	YangRecordTypePTR   = "ptr"
	YangRecordTypeMX    = "mx"
	YangRecordTypeTXT   = "txt"
	YangRecordTypeAAAA  = "aaaa"
	YangRecordTypeSRV   = "srv"

	// DNSSEC record types
	YangRecordTypeDNSKEY = "dnskey"
	YangRecordTypeDS     = "ds"
	YangRecordTypeRRSIG  = "rrsig"
	YangRecordTypeNSEC   = "nsec"
	YangRecordTypeNSEC3  = "nsec3"
	YangRecordTypeNSEC3PARAM = "nsec3param"

	// Other record types
	YangRecordTypeCAA   = "caa"
	YangRecordTypeTLSA  = "tlsa"
	YangRecordTypeSVCB  = "svcb"
	YangRecordTypeHTTPS = "https"
	YangRecordTypeURI   = "uri"
	YangRecordTypeCERT  = "cert"
)

// DNS Classes as YANG identities.
const (
	YangClassIN  = "in"   // Internet
	YangClassCS  = "cs"   // CSNET (obsolete)
	YangClassCH  = "ch"   // CHAOS
	YangClassHS  = "hs"   // Hesiod
	YangClassNONE = "none" // QCLASS NONE
	YangClassANY = "any"  // QCLASS ANY
)

// YANG DNS Module structure.
type YANGDNSModule struct {
	Name    string
	Prefix  string
	Contact string
	Description string
	Revision string
}

// RFC 9108 defines the ietf-dns module.
var IETFDNSModule = YANGDNSModule{
	Name:    "ietf-dns",
	Prefix:  "dns",
	Contact: "ietf-dns@ietf.org",
	Description: "YANG data model for DNS",
	Revision: "2021-03-02",
}

// YANG DNS TCP DNS Module for DNS over TCP.
var IETFDNSTCPModule = YANGDNSModule{
	Name:    "ietf-dns-tcp",
	Prefix:  "dns-tcp",
	Contact: "ietf-dns@ietf.org",
	Description: "YANG data model for DNS over TCP",
	Revision: "2021-03-02",
}

// YANG DNS DNSSEC Types Module.
var IETFDNSSECModule = YANGDNSModule{
	Name:    "ietf-dns-dnssec",
	Prefix:  "dnssec",
	Contact: "ietf-dns@ietf.org",
	Description: "YANG data model for DNSSEC",
	Revision: "2021-03-02",
}

// RecordTypeFromYANG converts a YANG record type string to record type code.
func RecordTypeFromYANG(yangType string) (uint16, error) {
	switch strings.ToLower(yangType) {
	case "a":
		return 1, nil
	case "ns":
		return 2, nil
	case "cname":
		return 5, nil
	case "soa":
		return 6, nil
	case "ptr":
		return 12, nil
	case "mx":
		return 15, nil
	case "txt":
		return 16, nil
	case "aaaa":
		return 28, nil
	case "srv":
		return 33, nil
	case "dnskey":
		return 48, nil
	case "ds":
		return 43, nil
	case "rrsig":
		return 46, nil
	case "nsec":
		return 47, nil
	case "nsec3":
		return 50, nil
	case "nsec3param":
		return 51, nil
	case "caa":
		return 257, nil
	case "tlsa":
		return 52, nil
	case "svcb":
		return 64, nil
	case "https":
		return 65, nil
	case "uri":
		return 256, nil
	case "cert":
		return 37, nil
	default:
		return 0, fmt.Errorf("unknown YANG record type: %s", yangType)
	}
}

// RecordTypeToYANG converts a record type code to YANG string.
func RecordTypeToYANG(rrtype uint16) (string, error) {
	switch rrtype {
	case 1:
		return "a", nil
	case 2:
		return "ns", nil
	case 5:
		return "cname", nil
	case 6:
		return "soa", nil
	case 12:
		return "ptr", nil
	case 15:
		return "mx", nil
	case 16:
		return "txt", nil
	case 28:
		return "aaaa", nil
	case 33:
		return "srv", nil
	case 48:
		return "dnskey", nil
	case 43:
		return "ds", nil
	case 46:
		return "rrsig", nil
	case 47:
		return "nsec", nil
	case 50:
		return "nsec3", nil
	case 51:
		return "nsec3param", nil
	case 257:
		return "caa", nil
	case 52:
		return "tlsa", nil
	case 64:
		return "svcb", nil
	case 65:
		return "https", nil
	case 256:
		return "uri", nil
	case 37:
		return "cert", nil
	default:
		return "", fmt.Errorf("unknown record type: %d", rrtype)
	}
}

// ClassFromYANG converts a YANG class string to class code.
func ClassFromYANG(yangClass string) (uint16, error) {
	switch strings.ToLower(yangClass) {
	case "in":
		return 1, nil
	case "cs":
		return 2, nil
	case "ch":
		return 3, nil
	case "hs":
		return 4, nil
	case "none":
		return 254, nil
	case "any":
		return 255, nil
	default:
		return 0, fmt.Errorf("unknown YANG class: %s", yangClass)
	}
}

// ClassToYANG converts a class code to YANG string.
func ClassToYANG(class uint16) (string, error) {
	switch class {
	case 1:
		return "in", nil
	case 2:
		return "cs", nil
	case 3:
		return "ch", nil
	case 4:
		return "hs", nil
	case 254:
		return "none", nil
	case 255:
		return "any", nil
	default:
		return "", fmt.Errorf("unknown class: %d", class)
	}
}

// RDataField holds YANG model information for an RData field.
type RDataField struct {
	Name string
	Type string // YANG type
}

// RDataFieldsForType returns the YANG field definitions for a record type.
func RDataFieldsForType(rrtype string) []RDataField {
	switch strings.ToLower(rrtype) {
	case "a":
		return []RDataField{
			{"address", "inet:ipv4-address"},
		}
	case "aaaa":
		return []RDataField{
			{"address", "inet:ipv6-address"},
		}
	case "cname", "ptr", "ns":
		return []RDataField{
			{"target", "dns:name"},
		}
	case "mx":
		return []RDataField{
			{"preference", "uint16"},
			{"exchange", "dns:name"},
		}
	case "txt":
		return []RDataField{
			{"txt-data", "binary"},
		}
	case "srv":
		return []RDataField{
			{"priority", "uint16"},
			{"weight", "uint16"},
			{"port", "inet:port-number"},
			{"target", "dns:name"},
		}
	case "dnskey":
		return []RDataField{
			{"flags", "dnskey-flags"},
			{"protocol", "uint8"},
			{"algorithm", "dnskey-algorithm"},
			{"public-key", "binary"},
		}
	case "ds":
		return []RDataField{
			{"key-tag", "uint16"},
			{"algorithm", "dnskey-algorithm"},
			{"digest-type", "ds-digest-type"},
			{"digest", "binary"},
		}
	case "nsec":
		return []RDataField{
			{"next-node-name", "dns:name"},
			{"type-bitmap", "binary"},
		}
	case "nsec3":
		return []RDataField{
			{"hash-algorithm", "nsec3-algorithm"},
			{"flags", "uint8"},
			{"iterations", "uint16"},
			{"salt", "binary"},
			{"next-hashed-name", "binary"},
			{"type-bitmap", "binary"},
		}
	case "caa":
		return []RDataField{
			{"flags", "uint8"},
			{"tag", "string"},
			{"value", "string"},
		}
	default:
		return nil
	}
}

// ValidateDNSName validates a DNS name per YANG constraints.
func ValidateDNSName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("DNS name cannot be empty")
	}

	if len(name) > 255 {
		return fmt.Errorf("DNS name too long: %d", len(name))
	}

	// Split into labels
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue // Skip empty labels (e.g., for root)
		}
		if len(label) > 63 {
			return fmt.Errorf("DNS label too long: %s", label)
		}
	}

	return nil
}
