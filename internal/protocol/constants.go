// Package protocol implements the DNS wire protocol per RFC 1035 and related RFCs.
package protocol

import "strconv"

// DNS Opcodes defined in RFC 1035 and extensions.
const (
	OpcodeQuery  = 0 // Standard query
	OpcodeIQuery = 1 // Inverse query (OBSOLETE)
	OpcodeStatus = 2 // Server status request
	OpcodeNotify = 4 // Zone change notification (RFC 1996)
	OpcodeUpdate = 5 // Dynamic update (RFC 2136)
)

// DNS Response Codes (RCODE) defined in RFC 1035 and extensions.
const (
	RcodeSuccess        = 0  // No error
	RcodeFormatError    = 1  // FormErr - Format error
	RcodeServerFailure  = 2  // ServFail - Server failure
	RcodeNameError      = 3  // NXDomain - Non-existent domain
	RcodeNotImplemented = 4  // NotImp - Not implemented
	RcodeRefused        = 5  // Refused - Query refused
	RcodeYXDomain       = 6  // YXDomain - Name exists when it should not (RFC 2136)
	RcodeYXRRSet        = 7  // YXRRSet - RR set exists when it should not (RFC 2136)
	RcodeNXRRSet        = 8  // NXRRSet - RR set that should exist does not (RFC 2136)
	RcodeNotAuth        = 9  // NotAuth - Server not authoritative for zone (RFC 2136)
	RcodeNotZone        = 10 // NotZone - Name not contained in zone (RFC 2136)

	// EDNS extended RCODEs (upper 8 bits)
	RcodeBadVers    = 16 // Bad OPT version
	RcodeBadSig     = 16 // TSIG signature failure (RFC 2845)
	RcodeBadKey     = 17 // Key not recognized (RFC 2845)
	RcodeBadTime    = 18 // Signature out of time window (RFC 2845)
	RcodeBadMode    = 19 // Bad TKEY mode (RFC 2930)
	RcodeBadName    = 20 // Duplicate key name (RFC 2930)
	RcodeBadAlg     = 21 // Algorithm not supported (RFC 2930)
	RcodeBadTrunc   = 22 // Bad truncation (RFC 4635)
	RcodeBadCookie  = 23 // Bad/missing server cookie (RFC 7873)
)

// DNS Record Types defined in RFC 1035 and various extensions.
const (
	TypeA          = 1   // Host address (RFC 1035)
	TypeNS         = 2   // Authoritative name server (RFC 1035)
	TypeMD         = 3   // Mail destination (OBSOLETE)
	TypeMF         = 4   // Mail forwarder (OBSOLETE)
	TypeCNAME      = 5   // Canonical name for an alias (RFC 1035)
	TypeSOA        = 6   // Start of a zone of authority (RFC 1035)
	TypeMB         = 7   // Mailbox domain name (EXPERIMENTAL)
	TypeMG         = 8   // Mail group member (EXPERIMENTAL)
	TypeMR         = 9   // Mail rename domain name (EXPERIMENTAL)
	TypeNULL       = 10  // Null RR (EXPERIMENTAL)
	TypeWKS        = 11  // Well known service description (RFC 1035)
	TypePTR        = 12  // Domain name pointer (RFC 1035)
	TypeHINFO      = 13  // Host information (RFC 1035)
	TypeMINFO      = 14  // Mailbox or mail list information (RFC 1035)
	TypeMX         = 15  // Mail exchange (RFC 1035)
	TypeTXT        = 16  // Text strings (RFC 1035)
	TypeRP         = 17  // Responsible Person (RFC 1183)
	TypeAFSDB      = 18  // AFS Data Base location (RFC 1183)
	TypeX25        = 19  // X.25 PSDN address (RFC 1183)
	TypeISDN       = 20  // ISDN address (RFC 1183)
	TypeRT         = 21  // Route Through (RFC 1183)
	TypeNSAP       = 22  // NSAP address (RFC 1706)
	TypeNSAP_PTR   = 23  // NSAP domain name pointer (RFC 1348)
	TypeSIG        = 24  // Security signature (RFC 2535, 2931)
	TypeKEY        = 25  // Security key (RFC 2535, 2930)
	TypePX         = 26  // X.400 mail mapping information (RFC 2163)
	TypeGPOS       = 27  // Geographical Position (RFC 1712)
	TypeAAAA       = 28  // IPv6 address (RFC 3596)
	TypeLOC        = 29  // Location Information (RFC 1876)
	TypeNXT        = 30  // Next Domain (OBSOLETE - RFC 2535, 3755)
	TypeEID        = 31  // Endpoint Identifier
	TypeNIMLOC     = 32  // Nimrod Locator
	TypeSRV        = 33  // Server Selection (RFC 2782)
	TypeATMA       = 34  // ATM Address
	TypeNAPTR      = 35  // Naming Authority Pointer (RFC 3403)
	TypeKX         = 36  // Key Exchanger (RFC 2230)
	TypeCERT       = 37  // CERT (RFC 4398)
	TypeA6         = 38  // A6 (OBSOLETE - RFC 2874, 3226, 6563)
	TypeDNAME      = 39  // DNAME (RFC 6672)
	TypeSINK       = 40  // SINK
	TypeOPT        = 41  // OPT (RFC 6891)
	TypeAPL        = 42  // APL (RFC 3123)
	TypeDS         = 43  // Delegation Signer (RFC 4034)
	TypeSSHFP      = 44  // SSH Key Fingerprint (RFC 4255)
	TypeIPSECKEY   = 45  // IPSECKEY (RFC 4025)
	TypeRRSIG      = 46  // RRSIG (RFC 4034)
	TypeNSEC       = 47  // NSEC (RFC 4034)
	TypeDNSKEY     = 48  // DNSKEY (RFC 4034)
	TypeDHCID      = 49  // DHCID (RFC 4701)
	TypeNSEC3      = 50  // NSEC3 (RFC 5155)
	TypeNSEC3PARAM = 51  // NSEC3PARAM (RFC 5155)
	TypeTLSA       = 52  // TLSA (RFC 6698)
	TypeSMIMEA     = 53  // S/MIME cert association (RFC 8162)
	// Type54 is unassigned
	TypeHIP      = 55  // Host Identity Protocol (RFC 8005)
	TypeNINFO    = 56  // NINFO
	TypeRKEY     = 57  // RKEY
	TypeTALINK   = 58  // Trust Anchor LINK
	TypeCDS      = 59  // Child DS (RFC 7344)
	TypeCDNSKEY  = 60  // Child DNSKEY (RFC 7344)
	TypeOPENPGPKEY = 61 // OpenPGP Key (RFC 7929)
	TypeCSYNC    = 62  // Child-to-Parent Synchronization (RFC 7477)
	TypeZONEMD   = 63  // Message Digests for DNS Zones (RFC 8976)
	TypeSVCB     = 64  // Service Binding (RFC 9460)
	TypeHTTPS    = 65  // HTTPS Binding (RFC 9460)

	// Types 66-98 are unassigned
	TypeSPF      = 99   // SPF (OBSOLETE - RFC 7208)
	TypeUINFO    = 100  // UINFO
	TypeUID      = 101  // UID
	TypeGID      = 102  // GID
	TypeUNSPEC   = 103  // UNSPEC
	TypeNID      = 104  // NID (RFC 6742)
	TypeL32      = 105  // L32 (RFC 6742)
	TypeL64      = 106  // L64 (RFC 6742)
	TypeLP       = 107  // LP (RFC 6742)
	TypeEUI48    = 108  // EUI-48 address (RFC 7043)
	TypeEUI64    = 109  // EUI-64 address (RFC 7043)
	// Types 110-248 are unassigned
	TypeTKEY     = 249  // Transaction Key (RFC 2930)
	TypeTSIG     = 250  // Transaction Signature (RFC 2845)
	TypeIXFR     = 251  // Incremental transfer (RFC 1995)
	TypeAXFR     = 252  // Transfer of an entire zone (RFC 1035)
	TypeMAILB    = 253  // Mailbox-related records (MB, MG or MR)
	TypeMAILA    = 254  // Mail agent RRs (OBSOLETE - see MX)
	TypeANY      = 255  // A request for all records (RFC 1035)
	TypeURI      = 256  // URI (RFC 7553)
	TypeCAA      = 257  // Certification Authority Authorization (RFC 8659)
	TypeAVC      = 258  // Application Visibility and Control
	TypeDOA      = 259  // Digital Object Architecture
	TypeAMTRELAY = 260  // Automatic Multicast Tunneling Relay (RFC 8777)
	TypeTA       = 32768 // DNSSEC Trust Authorities (OBSOLETE)
	TypeDLV      = 32769 // DNSSEC Lookaside Validation (OBSOLETE - RFC 8749)
)

// DNS Query Classes defined in RFC 1035 and extensions.
const (
	ClassIN   = 1   // Internet (RFC 1035)
	ClassCS   = 2   // CSNET (OBSOLETE)
	ClassCH   = 3   // CHAOS (RFC 1035)
	ClassHS   = 4   // Hesiod
	ClassNONE = 254 // QCLASS NONE (RFC 2136)
	ClassANY  = 255 // QCLASS ANY (RFC 1035)
)

// EDNS Option Codes (RFC 6891 and extensions).
const (
	OptionCodeLLQ          = 1   // Long-lived query
	OptionCodeUL           = 2   // Update lease
	OptionCodeNSID         = 3   // Name Server Identifier (RFC 5001)
	OptionCodeDAU          = 5   // DNSSEC Algorithm Understood
	OptionCodeDHU          = 6   // DS Hash Understood
	OptionCodeN3U          = 7   // NSEC3 Hash Understood
	OptionCodeClientSubnet = 8   // Client Subnet (RFC 7871)
	OptionCodeExpire       = 9   // Expire (RFC 7314)
	OptionCodeCookie       = 10  // Cookie (RFC 7873)
	OptionCodeTCPKeepalive = 11  // TCP Keepalive (RFC 7828)
	OptionCodePadding      = 12  // Padding (RFC 7830)
	OptionCodeChain        = 13  // Chain (RFC 7901)
	OptionCodeKeyTag       = 14  // Key Tag (RFC 8145)
	OptionCodeExtendedError = 15 // Extended DNS Error (RFC 8914)
)

// Header flag bits.
const (
	FlagQR = 1 << 15 // Query/Response (0 = query, 1 = response)
	FlagAA = 1 << 10 // Authoritative Answer
	FlagTC = 1 << 9  // Truncated
	FlagRD = 1 << 8  // Recursion Desired
	FlagRA = 1 << 7  // Recursion Available
	FlagZ  = 1 << 6  // Reserved (must be zero)
	FlagAD = 1 << 5  // Authentic Data (RFC 2535)
	FlagCD = 1 << 4  // Checking Disabled (RFC 2535)
)

// EDNS flags.
const (
	EDNSFlagDO = 1 << 15 // DNSSEC OK
)

// TypeToString maps DNS record types to their string representation.
var TypeToString = map[uint16]string{
	TypeA:          "A",
	TypeNS:         "NS",
	TypeCNAME:      "CNAME",
	TypeSOA:        "SOA",
	TypePTR:        "PTR",
	TypeMX:         "MX",
	TypeTXT:        "TXT",
	TypeAAAA:       "AAAA",
	TypeSRV:        "SRV",
	TypeNAPTR:      "NAPTR",
	TypeOPT:        "OPT",
	TypeDS:         "DS",
	TypeSSHFP:      "SSHFP",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTLSA:       "TLSA",
	TypeSVCB:       "SVCB",
	TypeHTTPS:      "HTTPS",
	TypeCAA:        "CAA",
	TypeTSIG:       "TSIG",
	TypeAXFR:       "AXFR",
	TypeIXFR:       "IXFR",
	TypeANY:        "ANY",
}

// StringToType maps record type strings to their numeric values.
var StringToType = map[string]uint16{
	"A":          TypeA,
	"NS":         TypeNS,
	"CNAME":      TypeCNAME,
	"SOA":        TypeSOA,
	"PTR":        TypePTR,
	"MX":         TypeMX,
	"TXT":        TypeTXT,
	"AAAA":       TypeAAAA,
	"SRV":        TypeSRV,
	"NAPTR":      TypeNAPTR,
	"OPT":        TypeOPT,
	"DS":         TypeDS,
	"SSHFP":      TypeSSHFP,
	"RRSIG":      TypeRRSIG,
	"NSEC":       TypeNSEC,
	"DNSKEY":     TypeDNSKEY,
	"NSEC3":      TypeNSEC3,
	"NSEC3PARAM": TypeNSEC3PARAM,
	"TLSA":       TypeTLSA,
	"SVCB":       TypeSVCB,
	"HTTPS":      TypeHTTPS,
	"CAA":        TypeCAA,
	"TSIG":       TypeTSIG,
	"AXFR":       TypeAXFR,
	"IXFR":       TypeIXFR,
	"ANY":        TypeANY,
}

// ClassToString maps DNS classes to their string representation.
var ClassToString = map[uint16]string{
	ClassIN:   "IN",
	ClassCS:   "CS",
	ClassCH:   "CH",
	ClassHS:   "HS",
	ClassNONE: "NONE",
	ClassANY:  "ANY",
}

// StringToClass maps class strings to their numeric values.
var StringToClass = map[string]uint16{
	"IN":    ClassIN,
	"CS":    ClassCS,
	"CH":    ClassCH,
	"HS":    ClassHS,
	"NONE":  ClassNONE,
	"ANY":   ClassANY,
	"CLASS": ClassIN, // Default to IN for "CLASS" keyword
}

// RcodeToString maps RCODE values to their string representation.
var RcodeToString = map[int]string{
	RcodeSuccess:        "NOERROR",
	RcodeFormatError:    "FORMERR",
	RcodeServerFailure:  "SERVFAIL",
	RcodeNameError:      "NXDOMAIN",
	RcodeNotImplemented: "NOTIMP",
	RcodeRefused:        "REFUSED",
	RcodeYXDomain:       "YXDOMAIN",
	RcodeYXRRSet:        "YXRRSET",
	RcodeNXRRSet:        "NXRRSET",
	RcodeNotAuth:        "NOTAUTH",
	RcodeNotZone:        "NOTZONE",
}

// TypeString returns the string representation of a record type.
func TypeString(t uint16) string {
	if s, ok := TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ClassString returns the string representation of a class.
func ClassString(c uint16) string {
	if s, ok := ClassToString[c]; ok {
		return s
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// RcodeString returns the string representation of an RCODE.
func RcodeString(r int) string {
	if s, ok := RcodeToString[r]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(r)
}
