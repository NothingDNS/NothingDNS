package protocol

import (
	"bytes"
	"fmt"
	"testing"
)

// ============================================================================
// ZONEMD Unpack (RFC 8976) — wire-format edge cases
//
// The ZONEMD parser guards a zone-integrity digest: Serial(4) Scheme(1)
// Algorithm(1) Digest(variable). Previously only exercised via full-message
// round-trips; these tests drive each guard branch directly.
// ============================================================================

func TestRDataZONEMDUnpack(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var r *RDataZONEMD
		if _, err := r.Unpack(nil, 0, 0); err == nil {
			t.Fatal("nil receiver: expected error")
		}
	})

	t.Run("rdata past end of buffer", func(t *testing.T) {
		r := &RDataZONEMD{}
		buf := make([]byte, 8)
		// rdlength 16 starting at offset 4 → endOffset 20 > len(buf) 8
		if _, err := r.Unpack(buf, 4, 16); err != ErrBufferTooSmall {
			t.Fatalf("err = %v, want ErrBufferTooSmall", err)
		}
	})

	t.Run("rdata too short for fixed fields", func(t *testing.T) {
		r := &RDataZONEMD{}
		buf := make([]byte, 16)
		// Fixed header alone is 6 bytes; rdlength 5 must be rejected.
		if _, err := r.Unpack(buf, 2, 5); err == nil {
			t.Fatal("rdlength 5: expected 'too short' error")
		}
	})

	t.Run("empty digest", func(t *testing.T) {
		r := &RDataZONEMD{}
		buf := make([]byte, 16)
		// Exactly the 6 fixed bytes: serial + scheme + algorithm, no digest.
		buf[4] = 0x11
		buf[5] = 0x22
		buf[6] = 0x33
		buf[7] = 0x44
		buf[8] = 1 // scheme
		buf[9] = 2 // algorithm
		n, err := r.Unpack(buf, 4, 6)
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		if n != 6 {
			t.Errorf("consumed = %d, want 6", n)
		}
		if r.Serial != 0x11223344 {
			t.Errorf("Serial = %#x, want 0x11223344", r.Serial)
		}
		if r.Scheme != 1 || r.Algorithm != 2 {
			t.Errorf("Scheme/Algorithm = %d/%d, want 1/2", r.Scheme, r.Algorithm)
		}
		if len(r.Digest) != 0 {
			t.Errorf("Digest len = %d, want 0", len(r.Digest))
		}
	})

	t.Run("full record with digest", func(t *testing.T) {
		r := &RDataZONEMD{}
		buf := make([]byte, 32)
		buf[0] = 0xde
		buf[1] = 0xad
		buf[2] = 0xbe
		buf[3] = 0xef
		buf[4] = 1 // scheme (simple)
		buf[5] = 1 // algorithm (SHA-384 placeholder)
		buf[6] = 0xaa
		buf[7] = 0xbb
		buf[8] = 0xcc
		n, err := r.Unpack(buf, 0, 9)
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		if n != 9 {
			t.Errorf("consumed = %d, want 9", n)
		}
		if r.Serial != 0xdeadbeef {
			t.Errorf("Serial = %#x, want 0xdeadbeef", r.Serial)
		}
		if !bytes.Equal(r.Digest, []byte{0xaa, 0xbb, 0xcc}) {
			t.Errorf("Digest = %x, want aabbcc", r.Digest)
		}
	})
}

// ============================================================================
// createRData — factory dispatch
//
// The pre-existing TestCreateRDataAllTypes covers the pooled mainstream
// types but never checks the concrete type it gets back (its expected
// field is unused). This table pins the type-mapping for every case that
// table misses: the RFC alias types (SIG/KEY/SPF/CDS/CDNSKEY/TA share
// wire formats with their canonical types) and the rare non-pooled types.
// A wrong mapping silently parses records into the wrong struct.
// ============================================================================

func TestCreateRDataAliasesAndRareTypes(t *testing.T) {
	cases := []struct {
		name string
		typ  uint16
		want string
	}{
		// RFC alias types — must map to the canonical wire format.
		{"SIG→RRSIG", TypeSIG, "*protocol.RDataRRSIG"},
		{"KEY→DNSKEY", TypeKEY, "*protocol.RDataDNSKEY"},
		{"SPF→TXT", TypeSPF, "*protocol.RDataTXT"},
		{"CDS→DS", TypeCDS, "*protocol.RDataDS"},
		{"CDNSKEY→DNSKEY", TypeCDNSKEY, "*protocol.RDataDNSKEY"},
		{"TA→DS", TypeTA, "*protocol.RDataDS"},
		// Rare / non-pooled types.
		{"DNAME", TypeDNAME, "*protocol.RDataDNAME"},
		{"LOC", TypeLOC, "*protocol.RDataLOC"},
		{"HINFO", TypeHINFO, "*protocol.RDataHINFO"},
		{"RP", TypeRP, "*protocol.RDataRP"},
		{"AFSDB", TypeAFSDB, "*protocol.RDataAFSDB"},
		{"KX", TypeKX, "*protocol.RDataKX"},
		{"CERT", TypeCERT, "*protocol.RDataCERT"},
		{"URI", TypeURI, "*protocol.RDataURI"},
		{"APL", TypeAPL, "*protocol.RDataAPL"},
		{"HIP", TypeHIP, "*protocol.RDataHIP"},
		{"IPSECKEY", TypeIPSECKEY, "*protocol.RDataIPSECKEY"},
		{"DHCID", TypeDHCID, "*protocol.RDataDHCID"},
		{"OPENPGPKEY", TypeOPENPGPKEY, "*protocol.RDataOPENPGPKEY"},
		{"ZONEMD", TypeZONEMD, "*protocol.RDataZONEMD"},
		{"OPT", TypeOPT, "*protocol.RDataOPT"},
		{"SVCB", TypeSVCB, "*protocol.RDataSVCB"},
		{"HTTPS", TypeHTTPS, "*protocol.RDataHTTPS"},
		{"NSEC", TypeNSEC, "*protocol.RDataNSEC"},
		{"NSEC3", TypeNSEC3, "*protocol.RDataNSEC3"},
		{"NSEC3PARAM", TypeNSEC3PARAM, "*protocol.RDataNSEC3PARAM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := createRData(tc.typ)
			if r == nil {
				t.Fatalf("createRData(%d) = nil, want %s", tc.typ, tc.want)
			}
			if got := fmt.Sprintf("%T", r); got != tc.want {
				t.Errorf("createRData(%d) = %s, want %s", tc.typ, got, tc.want)
			}
		})
	}

	t.Run("unknown type returns nil", func(t *testing.T) {
		if r := createRData(0xBEEF); r != nil {
			t.Errorf("createRData(0xBEEF) = %T, want nil", r)
		}
	})
}

// ============================================================================
// releaseRData — pool recycling
//
// releaseRData is called on every response. The contract: the recycled
// object is zeroed before being returned to its sync.Pool, and nested
// Names are Released (returned to the name pool) rather than leaked.
// These tests pin the zeroing behavior and that every pooled type
// survives release without panicking.
// ============================================================================

func TestReleaseRDataZeroesRecycledObjects(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		r := &RDataA{Address: [4]byte{192, 0, 2, 1}}
		releaseRData(r)
		if r.Address != [4]byte{} {
			t.Errorf("Address = %v, want zeroed", r.Address)
		}
	})

	t.Run("MX", func(t *testing.T) {
		exchange, _ := ParseName("mail.example.com.")
		r := &RDataMX{Preference: 10, Exchange: exchange}
		releaseRData(r)
		if r.Preference != 0 {
			t.Errorf("Preference = %d, want 0", r.Preference)
		}
		if r.Exchange != nil {
			t.Error("Exchange not nil after release")
		}
	})

	t.Run("CNAME nested name released", func(t *testing.T) {
		target, _ := ParseName("target.example.com.")
		r := &RDataCNAME{CName: target}
		releaseRData(r)
		if r.CName != nil {
			t.Error("CName not nil after release")
		}
	})

	t.Run("nil interface", func(t *testing.T) {
		// A nil RData interface must be a silent no-op — the pipeline
		// releases absent data on error paths.
		releaseRData(nil)
	})
}

func TestReleaseRDataAllPooledTypesNoPanic(t *testing.T) {
	cname, _ := ParseName("cname.example.com.")
	srvTarget, _ := ParseName("srv.example.com.")
	soaMName, _ := ParseName("ns.example.com.")
	soaRName, _ := ParseName("hostmaster.example.com.")
	afsHost, _ := ParseName("afs.example.com.")
	kxExchanger, _ := ParseName("kx.example.com.")
	rpMBox, _ := ParseName("admin.example.com.")
	naptrRepl, _ := ParseName("repl.example.com.")

	values := []RData{
		&RDataA{Address: [4]byte{10, 0, 0, 1}},
		&RDataAAAA{Address: [16]byte{}},
		&RDataCNAME{CName: cname},
		&RDataDNAME{DName: cname},
		&RDataNS{NSDName: cname},
		&RDataPTR{PtrDName: cname},
		&RDataMX{Preference: 10, Exchange: cname},
		&RDataTXT{Strings: []string{"v=spf1 -all"}},
		&RDataSOA{MName: soaMName, RName: soaRName, Serial: 42},
		&RDataSRV{Priority: 1, Weight: 2, Port: 53, Target: srvTarget},
		&RDataHINFO{CPU: "x86", OS: "linux"},
		&RDataRP{MBox: rpMBox, Txt: rpMBox},
		&RDataAFSDB{Subtype: 1, Hostname: afsHost},
		&RDataKX{Preference: 5, Exchanger: kxExchanger},
		&RDataURI{Priority: 1, Weight: 2, Target: "https://example.com/"},
		&RDataNAPTR{Order: 100, Flags: "S", Replacement: naptrRepl},
		&RDataCAA{Flags: 128, Tag: "issue", Value: "ca.example.com"},
		&RDataCERT{CertType: 1, KeyTag: 2, Algorithm: 3, Certificate: []byte{0x01}},
		&RDataOPENPGPKEY{PublicKey: []byte{0x01}},
		&RDataDHCID{Data: []byte{0x02}},
		&RDataSSHFP{Algorithm: 1, FPType: 2, Fingerprint: []byte{0x03}},
		&RDataTLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: []byte{0x04}},
		&RDataOPT{},
		&RDataSVCB{Priority: 1},
		&RDataHTTPS{Priority: 1},
		// Non-pooled types: releaseRData is a silent no-op for these.
		&RDataZONEMD{Serial: 1, Scheme: 1, Algorithm: 1, Digest: []byte{0xaa}},
		&RDataDS{KeyTag: 1, Algorithm: 8},
		&RDataDNSKEY{Flags: 257},
		&RDataRRSIG{TypeCovered: TypeA},
		&RDataNSEC{NextDomain: cname, TypeBitMap: []uint16{TypeA}},
		&RDataNSEC3{HashAlgorithm: 1, NextHashed: []byte{0x05}},
		&RDataNSEC3PARAM{HashAlgorithm: 1, Salt: []byte{0x06}},
		&RDataLOC{Version: 0},
		&RDataAPL{Items: nil},
		&RDataIPSECKEY{Precedence: 1, Gateway: []byte{10, 0, 0, 1}},
	}

	for i, v := range values {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Errorf("values[%d] (%T): releaseRData panicked: %v", i, v, rec)
				}
			}()
			releaseRData(v)
		}()
	}
}
