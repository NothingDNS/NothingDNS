package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const dnskeyZoneFile = `$ORIGIN signed.test.
$TTL 3600
@    IN  SOA ns1.signed.test. admin.signed.test. ( 1 3600 600 86400 300 )
@    IN  NS  ns1.signed.test.
ns1  IN  A   192.0.2.1
www  IN  A   192.0.2.10
`

// signedTestHandler wires a zone with a signer holding one KSK and one ZSK.
func signedTestHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	h.zones["signed.test."] = loadTestZoneFile(t, "signed.test.", dnskeyZoneFile)
	h.RebuildZoneTree()

	signer := dnssec.NewSigner("signed.test.", dnssec.DefaultSignerConfig())
	for _, isKSK := range []bool{true, false} {
		key, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, isKSK)
		if err != nil {
			t.Fatalf("GenerateKeyPair(ksk=%v): %v", isKSK, err)
		}
		signer.AddKey(key)
		signer.SetKeyState(key.KeyTag, dnssec.KeyStateActive)
	}

	h.zoneSigners = map[string]*dnssec.Signer{"signed.test.": signer}
	return h
}

func queryWithDO(t *testing.T, qname string, qtype uint16, do bool) *protocol.Message {
	t.Helper()
	msg := newTestQuery(t, qname, qtype)
	if do {
		msg.SetEDNS0(4096, true)
	}
	return msg
}

// TestDNSKEY_ServedFromZoneSigner is the regression for a signed zone that no
// validator could ever validate. A zone signed from configured keys carries no
// DNSKEY records in its file, and the query path never consulted the signer —
// so the apex answered NODATA for DNSKEY while every other RRset went out with
// an RRSIG naming a key nobody could fetch. `delv` reported exactly that:
// "broken trust chain resolving 'www.signed.test/A/IN'".
func TestDNSKEY_ServedFromZoneSigner(t *testing.T) {
	h := signedTestHandler(t)

	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "signed.test.", protocol.TypeDNSKEY, true))

	resp := w.msg
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	if !resp.Header.Flags.AA {
		t.Error("AA not set on an apex DNSKEY answer")
	}

	var dnskeys, rrsigs []*protocol.ResourceRecord
	for _, rr := range resp.Answers {
		switch rr.Type {
		case protocol.TypeDNSKEY:
			dnskeys = append(dnskeys, rr)
		case protocol.TypeRRSIG:
			rrsigs = append(rrsigs, rr)
		}
	}
	if len(dnskeys) != 2 {
		t.Fatalf("%d DNSKEY records, want 2 (KSK + ZSK)", len(dnskeys))
	}

	var sawKSK, sawZSK bool
	for _, rr := range dnskeys {
		key, ok := rr.Data.(*protocol.RDataDNSKEY)
		if !ok {
			t.Fatalf("DNSKEY rdata is %T", rr.Data)
		}
		if key.Flags&protocol.DNSKEYFlagSEP != 0 {
			sawKSK = true
		} else {
			sawZSK = true
		}
	}
	if !sawKSK || !sawZSK {
		t.Errorf("published set is missing a key: ksk=%v zsk=%v", sawKSK, sawZSK)
	}

	// RFC 4035 §2.2: the apex DNSKEY RRset is signed by the key-signing key —
	// that signature is what a validator follows down from the parent's DS.
	if len(rrsigs) == 0 {
		t.Fatal("DNSKEY RRset carries no RRSIG")
	}
	sig, ok := rrsigs[0].Data.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatalf("RRSIG rdata is %T", rrsigs[0].Data)
	}
	if sig.TypeCovered != protocol.TypeDNSKEY {
		t.Errorf("RRSIG covers type %d, want DNSKEY", sig.TypeCovered)
	}

	var kskTag uint16
	for _, rr := range dnskeys {
		key := rr.Data.(*protocol.RDataDNSKEY)
		if key.Flags&protocol.DNSKEYFlagSEP != 0 {
			kskTag = key.CalculateKeyTag()
		}
	}
	if sig.KeyTag != kskTag {
		t.Errorf("DNSKEY RRSIG key tag = %d, want the KSK's %d (a ZSK signature breaks the chain)",
			sig.KeyTag, kskTag)
	}
}

// TestDNSKEY_NoRRSIGWithoutDO: a client that did not ask for DNSSEC gets the
// keys but no signature.
func TestDNSKEY_NoRRSIGWithoutDO(t *testing.T) {
	h := signedTestHandler(t)

	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "signed.test.", protocol.TypeDNSKEY, false))

	if w.msg == nil {
		t.Fatal("no response")
	}
	var dnskeys, rrsigs int
	for _, rr := range w.msg.Answers {
		switch rr.Type {
		case protocol.TypeDNSKEY:
			dnskeys++
		case protocol.TypeRRSIG:
			rrsigs++
		}
	}
	if dnskeys != 2 {
		t.Errorf("%d DNSKEY records, want 2", dnskeys)
	}
	if rrsigs != 0 {
		t.Errorf("%d RRSIGs returned to a client that did not set DO", rrsigs)
	}
}

// TestDNSKEY_NotServedBelowApex: DNSKEY lives at the apex only.
func TestDNSKEY_NotServedBelowApex(t *testing.T) {
	h := signedTestHandler(t)

	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "www.signed.test.", protocol.TypeDNSKEY, true))

	if w.msg == nil {
		t.Fatal("no response")
	}
	for _, rr := range w.msg.Answers {
		if rr.Type == protocol.TypeDNSKEY {
			t.Error("DNSKEY served below the zone apex")
		}
	}
}

// TestDNSKEY_UnsignedZoneUnaffected: a zone with no signer must keep answering
// DNSKEY as NODATA rather than erroring.
func TestDNSKEY_UnsignedZoneUnaffected(t *testing.T) {
	h := newTestHandler()
	h.zones["signed.test."] = loadTestZoneFile(t, "signed.test.", dnskeyZoneFile)
	h.RebuildZoneTree()

	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "signed.test.", protocol.TypeDNSKEY, true))

	if w.msg == nil {
		t.Fatal("no response")
	}
	if w.msg.Header.Flags.RCODE != protocol.RcodeSuccess || len(w.msg.Answers) != 0 {
		t.Errorf("unsigned zone: rcode=%d answers=%d, want NOERROR/0 (NODATA)",
			w.msg.Header.Flags.RCODE, len(w.msg.Answers))
	}
}

// TestDNSKEY_ZoneFileRecordsWin: an operator who put DNSKEY records in the
// zone file keeps serving those, not the signer's.
func TestDNSKEY_ZoneFileRecordsWin(t *testing.T) {
	h := signedTestHandler(t)
	z := h.zones["signed.test."]
	z.Records["signed.test."] = append(z.Records["signed.test."], zone.Record{
		Name: "signed.test.", Type: "DNSKEY", TTL: 3600, Class: "IN",
		RData: "257 3 13 AwEAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, queryWithDO(t, "signed.test.", protocol.TypeDNSKEY, true))

	if w.msg == nil {
		t.Fatal("no response")
	}
	count := 0
	for _, rr := range w.msg.Answers {
		if rr.Type == protocol.TypeDNSKEY {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%d DNSKEY records, want the 1 from the zone file", count)
	}
}
