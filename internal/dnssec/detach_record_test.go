package dnssec

import (
	"bytes"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestDetachRecordRDataSurvivesSourceMessageRelease locks the load-bearing
// invariant that detachRecord (validator.go) relies on: the RData pointer is
// SHARED with the source record, and this is safe only because
// protocol.releaseRData has no case for any DNSSEC rdata type — releasing
// the source message must leave the detached copy's DNSKEY/RRSIG/DS data
// fully intact. If a pooling case for a DNSSEC rdata type is ever added to
// releaseRData, or detachRecord stops returning a usable record, this test
// fails loudly instead of silently corrupting the validation chain.
func TestDetachRecordRDataSurvivesSourceMessageRelease(t *testing.T) {
	origin, _ := protocol.ParseName("example.com.")
	signer, _ := protocol.ParseName("example.com.")

	dnskey := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeDNSKEY,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataDNSKEY{
			Flags:     257,
			Protocol:  3,
			Algorithm: 13,
			PublicKey: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
	}
	rrsig := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataRRSIG{
			TypeCovered: protocol.TypeA,
			Algorithm:   13,
			Labels:      2,
			OriginalTTL: 300,
			Expiration:  4102444800,
			Inception:   1600000000,
			KeyTag:      12345,
			SignerName:  signer,
			Signature:   []byte{0x11, 0x22, 0x33},
		},
	}
	ds := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeDS,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataDS{
			KeyTag:     12345,
			Algorithm:  13,
			DigestType: 2,
			Digest:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	// Build the source the production way: pack and unpack so the records
	// live in a pooled message, exactly like the fetch functions' input.
	msg := protocol.NewMessage(protocol.Header{
		ID:      0x1234,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	msg.Questions = []*protocol.Question{{
		Name:   origin,
		QType:  protocol.TypeDNSKEY,
		QClass: protocol.ClassIN,
	}}
	msg.Answers = []*protocol.ResourceRecord{dnskey, rrsig, ds}

	packed := make([]byte, 2+65535)
	n, err := msg.Pack(packed[2:])
	if err != nil {
		t.Fatalf("packing source message: %v", err)
	}
	source, err := protocol.UnpackMessage(packed[2 : 2+n])
	if err != nil {
		t.Fatalf("unpacking source message: %v", err)
	}

	// The production order: detach from the pooled source, then release.
	detached := make([]*protocol.ResourceRecord, 0, len(source.Answers))
	for _, rr := range source.Answers {
		detached = append(detached, detachRecord(rr))
	}
	source.Release()

	for i, rr := range detached {
		if rr == nil || rr.Data == nil {
			t.Fatalf("FAIL: detached record %d lost its RData after the source message was released", i)
		}
		if rr.Name == nil || rr.Name.String() == "" {
			t.Fatalf("FAIL: detached record %d lost its owner name after the source message was released", i)
		}
	}

	// The values must survive bit-for-bit through the source release.
	key, ok := detached[0].Data.(*protocol.RDataDNSKEY)
	if !ok {
		t.Fatalf("FAIL: detached DNSKEY has unexpected rdata type %T", detached[0].Data)
	}
	if key.Flags != 257 || key.Protocol != 3 || key.Algorithm != 13 ||
		!bytes.Equal(key.PublicKey, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("FAIL: detached DNSKEY rdata was altered by the source release: %+v", key)
	}

	sig, ok := detached[1].Data.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatalf("FAIL: detached RRSIG has unexpected rdata type %T", detached[1].Data)
	}
	if sig.TypeCovered != protocol.TypeA || sig.KeyTag != 12345 ||
		!bytes.Equal(sig.Signature, []byte{0x11, 0x22, 0x33}) {
		t.Fatalf("FAIL: detached RRSIG rdata was altered by the source release: %+v", sig)
	}

	dsRec, ok := detached[2].Data.(*protocol.RDataDS)
	if !ok {
		t.Fatalf("FAIL: detached DS has unexpected rdata type %T", detached[2].Data)
	}
	if dsRec.KeyTag != 12345 || dsRec.DigestType != 2 ||
		!bytes.Equal(dsRec.Digest, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("FAIL: detached DS rdata was altered by the source release: %+v", dsRec)
	}
}
