package protocol

import (
	"bytes"
	"testing"
)

func svcbTestRData(priority uint16, params ...[]byte) []byte {
	b := []byte{byte(priority >> 8), byte(priority), 3, 's', 'v', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	for _, p := range params {
		b = append(b, p...)
	}
	return b
}

func svcbTestParam(key uint16, val ...byte) []byte {
	return append([]byte{byte(key >> 8), byte(key), byte(len(val) >> 8), byte(len(val))}, val...)
}

// TestSVCBWireParamsRepackVerbatim covers F117/F118: Unpack accepts
// semantically malformed SvcParams (RFC 9460 §4.3, forwarders pass them
// through) and AliasMode params, so Pack must re-emit them verbatim instead of
// failing the whole message or rewriting RDATA covered by an RRSIG.
func TestSVCBWireParamsRepackVerbatim(t *testing.T) {
	cases := map[string][]byte{
		"ServiceMode keys out of order":     svcbTestRData(1, svcbTestParam(SvcParamKeyPort, 1, 0xbb), svcbTestParam(SvcParamKeyALPN, 2, 'h', '2')),
		"ServiceMode no-default-alpn alone": svcbTestRData(1, svcbTestParam(SvcParamKeyNoDefaultALPN)),
		"AliasMode with params":             svcbTestRData(0, svcbTestParam(SvcParamKeyPort, 1, 0xbb)),
		"AliasMode bare (control)":          svcbTestRData(0),
		"ServiceMode well-formed (control)": svcbTestRData(1, svcbTestParam(SvcParamKeyALPN, 2, 'h', '2')),
	}
	for name, wire := range cases {
		for _, rd := range []RData{&RDataSVCB{}, &RDataHTTPS{}} {
			if _, err := rd.Unpack(wire, 0, uint16(len(wire))); err != nil {
				t.Fatalf("%s %T: Unpack: %v", name, rd, err)
			}
			for _, r := range []RData{rd, rd.Copy()} {
				buf := make([]byte, 256)
				n, err := r.Pack(buf, 0)
				if err != nil {
					t.Fatalf("%s %T: Pack: %v", name, r, err)
				}
				if !bytes.Equal(buf[:n], wire) || r.Len() != n {
					t.Fatalf("%s %T: repacked %x (Len %d), want %x", name, r, buf[:n], r.Len(), wire)
				}
			}
		}
	}

	// Message level: a parsed upstream response must re-pack.
	rd := cases["ServiceMode keys out of order"]
	msgWire := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 's', 'v', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 65, 0, 1,
		0xc0, 12, 0, 65, 0, 1, 0, 0, 0, 60, 0, byte(len(rd))}
	msgWire = append(msgWire, rd...)
	msg, err := UnpackMessage(msgWire)
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}
	if _, err := msg.Pack(make([]byte, 4096)); err != nil {
		t.Fatalf("re-pack of parsed upstream response failed: %v", err)
	}

	// Locally built records keep the authoring validation.
	target, _ := ParseName("svc.example.")
	local := &RDataHTTPS{Priority: 1, Target: target, Params: []SvcParam{
		{Key: SvcParamKeyPort, Value: []byte{1, 0xbb}},
		{Key: SvcParamKeyALPN, Value: []byte{2, 'h', '2'}},
	}}
	if _, err := local.Pack(make([]byte, 256), 0); err == nil {
		t.Fatal("locally built out-of-order record packed without validation")
	}
}

// TestSVCBALPNTextRoundTripEscapes covers F119: alpn protocol ids containing
// ',' or '\' must survive String() -> ParseRDataText (RFC 9460 Appendix A.1).
func TestSVCBALPNTextRoundTripEscapes(t *testing.T) {
	target, _ := ParseName(".")
	for _, ids := range [][]string{{"a,b"}, {`f\oo,bar`, "h2"}, {`a\`}, {"h2", "h3"}} {
		var wire []byte
		for _, id := range ids {
			wire = append(wire, byte(len(id)))
			wire = append(wire, id...)
		}
		rd := &RDataHTTPS{Priority: 1, Target: target, Params: []SvcParam{{Key: SvcParamKeyALPN, Value: wire}}}
		parsed := ParseRDataText("HTTPS", rd.String())
		if parsed == nil {
			t.Fatalf("%q: ParseRDataText(%q) = nil", ids, rd.String())
		}
		want := make([]byte, rd.Len())
		got := make([]byte, parsed.Len())
		if _, err := rd.Pack(want, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Pack(got, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%q: text %q re-parsed to %x, want %x", ids, rd.String(), got, want)
		}
	}
}
