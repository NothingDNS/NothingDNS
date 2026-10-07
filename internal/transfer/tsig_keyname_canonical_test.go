package transfer

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F502 (P2-E4): TSIG key names are matched in canonical form (lower-case,
// absolute — RFC 8945 §4.2). A key configured as "xfr-key" or "XFR-Key."
// must authenticate AXFR / IXFR / UPDATE requests a client signs with
// "xfr-key.", and responses must be signed with the canonical name.

const keynameTestSecret = "RjUwMi1rZXluYW1lLXNlY3JldC0wMTIzNDU2Nzg5YWI=" // 32 bytes

func keynameZone() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 300, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 7, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["example.com."] = []zone.Record{{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."}}
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"}}
	return z
}

// keynameClientKey is the key as a BIND/kdig client signs with it: absolute,
// lower-case name, constructed directly (not via ParseTSIGKey).
func keynameClientKey(secret []byte) *TSIGKey {
	return &TSIGKey{Name: "xfr-key.", Algorithm: HmacSHA256, Secret: secret}
}

func keynameServerStore(t *testing.T, configured string) (*KeyStore, *TSIGKey) {
	t.Helper()
	k, err := ParseTSIGKey(configured, HmacSHA256, keynameTestSecret)
	if err != nil {
		t.Fatalf("ParseTSIGKey(%q): %v", configured, err)
	}
	ks := NewKeyStore()
	ks.AddKey(k)
	return ks, k
}

func keynameSign(t *testing.T, req *protocol.Message, key *TSIGKey) *protocol.Message {
	t.Helper()
	rr, err := SignMessage(req, key, 300)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	req.Additionals = append(req.Additionals, rr)
	return req
}

func keynameQuery(t *testing.T, qtype uint16, soaSerial uint32) *protocol.Message {
	t.Helper()
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{Header: protocol.Header{ID: 502, QDCount: 1},
		Questions: []*protocol.Question{{Name: name, QType: qtype, QClass: protocol.ClassIN}}}
	if qtype == protocol.TypeIXFR {
		ns, _ := protocol.ParseName("ns1.example.com.")
		rn, _ := protocol.ParseName("admin.example.com.")
		req.Authorities = []*protocol.ResourceRecord{{Name: name, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataSOA{MName: ns, RName: rn, Serial: soaSerial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}}}
		req.Header.NSCount = 1
	}
	return req
}

func TestCanonicalTSIGKeyName(t *testing.T) {
	for in, want := range map[string]string{
		"xfr-key": "xfr-key.", "xfr-key.": "xfr-key.", "XFR-Key.": "xfr-key.", " Key.Example ": "key.example.",
	} {
		if got := CanonicalTSIGKeyName(in); got != want {
			t.Errorf("CanonicalTSIGKeyName(%q) = %q, want %q", in, got, want)
		}
	}
	k, err := ParseTSIGKey("XFR-Key", HmacSHA256, keynameTestSecret)
	if err != nil || k.Name != "xfr-key." {
		t.Fatalf("ParseTSIGKey name = %q err=%v, want canonical xfr-key.", k.Name, err)
	}
}

func TestTSIGKeyName_CanonicalMatchAXFRIXFR(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	for _, configured := range []string{"xfr-key.", "xfr-key", "XFR-Key.", "XFR-KEY"} {
		ks, srvKey := keynameServerStore(t, configured)
		client := keynameClientKey(srvKey.Secret)
		s := NewAXFRServer(map[string]*zone.Zone{"example.com.": keynameZone()}, WithKeyStore(ks), WithRequireTSIG(), WithAllowList([]string{"127.0.0.0/8"}))

		for rep := 0; rep < 2; rep++ {
			recs, key, err := s.HandleAXFR(keynameSign(t, keynameQuery(t, protocol.TypeAXFR, 0), client), ip)
			if err != nil || len(recs) == 0 || key != srvKey {
				t.Fatalf("configured %q AXFR rep %d: records=%d key=%v err=%v", configured, rep, len(recs), key, err)
			}
			out, err := SignMessage(&protocol.Message{Header: protocol.Header{ID: 502}}, key, 300)
			if err != nil || out.Name.String() != "xfr-key." {
				t.Fatalf("configured %q: response TSIG owner = %v err=%v, want canonical xfr-key.", configured, out, err)
			}
		}
		recs, key, err := NewIXFRServer(s).HandleIXFRWithKey(keynameSign(t, keynameQuery(t, protocol.TypeIXFR, 7), client), ip)
		if err != nil || len(recs) == 0 || key != srvKey {
			t.Fatalf("configured %q IXFR: records=%d key=%v err=%v", configured, len(recs), key, err)
		}

		// Wrong secret under the same name still fails; another name is unknown.
		wrong := keynameClientKey([]byte("F502-wrong-secret-0123456789abcd"))
		if _, _, err := s.HandleAXFR(keynameSign(t, keynameQuery(t, protocol.TypeAXFR, 0), wrong), ip); err == nil {
			t.Fatalf("configured %q: wrong secret accepted", configured)
		}
		other := &TSIGKey{Name: "xfr-key2.", Algorithm: HmacSHA256, Secret: srvKey.Secret}
		if _, _, err := s.HandleAXFR(keynameSign(t, keynameQuery(t, protocol.TypeAXFR, 0), other), ip); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("configured %q: unknown key name err=%v, want not found", configured, err)
		}
	}
}

func TestTSIGKeyName_CanonicalMatchUPDATE(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	for _, configured := range []string{"xfr-key", "XFR-Key."} {
		ks, srvKey := keynameServerStore(t, configured)
		z := keynameZone()
		h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
		h.SetKeyStore(ks)
		h.AllowKeyUpdate(configured, "example.com")
		rr := policyA(t, "new.example.com.", "192.0.2.9", protocol.ClassIN)
		resp, key, err := h.HandleUpdateRequest(policyUpdate(t, keynameClientKey(srvKey.Secret), rr), ip, nil)
		if err != nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || key != srvKey || len(z.Records["new.example.com."]) != 1 {
			t.Fatalf("configured %q UPDATE: rcode=%d key=%v err=%v", configured, resp.Header.Flags.RCODE, key, err)
		}
	}
}

func TestKeyStore_CanonicalNameOperations(t *testing.T) {
	ks := NewKeyStoreWithGracePeriod(time.Hour)
	k1, _ := ParseTSIGKey("Rot-Key", HmacSHA256, keynameTestSecret)
	k1.AllowedCIDRs = []string{"192.0.2.0/24"}
	ks.AddKey(k1)
	if err := ks.ValidateKeySource("rot-key.", net.ParseIP("192.0.2.5")); err != nil {
		t.Fatalf("ValidateKeySource canonical: %v", err)
	}
	if err := ks.ValidateKeySource("ROT-KEY", net.ParseIP("198.51.100.1")); err == nil || strings.Contains(err.Error(), "not found") {
		t.Fatalf("ValidateKeySource outside CIDR: err=%v, want CIDR rejection", err)
	}
	k2 := &TSIGKey{Name: "ROT-KEY.", Algorithm: HmacSHA256, Secret: []byte("F502-rotated-secret-0123456789ab")}
	ks.RotateKey(k2)
	if got, _ := ks.GetKey("rot-key"); got != k2 {
		t.Fatal("RotateKey under a differently-cased name did not replace the key")
	}
	if ks.GetPreviousKey("rot-key.") != k1 || ks.GetPreviousKey("Rot-Key") != k1 {
		t.Fatal("GetPreviousKey must match the canonical name")
	}
	ks.ReplaceKey("rot-key", k1)
	if got, _ := ks.GetKey("ROT-KEY."); got != k1 {
		t.Fatal("ReplaceKey canonical lookup failed")
	}
	ks.RemoveKey("Rot-Key.")
	if ks.HasKeys() {
		t.Fatal("RemoveKey with a differently-formed name left the key")
	}
}
