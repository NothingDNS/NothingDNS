package transfer

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const rfcRegressionZone = `$ORIGIN example.test.
$TTL 3600
@   IN SOA ns1.example.test. admin.example.test. ( 2026071001 7200 3600 1209600 3600 )
@   IN NS  ns1.example.test.
@   IN NS  ns2.example.test.
@   IN A   192.0.2.10
www IN A   192.0.2.20
www IN A   192.0.2.21
`

func loadRFCRegressionZone(t *testing.T) *zone.Zone {
	t.Helper()
	z, err := zone.ParseFile("example.test.zone", strings.NewReader(rfcRegressionZone))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return z
}

func countApexType(z *zone.Zone, typ string) int {
	n := 0
	for _, r := range z.Records["example.test."] {
		if r.Type == typ {
			n++
		}
	}
	return n
}

// F82: RFC 2136 §3.4.2.3/§3.4.2.4 — UPDATE deletes must never remove the
// apex SOA, the apex NS RRset, or the last apex NS.
func TestApplyUpdate_ApexSOAAndNSProtected(t *testing.T) {
	const apex = "example.test."
	cases := []struct {
		name          string
		ops           []UpdateOperation
		soa, ns, apxA int
	}{
		{"ANY/ANY at apex", []UpdateOperation{{Name: apex, Type: protocol.TypeANY, Operation: UpdateOpDeleteName}}, 1, 2, 0},
		{"ANY/NS at apex", []UpdateOperation{{Name: apex, Type: protocol.TypeNS, Operation: UpdateOpDeleteRRSet}}, 1, 2, 1},
		{"ANY/SOA at apex", []UpdateOperation{{Name: apex, Type: protocol.TypeSOA, Operation: UpdateOpDeleteRRSet}}, 1, 2, 1},
		{"NONE/NS both apex NS", []UpdateOperation{
			{Name: apex, Type: protocol.TypeNS, RData: "ns1.example.test.", Operation: UpdateOpDelete},
			{Name: apex, Type: protocol.TypeNS, RData: "ns2.example.test.", Operation: UpdateOpDelete},
		}, 1, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := loadRFCRegressionZone(t)
			if err := ApplyUpdate(z, &UpdateRequest{ZoneName: z.Origin, Updates: tc.ops}); err != nil {
				t.Fatalf("ApplyUpdate: %v", err)
			}
			if got := [3]int{countApexType(z, "SOA"), countApexType(z, "NS"), countApexType(z, "A")}; got != [3]int{tc.soa, tc.ns, tc.apxA} {
				t.Fatalf("apex SOA/NS/A = %v, want %v", got, [3]int{tc.soa, tc.ns, tc.apxA})
			}
		})
	}
}

// F84: RFC 2136 §3.2.3 — a value-dependent prerequisite RRset must match the
// zone RRset exactly; naming only a subset of the zone's RRs must fail.
func TestApplyUpdate_ValuePrereqRRsetMustMatchExactly(t *testing.T) {
	run := func(vals ...string) error {
		z := loadRFCRegressionZone(t)
		var pre []UpdatePrerequisite
		for _, v := range vals {
			pre = append(pre, UpdatePrerequisite{Name: "www.example.test.", Type: protocol.TypeA, Class: protocol.ClassIN, RData: v, Condition: PrecondExistsValue})
		}
		return ApplyUpdate(z, &UpdateRequest{ZoneName: z.Origin, Prerequisites: pre})
	}
	if err := run("192.0.2.20"); !errors.Is(err, ErrPrereqFailed) {
		t.Fatalf("subset prerequisite: err = %v, want ErrPrereqFailed", err)
	}
	if err := run("192.0.2.21", "192.0.2.20"); err != nil {
		t.Fatalf("exact prerequisite RRset: %v", err)
	}
}

func tsigRegressionWireName(t *testing.T, s string) []byte {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 256)
	l, err := protocol.PackName(n, b, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b[:l]
}

// tsigReferenceMAC is an independent RFC 8945 §4.3 digest over the message
// (with Original ID substituted) and every TSIG variable.
func tsigReferenceMAC(t *testing.T, key *TSIGKey, m *protocol.Message, ts *TSIGRecord) []byte {
	t.Helper()
	c := *m
	c.Header.ID = ts.OriginalID
	c.Header.ARCount = 0
	c.Additionals = nil
	buf := make([]byte, 65535)
	n, err := c.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	d := append([]byte{}, buf[:n]...)
	d = append(d, tsigRegressionWireName(t, key.Name)...)
	d = append(d, 0, 255, 0, 0, 0, 0)
	d = append(d, tsigRegressionWireName(t, key.Algorithm)...)
	sec := uint64(ts.TimeSigned.Unix())
	d = append(d, byte(sec>>40), byte(sec>>32), byte(sec>>24), byte(sec>>16), byte(sec>>8), byte(sec))
	d = append(d, byte(ts.Fudge>>8), byte(ts.Fudge), byte(ts.Error>>8), byte(ts.Error))
	d = append(d, byte(len(ts.OtherData)>>8), byte(len(ts.OtherData)))
	d = append(d, ts.OtherData...)
	h := hmac.New(sha256.New, key.Secret)
	h.Write(d)
	return h.Sum(nil)
}

func tsigRegressionMessage(t *testing.T, id uint16) *protocol.Message {
	t.Helper()
	q, err := protocol.NewQuestion("example.test.", protocol.TypeSOA, protocol.ClassIN)
	if err != nil {
		t.Fatal(err)
	}
	m := protocol.NewMessage(protocol.Header{ID: id})
	m.AddQuestion(q)
	return m
}

func tsigRegressionAttach(t *testing.T, m *protocol.Message, key *TSIGKey, ts *TSIGRecord) {
	t.Helper()
	raw, err := PackTSIGRecord(ts)
	if err != nil {
		t.Fatal(err)
	}
	kn, err := protocol.ParseName(key.Name)
	if err != nil {
		t.Fatal(err)
	}
	m.Additionals = append(m.Additionals, &protocol.ResourceRecord{Name: kn, Type: protocol.TypeTSIG, Class: protocol.ClassANY, Data: &RDataTSIG{Raw: raw}})
	m.Header.ARCount = uint16(len(m.Additionals))
}

// F83: RFC 8945 §4.3 — the TSIG MAC covers Error, Other Data and the
// Original ID; altering them must break verification, and an RFC-correct
// peer MAC over non-zero Error/Other Data must verify.
func TestVerifyMessage_MACCoversErrorOtherDataAndOriginalID(t *testing.T) {
	newKey := func(name string) *TSIGKey {
		return &TSIGKey{Name: name, Algorithm: HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}
	}
	tamper := func(k *TSIGKey, mut func(*TSIGRecord)) *protocol.Message {
		m := tsigRegressionMessage(t, 0x1234)
		rr, err := SignMessage(m, k, 300)
		if err != nil {
			t.Fatalf("SignMessage: %v", err)
		}
		ts, _, err := UnpackTSIGRecord(rr.Data.(*RDataTSIG).Raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		mut(ts)
		tsigRegressionAttach(t, m, k, ts)
		return m
	}

	k := newKey("f83-error.")
	if err := VerifyMessage(tamper(k, func(ts *TSIGRecord) {
		ts.Error, ts.OtherData, ts.OtherLen = TSIGErrBadTime, []byte{0, 0, 0x65, 0, 0, 0}, 6
	}), k, nil); err == nil {
		t.Error("tampered Error/Other Data accepted")
	}
	k = newKey("f83-origid.")
	if err := VerifyMessage(tamper(k, func(ts *TSIGRecord) { ts.OriginalID ^= 0xffff }), k, nil); err == nil {
		t.Error("tampered Original ID accepted")
	}

	k = newKey("f83-peer.")
	m := tsigRegressionMessage(t, 0x0bad) // header ID rewritten in transit
	m.Header.Flags.QR = true
	ts := &TSIGRecord{Algorithm: HmacSHA256, TimeSigned: time.Now().Truncate(time.Second), Fudge: 300,
		OriginalID: 0x4242, Error: TSIGErrBadTime, OtherData: []byte{0, 0, 0x65, 0, 0, 1}, OtherLen: 6}
	ts.MAC = tsigReferenceMAC(t, k, m, ts)
	tsigRegressionAttach(t, m, k, ts)
	if err := VerifyMessage(m, k, nil); err != nil {
		t.Errorf("RFC 8945-correct peer MAC rejected: %v", err)
	}
}
