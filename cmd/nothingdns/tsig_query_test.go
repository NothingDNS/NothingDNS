package main

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A TSIG on an ordinary query is verified (unknown key or bad MAC: NOTAUTH)
// and the answer to a verified query is signed against the request MAC (RFC
// 8945 §5.2, §5.3), also when it has to be truncated to fit (F759).

func tsigQueryKey() *transfer.TSIGKey {
	return &transfer.TSIGKey{Name: "q-key.example.", Algorithm: transfer.HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}
}

func tsigQueryHandler(t *testing.T) *integratedHandler {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "example.com.", Type: "SOA", TTL: 300, RData: "ns1.example.com. h.example.com. 1 3600 600 604800 300"},
		{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"},
	})
	h.transfer.AXFRKeys = newManagedKeyStore()
	h.transfer.AXFRKeys.store.AddKey(tsigQueryKey())
	return h
}

func tsigQueryAsk(t *testing.T, h *integratedHandler, key *transfer.TSIGKey, proto string) (*protocol.Message, []byte) {
	q := newTestQuery(t, "www.example.com.", protocol.TypeA)
	q.SetEDNS0(1232, false)
	rr, err := transfer.SignMessage(q, key, 300)
	if err != nil {
		t.Fatal(err)
	}
	q.Additionals = append(q.Additionals, rr)
	mac, err := transfer.TSIGRequestMAC(q)
	if err != nil {
		t.Fatal(err)
	}
	w := newCaptureWriter("127.0.0.1", proto)
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("no response")
	}
	return w.msg, mac
}

func TestTSIGSignedQueryIsVerifiedAndAnswerSigned(t *testing.T) {
	h := tsigQueryHandler(t)
	for _, proto := range []string{"udp", "tcp"} {
		resp, mac := tsigQueryAsk(t, h, tsigQueryKey(), proto)
		if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
			t.Fatalf("%s: rcode %d answers %d", proto, resp.Header.Flags.RCODE, len(resp.Answers))
		}
		if err := transfer.VerifyMessage(resp, tsigQueryKey(), mac); err != nil {
			t.Fatalf("%s: answer not signed against the request MAC: %v", proto, err)
		}
	}
	forged := &transfer.TSIGKey{Name: "q-key.example.", Algorithm: transfer.HmacSHA256, Secret: []byte("ffffffffffffffffffffffffffffffff")}
	unknown := &transfer.TSIGKey{Name: "nobody.example.", Algorithm: transfer.HmacSHA256, Secret: tsigQueryKey().Secret}
	for name, key := range map[string]*transfer.TSIGKey{"bad MAC": forged, "unknown key": unknown} {
		if resp, _ := tsigQueryAsk(t, h, key, "udp"); resp.Header.Flags.RCODE != protocol.RcodeNotAuth || len(resp.Answers) != 0 {
			t.Fatalf("%s: rcode %d, want NOTAUTH", name, resp.Header.Flags.RCODE)
		}
	}
	// No keys configured: any TSIG is an unknown key (RFC 8945 §5.2.1).
	h.transfer.AXFRKeys = nil
	if resp, _ := tsigQueryAsk(t, h, tsigQueryKey(), "udp"); resp.Header.Flags.RCODE != protocol.RcodeNotAuth {
		t.Fatalf("no keys configured: rcode %d", resp.Header.Flags.RCODE)
	}
	// An unsigned query is unaffected.
	w := newCaptureWriter("127.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatal("unsigned query refused")
	}
}

// sizedWriter is a capture writer with a small response limit.
type sizedWriter struct {
	*captureWriter
	max int
}

func (w *sizedWriter) MaxSize() int { return w.max }

// A signed answer that would exceed the client's limit is cut down so that
// message and TSIG fit, and still verifies.
func TestTSIGSignedAnswerFitsTheClientLimit(t *testing.T) {
	key := tsigQueryKey()
	req := newTestQuery(t, "big.example.com.", protocol.TypeTXT)
	rr, err := transfer.SignMessage(req, key, 300)
	if err != nil {
		t.Fatal(err)
	}
	req.Additionals = append(req.Additionals, rr)
	mac, _ := transfer.TSIGRequestMAC(req)

	resp := &protocol.Message{Header: protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}, Questions: req.Questions}
	for i := 0; i < 12; i++ {
		a, _ := protocol.NewResourceRecord("big.example.com.", protocol.TypeTXT, protocol.ClassIN, 300, &protocol.RDataTXT{Strings: []string{strings.Repeat("x", 200)}})
		resp.Answers = append(resp.Answers, a)
	}
	inner := &sizedWriter{captureWriter: newCaptureWriter("127.0.0.1", "udp"), max: 512}
	if _, err := (&tsigResponseWriter{inner: inner, key: key, requestMAC: mac}).Write(resp); err != nil {
		t.Fatal(err)
	}
	got := inner.msg
	wire := make([]byte, 65535)
	n, err := got.Pack(wire)
	if err != nil || n > 512 {
		t.Fatalf("signed answer is %d bytes (err %v), limit 512", n, err)
	}
	if !got.Header.Flags.TC || len(got.Answers) == 0 || len(got.Answers) >= 12 {
		t.Fatalf("answers %d TC %v, want a truncated answer", len(got.Answers), got.Header.Flags.TC)
	}
	if err := transfer.VerifyMessage(got, key, mac); err != nil {
		t.Fatalf("truncated answer does not verify: %v", err)
	}
}
