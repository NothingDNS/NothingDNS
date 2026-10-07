package transfer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// R53 regressions for multi-message TSIG (RFC 8945 §4.3.3, §5.3.1): F314.

var r53StreamKey = &TSIGKey{Name: "r53-stream-key.example.", Algorithm: HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}

func r53WireName(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, 256)
	n, err := protocol.PackName(mkName(t, s), b, 0, nil)
	if err != nil {
		t.Fatalf("PackName: %v", err)
	}
	return b[:n]
}

func r53Pack(t *testing.T, m *protocol.Message) []byte {
	t.Helper()
	b := make([]byte, 65535)
	n, err := m.Pack(b)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return b[:n]
}

func r53Resp(id uint16, rr *protocol.ResourceRecord) *protocol.Message {
	return &protocol.Message{
		Header:  protocol.Header{ID: id, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{rr},
	}
}

func r53HMAC(data []byte) []byte {
	h := hmac.New(sha256.New, r53StreamKey.Secret)
	h.Write(data)
	return h.Sum(nil)
}

func r53TSIGMAC(t *testing.T, rr *protocol.ResourceRecord) []byte {
	t.Helper()
	ts, _, err := UnpackTSIGRecord(rr.Data.(*RDataTSIG).Raw, 0)
	if err != nil {
		t.Fatalf("UnpackTSIGRecord: %v", err)
	}
	return ts.MAC
}

// F314: TSIGStreamSigner produces the RFC 8945 digests, checked against an
// independent byte-level construction at a fixed time: the first message
// digests the request MAC, the message and all TSIG variables; a later signed
// message digests the prior MAC, the unsigned messages since, the message and
// the TSIG timers only.
func TestTSIGStream_RFC8945DigestVector(t *testing.T) {
	ts := time.Unix(1767225600, 0) // 2026-01-01T00:00:00Z
	requestMAC := bytes.Repeat([]byte{0xab}, 32)
	signer := NewTSIGStreamSigner(r53StreamKey, requestMAC, 300)
	signer.now = func() time.Time { return ts }

	m1 := r53Resp(0x2222, mkSOARR(t, 3))
	m2 := r53Resp(0x2222, mkARR(t, "www.example.com.", 192, 0, 2, 2))
	m3 := r53Resp(0x2222, mkSOARR(t, 3))
	b1, b2, b3 := r53Pack(t, m1), r53Pack(t, m2), r53Pack(t, m3)

	rr1, err := signer.Sign(m1)
	if err != nil {
		t.Fatalf("Sign(m1): %v", err)
	}
	if err := signer.Skip(m2); err != nil {
		t.Fatalf("Skip(m2): %v", err)
	}
	rr3, err := signer.Sign(m3)
	if err != nil {
		t.Fatalf("Sign(m3): %v", err)
	}

	timeAndFudge := []byte{0x00, 0x00, 0x69, 0x55, 0xb9, 0x00, 0x01, 0x2c} // 1767225600, fudge 300
	var d1 []byte
	d1 = append(d1, 0x00, 0x20)
	d1 = append(d1, requestMAC...)
	d1 = append(d1, b1...)
	d1 = append(d1, r53WireName(t, r53StreamKey.Name)...)
	d1 = append(d1, 0x00, 0xff, 0, 0, 0, 0) // class ANY, TTL 0
	d1 = append(d1, r53WireName(t, HmacSHA256)...)
	d1 = append(d1, timeAndFudge...)
	d1 = append(d1, 0, 0, 0, 0) // error, other len
	want1 := r53HMAC(d1)
	if got := r53TSIGMAC(t, rr1); !hmac.Equal(got, want1) {
		t.Fatalf("first message MAC = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want1))
	}

	var d3 []byte
	d3 = append(d3, 0x00, 0x20)
	d3 = append(d3, want1...)
	d3 = append(d3, b2...)
	d3 = append(d3, b3...)
	d3 = append(d3, timeAndFudge...)
	want3 := r53HMAC(d3)
	if got := r53TSIGMAC(t, rr3); !hmac.Equal(got, want3) {
		t.Fatalf("third message MAC = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want3))
	}
}

// r53Stream signs answers one per message; signedIdx selects the signed ones.
func r53Stream(t *testing.T, requestMAC []byte, answers []*protocol.ResourceRecord, signedIdx map[int]bool) []*protocol.Message {
	t.Helper()
	signer := NewTSIGStreamSigner(r53StreamKey, requestMAC, 300)
	var out []*protocol.Message
	for i, rr := range answers {
		m := r53Resp(0x4343, rr)
		if signedIdx[i] {
			tsigRR, err := signer.Sign(m)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			m.Additionals = append(m.Additionals, tsigRR)
		} else if err := signer.Skip(m); err != nil {
			t.Fatalf("Skip: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func r53RunAXFR(t *testing.T, msgs []*protocol.Message, requestMAC []byte) ([]*protocol.ResourceRecord, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		for _, m := range msgs {
			if _, err := serverConn.Write(frameMessage(t, m)); err != nil {
				return
			}
		}
	}()
	recs, err := NewAXFRClient("unused:53").receiveAXFRResponseForRequest(clientConn, 0x4343, r53StreamKey, requestMAC)
	clientConn.Close()
	<-done
	return recs, err
}

// F314: the transfer clients verify the whole stream as one chain bound to
// the request MAC — unsigned messages included — and reject a stream signed
// for another request or with the pre-R53 standalone/unbound convention.
func TestTSIGStream_ClientVerifiesRequestBoundChain(t *testing.T) {
	requestMAC := bytes.Repeat([]byte{0x5a}, 32)
	answers := []*protocol.ResourceRecord{mkSOARR(t, 3), mkARR(t, "a.example.com.", 192, 0, 2, 1), mkARR(t, "b.example.com.", 192, 0, 2, 2), mkSOARR(t, 3)}
	firstAndLast := map[int]bool{0: true, 3: true}

	if recs, err := r53RunAXFR(t, r53Stream(t, requestMAC, answers, firstAndLast), requestMAC); err != nil || len(recs) != 4 {
		t.Fatalf("RFC 8945 chain with unsigned middle: records=%d err=%v", len(recs), err)
	}
	all := map[int]bool{0: true, 1: true, 2: true, 3: true}
	if recs, err := r53RunAXFR(t, r53Stream(t, requestMAC, answers, all), requestMAC); err != nil || len(recs) != 4 {
		t.Fatalf("RFC 8945 chain, every message signed: records=%d err=%v", len(recs), err)
	}

	// Bound to another request: a captured response cannot be replayed.
	other := bytes.Repeat([]byte{0x77}, 32)
	if _, err := r53RunAXFR(t, r53Stream(t, other, answers, firstAndLast), requestMAC); err == nil || !strings.Contains(err.Error(), "TSIG") {
		t.Fatalf("stream signed for another request: err=%v, want TSIG rejection", err)
	}

	// Unsigned messages are covered by the next MAC.
	tampered := r53Stream(t, requestMAC, answers, firstAndLast)
	tampered[1].Answers = []*protocol.ResourceRecord{mkARR(t, "a.example.com.", 203, 0, 113, 66)}
	if _, err := r53RunAXFR(t, tampered, requestMAC); err == nil || !strings.Contains(err.Error(), "TSIG") {
		t.Fatalf("tampered unsigned message: err=%v, want TSIG rejection", err)
	}

	// Pre-R53 convention: first message signed standalone (no request MAC).
	legacy := r53Stream(t, nil, answers, firstAndLast)
	if _, err := r53RunAXFR(t, legacy, requestMAC); err == nil || !strings.Contains(err.Error(), "TSIG") {
		t.Fatalf("stream not bound to the request MAC: err=%v, want TSIG rejection", err)
	}

	// 100 consecutive unsigned messages exceed RFC 8945 §5.3.1.
	long := []*protocol.ResourceRecord{mkSOARR(t, 3)}
	for i := 0; i < 100; i++ {
		long = append(long, mkARR(t, "h.example.com.", 198, 51, 100, byte(i)))
	}
	long = append(long, mkSOARR(t, 3))
	if _, err := r53RunAXFR(t, r53Stream(t, requestMAC, long, map[int]bool{0: true, len(long) - 1: true}), requestMAC); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("100 unsigned AXFR messages: err=%v, want rejection", err)
	}
}

// Single-message TSIG (DDNS, NOTIFY, SOA query, transfer requests) keeps its
// pre-R53 digest: golden MACs computed with the baseline tsig.go.
func TestTSIG_SingleMessageDigestUnchanged(t *testing.T) {
	key := &TSIGKey{Name: "ddns-key.example.", Algorithm: HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}
	msg := &protocol.Message{Header: protocol.Header{ID: 0x1234, QDCount: 1}, Questions: []*protocol.Question{{Name: mkName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}}}
	ts := time.Unix(1767225600, 0)

	d, err := buildSignedData(msg, key.Name, nil, key.Algorithm, ts, 300, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := calculateMAC(key.Secret, d, key.Algorithm)
	if got := hex.EncodeToString(m); got != "386a0416ee931bc6e5821a729041840e98a6e9bd6b5754c3f964a5d5b869943a" {
		t.Fatalf("single-message MAC changed: %s", got)
	}
	d, err = buildSignedDataWithError(msg, key.Name, []byte{1, 2, 3, 4}, key.Algorithm, ts, 300, 0x1234, TSIGErrBadTime, []byte{0, 0, 0x69, 0x55, 0x9b, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	m, _ = calculateMAC(key.Secret, d, key.Algorithm)
	if got := hex.EncodeToString(m); got != "55cd898750f112b316afe710d0766c90abfc2f4e769a21b8461d0a7cafd39311" {
		t.Fatalf("request-MAC/error MAC changed: %s", got)
	}

	// Sign/verify round trip of a single message is unaffected.
	tsigRR, err := SignMessage(msg, key, 300)
	if err != nil {
		t.Fatal(err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)
	if err := VerifyMessage(msg, key, nil); err != nil {
		t.Fatalf("single-message round trip: %v", err)
	}
}
