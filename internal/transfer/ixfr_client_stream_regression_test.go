package transfer

import (
	"net"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// R30 regressions for IXFRClient.receiveIXFRResponse (F197, F198, F199).

type ixfrTestMsg struct {
	answers []*protocol.ResourceRecord
	key     *TSIGKey // nil = unsigned
}

// ixfrTestRequestMAC stands in for the MAC of the client's signed request.
var ixfrTestRequestMAC = []byte("r53-ixfr-test-request-mac-32byte")

// ixfrStreamFrames builds the framed response stream. Signed messages form one
// RFC 8945 §5.3.1 chain (TSIGStreamSigner) bound to ixfrTestRequestMAC;
// unsigned messages after the first signed one are digested into the next
// signature.
func ixfrStreamFrames(t *testing.T, id uint16, msgs []ixfrTestMsg) [][]byte {
	t.Helper()
	var signer *TSIGStreamSigner
	var frames [][]byte
	for _, m := range msgs {
		msg := &protocol.Message{
			Header:  protocol.Header{ID: id, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: m.answers,
		}
		if m.key != nil {
			if signer == nil {
				signer = NewTSIGStreamSigner(m.key, ixfrTestRequestMAC, 300)
			}
			tsigRR, err := signer.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			msg.Additionals = append(msg.Additionals, tsigRR)
		} else if signer != nil {
			if err := signer.Skip(msg); err != nil {
				t.Fatalf("Skip: %v", err)
			}
		}
		frames = append(frames, frameMessage(t, msg))
	}
	return frames
}

// runIXFRStream feeds frames to receiveIXFRResponse over net.Pipe, then closes
// the server side (a master closing or dying after its last write).
func runIXFRStream(t *testing.T, frames [][]byte, key *TSIGKey, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer serverConn.Close()
		for _, f := range frames {
			if _, err := serverConn.Write(f); err != nil {
				return
			}
		}
	}()
	recs, err := NewIXFRClient("unused:53").receiveIXFRResponseForRequest(clientConn, 0x4242, key, clientSerial, ixfrTestRequestMAC)
	clientConn.Close()
	<-writerDone
	return recs, err
}

func ixfrDiffStream(t *testing.T) []*protocol.ResourceRecord {
	// 2 -> 3: delete www A .1, add www A .2.
	return []*protocol.ResourceRecord{
		mkSOARR(t, 3), mkSOARR(t, 2), mkARR(t, "www.example.com.", 192, 0, 2, 1),
		mkSOARR(t, 3), mkARR(t, "www.example.com.", 192, 0, 2, 2), mkSOARR(t, 3),
	}
}

func onePerMessage(rrs []*protocol.ResourceRecord, key *TSIGKey) []ixfrTestMsg {
	var out []ixfrTestMsg
	for i, rr := range rrs {
		m := ixfrTestMsg{answers: []*protocol.ResourceRecord{rr}}
		if i == 0 || i == len(rrs)-1 {
			m.key = key
		}
		out = append(out, m)
	}
	return out
}

// F198: a lone-SOA message is terminal only when it is the up-to-date answer;
// a master that sends one RR per message must still be read to the closing SOA.
func TestIXFRClient_OneRecordPerMessageStreamReadToEnd(t *testing.T) {
	stream := ixfrDiffStream(t)
	recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, nil)), nil, 2)
	if err != nil || len(recs) != len(stream) {
		t.Fatalf("one-RR-per-message IXFR: got %d records err=%v, want %d records", len(recs), err, len(stream))
	}

	// End to end: the slave must apply the diff, not take the lone-SOA
	// "up to date" path that bumps the serial over stale data.
	sm := &SlaveManager{}
	sz := newTestSlaveZone(t)
	if err := sm.applyTransferredZone(sz, []*protocol.ResourceRecord{mkSOARR(t, 2), mkARR(t, "www.example.com.", 192, 0, 2, 1), mkSOARR(t, 2)}); err != nil {
		t.Fatalf("seeding base zone: %v", err)
	}
	if err := sm.applyTransferredZone(sz, recs); err != nil {
		t.Fatalf("applying IXFR: %v", err)
	}
	z := sz.GetZone()
	if sz.GetLastSerial() != 3 || zoneHas(z, "www.example.com.", "A", "192.0.2.1") || !zoneHas(z, "www.example.com.", "A", "192.0.2.2") {
		t.Fatalf("slave zone after IXFR: serial=%d has .1=%v has .2=%v; want serial 3 with only .2",
			sz.GetLastSerial(), zoneHas(z, "www.example.com.", "A", "192.0.2.1"), zoneHas(z, "www.example.com.", "A", "192.0.2.2"))
	}

	// Controls: the up-to-date single SOA (equal, and client newer) is still
	// terminal; AXFR-style and multi-diff streams terminate at the closing SOA.
	for _, cs := range []uint32{3, 4} {
		recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, []ixfrTestMsg{{answers: []*protocol.ResourceRecord{mkSOARR(t, 3)}}}), nil, cs)
		if err != nil || len(recs) != 1 {
			t.Fatalf("up-to-date single SOA (client %d): got %d records err=%v", cs, len(recs), err)
		}
	}
	axfr := []*protocol.ResourceRecord{mkSOARR(t, 3), mkARR(t, "www.example.com.", 192, 0, 2, 2), mkSOARR(t, 3)}
	if recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(axfr, nil)), nil, 2); err != nil || len(recs) != 3 {
		t.Fatalf("AXFR-style one-RR-per-message: got %d records err=%v", len(recs), err)
	}
	multi := []*protocol.ResourceRecord{
		mkSOARR(t, 4), mkSOARR(t, 2), mkSOARR(t, 3), mkARR(t, "a.example.com.", 192, 0, 2, 3),
		mkSOARR(t, 3), mkSOARR(t, 4), mkSOARR(t, 4),
	}
	if recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(multi, nil)), nil, 2); err != nil || len(recs) != len(multi) {
		t.Fatalf("multi-diff one-RR-per-message: got %d records err=%v", len(recs), err)
	}
}

// F199: a stream that ends (EOF) before its closing SOA is truncated and must
// be an error, at every truncation point — including the one right after the
// additions-opening SOA, whose serial equals the target.
func TestIXFRClient_TruncatedStreamRejected(t *testing.T) {
	stream := ixfrDiffStream(t)
	for cut := 1; cut < len(stream); cut++ {
		recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, []ixfrTestMsg{{answers: stream[:cut]}}), nil, 2)
		if err == nil {
			t.Fatalf("stream truncated after %d of %d RRs accepted (%d records)", cut, len(stream), len(recs))
		}
	}
	// Records after the closing SOA are a malformed stream.
	extra := append(append([]*protocol.ResourceRecord{}, stream...), mkARR(t, "x.example.com.", 192, 0, 2, 9))
	if _, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, []ixfrTestMsg{{answers: extra}}), nil, 2); err == nil {
		t.Fatal("records after the closing SOA accepted")
	}
	if recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, []ixfrTestMsg{{answers: stream}}), nil, 2); err != nil || len(recs) != len(stream) {
		t.Fatalf("control complete stream: got %d records err=%v", len(recs), err)
	}
}

// F197: a TSIG-keyed IXFR must have its first and last messages signed and at
// most 99 consecutive unsigned messages (RFC 8945 §5.3.1).
func TestIXFRClient_KeyedTransferRequiresTSIG(t *testing.T) {
	key := &TSIGKey{Name: "r30-ixfr-key.", Algorithm: HmacSHA256, Secret: []byte("0123456789abcdef0123456789abcdef")}
	stream := ixfrDiffStream(t)

	// Control: signed first and last, unsigned middle.
	if recs, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, onePerMessage(stream, key)), key, 2); err != nil || len(recs) != len(stream) {
		t.Fatalf("control signed first/last: got %d records err=%v", len(recs), err)
	}

	cases := map[string][]ixfrTestMsg{
		"unsigned single message":        {{answers: stream}},
		"unsigned first, signed last":    {{answers: stream[:3]}, {answers: stream[3:], key: key}},
		"signed first, unsigned last":    {{answers: stream[:3], key: key}, {answers: stream[3:]}},
		"unsigned up-to-date single SOA": {{answers: []*protocol.ResourceRecord{mkSOARR(t, 2)}}},
	}
	for name, msgs := range cases {
		if _, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, msgs), key, 2); err == nil || !strings.Contains(err.Error(), "TSIG") {
			t.Fatalf("%s: err=%v, want TSIG rejection", name, err)
		}
	}

	// 99 unsigned messages between signed ones is the limit; 100 is rejected.
	for _, gap := range []int{99, 100} {
		msgs := []ixfrTestMsg{{answers: []*protocol.ResourceRecord{mkSOARR(t, 3)}, key: key}}
		for i := 0; i < gap; i++ {
			msgs = append(msgs, ixfrTestMsg{answers: []*protocol.ResourceRecord{mkARR(t, "www.example.com.", 192, 0, 2, byte(i))}})
		}
		msgs = append(msgs, ixfrTestMsg{answers: []*protocol.ResourceRecord{mkSOARR(t, 3)}, key: key})
		_, err := runIXFRStream(t, ixfrStreamFrames(t, 0x4242, msgs), key, 2)
		if gap == 99 && err != nil {
			t.Fatalf("99 unsigned messages rejected: %v", err)
		}
		if gap == 100 && (err == nil || !strings.Contains(err.Error(), "unsigned")) {
			t.Fatalf("100 unsigned messages: err=%v, want rejection", err)
		}
	}
}
