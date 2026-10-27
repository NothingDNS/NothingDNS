package odoh

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// The target pads its answers to RFC 8467 response blocks (RFC 9230 §11), so
// the proxy cannot tell answer sizes apart from the ciphertext length, and the
// largest answer that fit before still fits (F738).

func paddingTestTarget(t *testing.T) *ObliviousTarget {
	h := server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: r.Questions,
		}
		txt := "x"
		if strings.HasPrefix(r.Questions[0].Name.String(), "long") {
			txt = strings.Repeat("y", 200)
		}
		rr, _ := protocol.NewResourceRecord(r.Questions[0].Name.String(), protocol.TypeTXT, protocol.ClassIN, 300, &protocol.RDataTXT{Strings: []string{txt}})
		resp.Answers = append(resp.Answers, rr)
		w.Write(resp)
	})
	target, err := NewObliviousTarget(NewODoHConfig("target.example.com", "proxy.example.com"), h)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// paddingTestAsk returns the ciphertext length the proxy sees and the decrypted
// DNS answer.
func paddingTestAsk(t *testing.T, target *ObliviousTarget, name string) (int, *protocol.Message) {
	q, _ := protocol.NewQuery(0, name, protocol.TypeTXT)
	wire := make([]byte, q.WireLength())
	n, _ := q.Pack(wire)
	msg, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), wire[:n])
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msg))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	plain, err := qCtx.decryptResponse(w.Body.Bytes())
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	m, err := protocol.UnpackMessage(plain)
	if err != nil {
		t.Fatal(err)
	}
	return w.Body.Len(), m
}

func TestTargetPadsAnswers(t *testing.T) {
	target := paddingTestTarget(t)
	shortLen, _ := paddingTestAsk(t, target, "short.example.")
	longLen, _ := paddingTestAsk(t, target, "long.example.")
	if shortLen != longLen {
		t.Fatalf("ciphertext lengths differ: %d vs %d", shortLen, longLen)
	}

	qmsg, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), []byte{9, 9})
	if err != nil {
		t.Fatal(err)
	}
	_, respCtx, err := target.keyPair.decryptQuery(qmsg)
	if err != nil {
		t.Fatal(err)
	}
	largest := bytes.Repeat([]byte{0xab}, 0xFFFF-16-4) // fills encrypted_message
	out, err := respCtx.encryptResponse(largest)
	if err != nil {
		t.Fatalf("largest answer no longer fits: %v", err)
	}
	if plain, err := qCtx.decryptResponse(out); err != nil || !bytes.Equal(plain, largest) {
		t.Fatalf("largest answer round trip: %v", err)
	}
}
