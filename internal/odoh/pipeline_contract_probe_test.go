package odoh

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// pipelineMimicHandler mimics the production pipeline contract — the inner
// handler writes a POOLED response message (from UnpackMessage, exactly like
// upstreamStage) and Releases it at stage exit (upstreamStage's defer
// resp.Release() fires before ServeDNS returns to the ODoH target).
type pipelineMimicHandler struct {
	tmpl *protocol.Message
}

func (h *pipelineMimicHandler) ServeDNS(w server.ResponseWriter, _ *protocol.Message) {
	packed := make([]byte, h.tmpl.WireLength())
	n, err := h.tmpl.Pack(packed)
	if err != nil {
		return
	}
	resp, err := protocol.UnpackMessage(packed[:n]) // pooled message, like upstreamStage
	if err != nil {
		return
	}
	w.Write(resp)  // reply() writes the same pointer to the writer
	resp.Release() // upstreamStage's defer resp.Release() — fires before odoh.go resumes
}

// TestODoHTarget_PipelineReleasedResponseEncrypted drives the ODoH target
// with a handler that mimics the production pipeline contract (write a pooled
// response, Release it at stage exit). The encrypted response must still
// decrypt to the handler's answer — the target must snapshot the wire while
// the message is alive, not read (or Release) it after the pipeline Released
// it. Guards against reintroducing the use-after-release/double-Release bug
// fixed in odoh.go (the writer snapshots at Write time; the target never
// touches the handler's message afterwards).
func TestODoHTarget_PipelineReleasedResponseEncrypted(t *testing.T) {
	respMsg, err := protocol.NewQuery(0xdead, "probe.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	respMsg.Header.Flags.QR = true
	rr, _ := protocol.NewResourceRecord("probe.example.com.", protocol.TypeA, protocol.ClassIN, 300, &protocol.RDataA{Address: [4]byte{9, 9, 9, 9}})
	respMsg.Answers = append(respMsg.Answers, rr)
	respMsg.Header.ANCount = 1

	target, err := NewObliviousTarget(NewODoHConfig("target.example.com", "proxy.example.com"), &pipelineMimicHandler{tmpl: respMsg})
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	queryMsg, _ := protocol.NewQuery(0xdead, "probe.example.com.", protocol.TypeA)
	queryWire := make([]byte, queryMsg.WireLength())
	if _, err := queryMsg.Pack(queryWire); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	msgBytes, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), queryWire)
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("ServeHTTP status = %d", w.Code)
	}

	plain, err := qCtx.decryptResponse(w.Body.Bytes())
	if err != nil {
		t.Fatalf("decryptResponse: %v", err)
	}
	got, err := protocol.UnpackMessage(plain)
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}
	if got.Header.ID != 0xdead || len(got.Answers) != 1 {
		t.Fatalf("pipeline-written response corrupted by the ODoH target: id=%#x answers=%d (want 0xdead/1)", got.Header.ID, len(got.Answers))
	}
}
