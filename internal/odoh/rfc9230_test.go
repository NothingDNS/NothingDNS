package odoh

// RFC 9230 / RFC 9180 end-to-end round-trip tests.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

func httptestNewServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(h)
}

// rfc9230MockHandler returns a fixed response for any query so we can
// assert the round-trip identity.
type rfc9230MockHandler struct {
	response *protocol.Message
}

func (h *rfc9230MockHandler) ServeDNS(w server.ResponseWriter, _ *protocol.Message) {
	if h.response == nil {
		return
	}
	// Single ownership: the ODoH target Releases the response message it is
	// given after encrypting it (odoh.go defer rw.response.Release()), so
	// hand it a detached Pack/Unpack copy — never the shared template
	// fixture, whose reuse across requests would be corrupted by that
	// release.
	packed := make([]byte, h.response.WireLength())
	n, err := h.response.Pack(packed)
	if err != nil {
		return
	}
	detached, err := protocol.UnpackMessage(packed[:n])
	if err != nil {
		return
	}
	_, _ = w.Write(detached)
	// The ODoH writer snapshots the wire inside Write; release the detached
	// copy afterwards for pooling hygiene.
	detached.Release()
}

// TestRFC9230RoundTrip exercises the full ODoH flow with the conformant
// HPKE implementation:
//
//  1. Build target with a fresh HPKE key pair.
//  2. Fetch its ObliviousDoHConfigContents.
//  3. Encrypt a DNS query under RFC 9230 §4.1.1 (HPKE base mode).
//  4. POST to the target's ServeHTTP.
//  5. Decrypt the response under RFC 9230 §4.1.2 (response-key
//     derivation from query plaintext + ephemeral pk).
//  6. Confirm the decrypted DNS answer matches what the handler emitted.
func TestRFC9230RoundTrip(t *testing.T) {
	// Build a mock DNS response that the target's handler will produce.
	respMsg, err := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	respMsg.Header.Flags.QR = true
	respMsg.Header.Flags.AA = true
	rr, err := protocol.NewResourceRecord(
		"example.com.", protocol.TypeA, protocol.ClassIN, 300,
		&protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
	)
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}
	respMsg.Answers = append(respMsg.Answers, rr)
	respMsg.Header.ANCount = 1

	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{response: respMsg},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	// Build a DNS query in wire format.
	queryMsg, err := protocol.NewQuery(0xbeef, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery query: %v", err)
	}
	queryWire := make([]byte, queryMsg.WireLength())
	if _, err := queryMsg.Pack(queryWire); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	// Client side: encrypt under the target's published config.
	msgBytes, qCtx, err := encryptQueryRFC9230(target.ConfigContents(), queryWire)
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	// POST it through the target's HTTP handler.
	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("ServeHTTP status = %d, body = %q", w.Code, w.Body.String())
	}
	respBytes := w.Body.Bytes()

	// Client side: decrypt the response. The plaintext envelope used for
	// the response key derivation is the same plaintext the target saw
	// when opening the query — for the client it's the bytes it sealed,
	// reconstructed here.

	plain, err := qCtx.decryptResponse(respBytes)
	if err != nil {
		t.Fatalf("decryptResponse: %v", err)
	}

	got, err := protocol.UnpackMessage(plain)
	if err != nil {
		t.Fatalf("UnpackMessage response: %v", err)
	}
	if got.Header.ID != 0xbeef {
		t.Errorf("response ID = %#x, want 0xbeef", got.Header.ID)
	}
	if len(got.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answers))
	}
	if a, ok := got.Answers[0].Data.(*protocol.RDataA); !ok || a.Address != [4]byte{93, 184, 216, 34} {
		t.Errorf("answer A = %+v, want 93.184.216.34", got.Answers[0].Data)
	}
}

// TestRFC9230_WrongKeyID confirms the target rejects messages framed
// with an incorrect key_id (e.g. addressed to a different target key).
func TestRFC9230_WrongKeyID(t *testing.T) {
	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	// Encrypt to a *different* target's config (fresh key pair) so the
	// key_id won't match.
	other, err := newODoHKeyPair()
	if err != nil {
		t.Fatalf("newODoHKeyPair: %v", err)
	}
	msgBytes, _, err := encryptQueryRFC9230(other.configBytes, []byte{0, 0})
	if err != nil {
		t.Fatalf("encryptQueryRFC9230: %v", err)
	}

	req := httptest.NewRequest("POST", "https://target/dns-query", bytes.NewReader(msgBytes))
	w := httptest.NewRecorder()
	target.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("expected 400 for wrong key_id, got %d", w.Code)
	}
}

func TestMarshalODoHMessageRejectsLengthOverflow(t *testing.T) {
	if _, err := marshalODoHMessage(&odohMessage{
		msgType:          odohMsgTypeQuery,
		keyID:            make([]byte, 65536),
		encryptedMessage: []byte{1},
	}); err == nil {
		t.Fatal("expected oversized key_id to fail")
	}

	if _, err := marshalODoHMessage(&odohMessage{
		msgType:          odohMsgTypeQuery,
		keyID:            []byte{1},
		encryptedMessage: make([]byte, 65536),
	}); err == nil {
		t.Fatal("expected oversized encrypted_message to fail")
	}
}

func TestEncryptQueryRFC9230RejectsOversizedDNSQuery(t *testing.T) {
	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}

	if _, _, err := encryptQueryRFC9230(target.ConfigContents(), make([]byte, 65536)); err == nil {
		t.Fatal("expected oversized DNS query to fail")
	}
}

// TestRFC9230_ConfigsObjectShape verifies the outer-wrapped
// ObliviousDoHConfigs object has the expected header so clients can
// parse it.
func TestRFC9230_ConfigsObjectShape(t *testing.T) {
	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}
	cfgs := target.ConfigsObject()
	// Outer: u16 total_length || inner (version u16 || length u16 || contents).
	if len(cfgs) < 6 {
		t.Fatalf("ConfigsObject too short: %d bytes", len(cfgs))
	}
	innerLen := uint16(cfgs[0])<<8 | uint16(cfgs[1])
	if int(innerLen)+2 != len(cfgs) {
		t.Errorf("outer length %d, want %d", innerLen, len(cfgs)-2)
	}
	version := uint16(cfgs[2])<<8 | uint16(cfgs[3])
	if version != 0x0001 {
		t.Errorf("version = %#x, want 0x0001", version)
	}
}

func TestRFC9230_ConfigsObjectRejectsOversizedLengths(t *testing.T) {
	kp := &odohKeyPair{configBytes: make([]byte, 65536)}
	if _, err := kp.configsObject(); err == nil {
		t.Fatal("expected oversized config contents to fail")
	}

	target := &ObliviousTarget{keyPair: kp}
	if cfgs := target.ConfigsObject(); cfgs != nil {
		t.Fatalf("ConfigsObject with oversized config returned %d bytes, want nil", len(cfgs))
	}
}

// TestRFC9230_ClientProxyTargetRoundTrip is the full pipeline test:
// real Client → real Proxy → real Target → DNS handler, decrypted on
// return. Proves all four moving parts wire together under RFC 9230.
func TestRFC9230_ClientProxyTargetRoundTrip(t *testing.T) {
	// Build a DNS response the target's handler will emit.
	respMsg, err := protocol.NewQuery(0xcafe, "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("NewQuery: %v", err)
	}
	respMsg.Header.Flags.QR = true
	respMsg.Header.Flags.AA = true
	rr, _ := protocol.NewResourceRecord(
		"example.com.", protocol.TypeA, protocol.ClassIN, 60,
		&protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
	)
	respMsg.Answers = append(respMsg.Answers, rr)
	respMsg.Header.ANCount = 1

	target, err := NewObliviousTarget(
		NewODoHConfig("target.example.com", "proxy.example.com"),
		&rfc9230MockHandler{response: respMsg},
	)
	if err != nil {
		t.Fatalf("NewObliviousTarget: %v", err)
	}
	targetServer := httptestNewServer(t, target)
	defer targetServer.Close()

	// Proxy points at the target.
	proxyCfg := NewODoHConfig("target.example.com", "proxy.example.com")
	proxyCfg.TargetURL = targetServer.URL
	proxy, err := NewObliviousProxy(proxyCfg)
	if err != nil {
		t.Fatalf("NewObliviousProxy: %v", err)
	}
	proxyServer := httptestNewServer(t, proxy)
	defer proxyServer.Close()

	// Client points at the proxy and trusts the target's config.
	clientCfg := NewODoHConfig("target.example.com", "proxy.example.com")
	clientCfg.ProxyURL = proxyServer.URL
	clientCfg.TargetPublicKey = target.ConfigContents()
	client, err := NewObliviousClient(clientCfg)
	if err != nil {
		t.Fatalf("NewObliviousClient: %v", err)
	}

	queryMsg, _ := protocol.NewQuery(0xcafe, "example.com.", protocol.TypeA)
	queryWire := make([]byte, queryMsg.WireLength())
	if _, err := queryMsg.Pack(queryWire); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	respWire, err := client.Query(queryWire)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	got, err := protocol.UnpackMessage(respWire)
	if err != nil {
		t.Fatalf("UnpackMessage: %v", err)
	}
	if got.Header.ID != 0xcafe {
		t.Errorf("response ID = %#x, want 0xcafe", got.Header.ID)
	}
	if len(got.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.Answers))
	}
	if a, ok := got.Answers[0].Data.(*protocol.RDataA); !ok || a.Address != [4]byte{1, 2, 3, 4} {
		t.Errorf("answer A = %+v, want 1.2.3.4", got.Answers[0].Data)
	}
}
