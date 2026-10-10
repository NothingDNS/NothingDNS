package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ddnsDrainQueueUpdate applies one signed UPDATE through ddns, which queues
// its post-apply side effects for the handler's event consumer.
func ddnsDrainQueueUpdate(t *testing.T, ddns *transfer.DynamicDNSHandler, key *transfer.TSIGKey, host string, id uint16) {
	t.Helper()
	msg := &protocol.Message{
		Header:      protocol.Header{ID: id, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions:   []*protocol.Question{{Name: ddnsPolName(t, "example.com."), QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{ddnsPolAdd(t, host, "192.0.2.65")},
	}
	tsigRR, err := transfer.SignMessage(msg, key, 300)
	if err != nil {
		t.Fatal(err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := ddns.HandleUpdateRequest(wire, net.ParseIP("127.0.0.1"), nil)
	if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("UPDATE %s not accepted: resp=%v err=%v", host, resp, err)
	}
}

// F665: shutdown (and a reload replacing the DDNS handler) closed the handler
// without waiting for its event consumer, so an acknowledged UPDATE's journal
// entry, KV record and zone file could still be pending — or never written —
// when the server returned.
func TestDDNSHandlerCloseWaitsForSideEffects(t *testing.T) {
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	h.zones["example.com."] = xfrTSIGZone(0)
	key := &transfer.TSIGKey{Name: "upd-key.", Algorithm: transfer.HmacSHA256, Secret: ddnsPolSecret}
	ddns := transfer.NewDynamicDNSHandler(h.zones)
	ddns.SetZonesMu(&h.zonesMu)
	ks := transfer.NewKeyStore()
	ks.AddKey(key)
	ddns.SetKeyStore(ks)
	ddns.AllowKeyUpdate("upd-key.", "example.com.")
	h.transfer.DDNSHandler = ddns
	for i, host := range []string{"a.example.com.", "b.example.com."} {
		ddnsDrainQueueUpdate(t, ddns, key, host, uint16(0x6650+i))
	}
	var persisted atomic.Int32
	h.zoneManager.SetMutationHook(func(string, bool) { persisted.Add(1) })

	// The consumer's first step takes zonesMu: holding it keeps both side
	// effects pending while Close runs.
	h.zonesMu.Lock()
	h.ensureUpdateConsumer(ddns)
	closed := make(chan struct{})
	go func() { ddns.Close(); close(closed) }()
	select {
	case <-closed:
		h.zonesMu.Unlock()
		t.Fatal("Close returned while the queued side effects were pending")
	case <-time.After(200 * time.Millisecond):
	}
	h.zonesMu.Unlock()
	<-closed
	if got := persisted.Load(); got != 2 {
		t.Fatalf("Close returned after %d of 2 side effects", got)
	}
}
