package transfer

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func closeInflightHandler(t *testing.T) (*DynamicDNSHandler, *sync.RWMutex, *TSIGKey) {
	t.Helper()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 300, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["example.com."] = []zone.Record{{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."}}
	mu := &sync.RWMutex{}
	key := &TSIGKey{Name: "upd-key.", Algorithm: HmacSHA256, Secret: []byte("F666-ddns-update-key-0123456789!")}
	h := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
	h.SetZonesMu(mu)
	ks := NewKeyStore()
	ks.AddKey(key)
	h.SetKeyStore(ks)
	h.AllowKeyUpdate("upd-key.", "example.com.")
	return h, mu, key
}

// closeInflightUpdate runs one signed UPDATE adding host in a goroutine and
// reports its RCODE, or the panic it raised.
func closeInflightUpdate(t *testing.T, h *DynamicDNSHandler, key *TSIGKey, host string) <-chan string {
	t.Helper()
	zn, _ := protocol.ParseName("example.com.")
	hn, _ := protocol.ParseName(host)
	msg := &protocol.Message{
		Header:      protocol.Header{ID: 0x6660, Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate}},
		Questions:   []*protocol.Question{{Name: zn, QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Authorities: []*protocol.ResourceRecord{{Name: hn, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 66}}}},
	}
	tsigRR, err := SignMessage(msg, key, 300)
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
	out := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				out <- fmt.Sprintf("panic: %v", r)
			}
		}()
		resp, _, err := h.HandleUpdateRequest(wire, net.ParseIP("127.0.0.1"), nil)
		if err != nil {
			out <- "error: " + err.Error()
			return
		}
		out <- protocol.RcodeString(int(resp.Header.Flags.RCODE))
	}()
	return out
}

// F666: an UPDATE still running when the handler was closed (shutdown) sent
// its event on the closed channel and panicked; one arriving after Close was
// applied although its side effects could never run.
func TestDDNSUpdateAcrossClose(t *testing.T) {
	t.Run("in flight", func(t *testing.T) {
		h, mu, key := closeInflightHandler(t)
		mu.Lock() // the UPDATE waits at its zone lookup
		res := closeInflightUpdate(t, h, key, "late.example.com.")
		closed := make(chan struct{})
		go func() { h.Close(); close(closed) }()
		mu.Unlock()
		if got := <-res; got != "NOERROR" && got != "SERVFAIL" {
			t.Fatalf("in-flight UPDATE across Close: %s", got)
		}
		<-closed
	})
	t.Run("after close", func(t *testing.T) {
		h, _, key := closeInflightHandler(t)
		h.Close()
		if got := <-closeInflightUpdate(t, h, key, "after.example.com."); got != "SERVFAIL" {
			t.Fatalf("UPDATE after Close: %s, want SERVFAIL", got)
		}
		z := h.zones["example.com."]
		z.RLock()
		_, applied := z.Records["after.example.com."]
		serial := z.SOA.Serial
		z.RUnlock()
		if applied || serial != 2 {
			t.Fatalf("UPDATE applied after Close: applied=%v serial=%d", applied, serial)
		}
	})
}

// F667: with the event buffer full, an accepted UPDATE's event was dropped,
// losing its journal entry and persistence. A registered consumer now gets
// backpressure: every acknowledged update's event arrives.
func TestDDNSUpdateEventsNotDroppedWhenBufferFull(t *testing.T) {
	const updates = 101 // one more than the buffer
	h, _, key := closeInflightHandler(t)
	events, consumed := h.UpdateEvents()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < updates; i++ {
			if rc := <-closeInflightUpdate(t, h, key, fmt.Sprintf("b%d.example.com.", i)); rc != "NOERROR" {
				t.Errorf("update %d: %s", i, rc)
			}
		}
	}()
	// Start reading only once the burst finished or is parked on the full
	// buffer (stack polling, no sleeps).
	buf := make([]byte, 1<<20)
	for parked := false; !parked; runtime.Gosched() {
		select {
		case <-done:
			parked = true
			continue
		default:
		}
		n := runtime.Stack(buf, true)
		parked = strings.Contains(string(buf[:n]), "chan send")
	}
	got := 0
	for got < updates {
		select {
		case <-events:
			got++
		case <-done:
			for len(events) > 0 {
				<-events
				got++
			}
			if got != updates {
				t.Fatalf("%d events for %d acknowledged updates", got, updates)
			}
		}
	}
	<-done
	consumed()
	h.Close()
}
