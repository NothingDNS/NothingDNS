package transfer

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// r32Notify builds a NOTIFY for example.com. carrying serial in the Answer
// (sec "an") or Authority (sec "ns") section, or no SOA at all (sec "").
func r32Notify(sec string, serial uint32) *protocol.Message {
	origin, _ := protocol.ParseName("example.com.")
	m := &protocol.Message{
		Header:    protocol.Header{ID: 77, QDCount: 1, Flags: protocol.Flags{Opcode: protocol.OpcodeNotify}},
		Questions: []*protocol.Question{{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
	}
	soa := []*protocol.ResourceRecord{{Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 60,
		Data: &protocol.RDataSOA{MName: origin, RName: origin, Serial: serial}}}
	switch sec {
	case "an":
		m.Header.ANCount, m.Answers = 1, soa
	case "ns":
		m.Header.NSCount, m.Authorities = 1, soa
	}
	return m
}

func r32Handle(t *testing.T, local uint32, req *protocol.Message, check SerialChecker) (*NOTIFYRequest, bool) {
	t.Helper()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: local}
	h := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	if err := h.AddNotifyAllowed("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if check != nil {
		h.SetSerialChecker(check)
	}
	resp, err := h.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil || resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("HandleNOTIFY: resp=%v err=%v", resp, err)
	}
	select {
	case ev := <-h.GetNotifyChannel():
		return ev, true
	default:
		return nil, false
	}
}

// TestNOTIFYSlaveHandler_SerialZeroIsASerial pins F207: SOA serial 0 is a
// valid RFC 1982 serial (e.g. after wraparound) and used to be treated as
// "no serial", replaced by the local serial, and the newer zone dropped.
func TestNOTIFYSlaveHandler_SerialZeroIsASerial(t *testing.T) {
	for _, sec := range []string{"an", "ns"} {
		ev, ok := r32Handle(t, 4294967000, r32Notify(sec, 0), nil)
		if !ok || ev.Serial != 0 || ev.SerialUnknown {
			t.Fatalf("%s: serial 0 after 4294967000: event=%v %+v, want serial 0", sec, ok, ev)
		}
	}
	var got []uint32
	if _, ok := r32Handle(t, 4294967000, r32Notify("an", 0), func(_ string, s uint32) bool {
		got = append(got, s)
		return true
	}); !ok || len(got) != 1 || got[0] != 0 {
		t.Fatalf("serial checker saw %v, want [0]", got)
	}
	// Control: serial 0 equal to the local serial is not newer.
	if ev, ok := r32Handle(t, 0, r32Notify("an", 0), nil); ok {
		t.Fatalf("equal serial 0 produced an event: %+v", ev)
	}
}

// TestNOTIFY_WithoutSOAHintTriggersTransfer pins F208: the NOTIFY SOA is only
// a hint (RFC 1996 §3.7/§3.11). Without it the handler compared the local
// serial with itself and dropped the NOTIFY, so no transfer ever ran.
func TestNOTIFY_WithoutSOAHintTriggersTransfer(t *testing.T) {
	ev, ok := r32Handle(t, 5, r32Notify("", 0), func(string, uint32) bool { return false })
	if !ok || !ev.SerialUnknown {
		t.Fatalf("hint-less NOTIFY: event=%v %+v, want SerialUnknown event", ok, ev)
	}

	run := func(req *NOTIFYRequest) int {
		m := newR31Master(t)
		stop := m.serve(r31ServeAXFR(6))
		sm := NewSlaveManager(nil)
		sz, err := NewSlaveZone(r31Config(m.ln.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		sz.LastSerial = 5
		sm.slaveZones["example.com."] = sz
		sm.clients["example.com."] = NewIXFRClient(sz.Config.Masters[0])
		sm.handleNotify(req)
		sm.Stop() // barrier: a started transfer has finished
		return stop()
	}
	if n := run(&NOTIFYRequest{ZoneName: "example.com.", Serial: 5, SerialUnknown: true}); n != 1 {
		t.Fatalf("SerialUnknown NOTIFY ran %d transfers, want 1", n)
	}
	// Control: a known, not-newer serial is still skipped.
	if n := run(&NOTIFYRequest{ZoneName: "example.com.", Serial: 5}); n != 0 {
		t.Fatalf("up-to-date NOTIFY ran %d transfers, want 0", n)
	}
}

// r32Slave is a loopback fake slave. For the i-th received datagram (from 1)
// reply(i, req) returns the replies to send. It reports the datagram count
// once closed.
func r32Slave(t *testing.T, reply func(i int, req *protocol.Message) [][]byte) (*net.UDPConn, <-chan int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan int, 1)
	go func() {
		n := 0
		buf := make([]byte, 65535)
		for {
			k, from, err := c.ReadFromUDP(buf)
			if err != nil {
				seen <- n
				return
			}
			n++
			req, err := protocol.UnpackMessage(buf[:k])
			if err != nil {
				continue
			}
			for _, b := range reply(n, req) {
				_, _ = c.WriteToUDP(b, from)
			}
		}
	}()
	return c, seen
}

func r32Reply(req *protocol.Message, id uint16, rcode uint8) []byte {
	f := protocol.NewResponseFlags(rcode)
	f.AA, f.Opcode = true, protocol.OpcodeNotify
	resp := &protocol.Message{Header: protocol.Header{ID: id, Flags: f}, Questions: req.Questions}
	out := make([]byte, 512)
	m, err := resp.Pack(out)
	if err != nil {
		panic(err)
	}
	return out[:m]
}

func r32Send(t *testing.T, retransmits int, reply func(i int, req *protocol.Message) [][]byte) (int, error) {
	t.Helper()
	c, seen := r32Slave(t, reply)
	s := NewNOTIFYSender(":0")
	s.SetTimeout(150 * time.Millisecond)
	s.retransmits = retransmits
	err := s.SendNOTIFY("example.com.", 7, c.LocalAddr().String())
	c.Close()
	return <-seen, err
}

// TestNOTIFYSender_Retransmits pins F209: RFC 1996 §3.6 requires an
// unanswered UDP NOTIFY to be retransmitted; it used to be sent once. Loss is
// gated by datagram count, not timing.
func TestNOTIFYSender_Retransmits(t *testing.T) {
	if NewNOTIFYSender(":0").retransmits != notifyDefaultRetransmits {
		t.Fatal("default retransmits not set")
	}
	answerFrom := func(first int) func(int, *protocol.Message) [][]byte {
		return func(i int, req *protocol.Message) [][]byte {
			if i < first {
				return nil
			}
			return [][]byte{r32Reply(req, req.Header.ID, protocol.RcodeSuccess)}
		}
	}
	if n, err := r32Send(t, 2, answerFrom(3)); err != nil || n != 3 {
		t.Fatalf("two lost datagrams: sent=%d err=%v, want 3 / nil", n, err)
	}
	if n, err := r32Send(t, 2, answerFrom(99)); err == nil || n != 3 {
		t.Fatalf("never answered: sent=%d err=%v, want 3 / error", n, err)
	}
	if n, err := r32Send(t, 0, answerFrom(99)); err == nil || n != 1 {
		t.Fatalf("retransmits=0: sent=%d err=%v, want 1 / error", n, err)
	}
	if n, err := r32Send(t, 2, answerFrom(1)); err != nil || n != 1 {
		t.Fatalf("answered at once: sent=%d err=%v, want 1 / nil", n, err)
	}
}

// TestNOTIFYSender_DiscardsStrayReplies pins F210: a datagram that is not the
// reply to this NOTIFY (wrong ID or unparseable) used to fail it, so a stale
// or spoofed REFUSED aborted the NOTIFY. It must be discarded.
func TestNOTIFYSender_DiscardsStrayReplies(t *testing.T) {
	n, err := r32Send(t, 0, func(_ int, req *protocol.Message) [][]byte {
		return [][]byte{
			r32Reply(req, req.Header.ID^0x5a5a, protocol.RcodeRefused),
			{0xde, 0xad},
			r32Reply(req, req.Header.ID, protocol.RcodeSuccess),
		}
	})
	if err != nil || n != 1 {
		t.Fatalf("stray replies before the genuine one: sent=%d err=%v, want 1 / nil", n, err)
	}
	if _, err := r32Send(t, 0, func(_ int, req *protocol.Message) [][]byte {
		return [][]byte{r32Reply(req, req.Header.ID+1, protocol.RcodeSuccess)}
	}); err == nil || !strings.Contains(err.Error(), "ID mismatch") {
		t.Fatalf("only a wrong-ID reply: err=%v, want timeout mentioning ID mismatch", err)
	}
	// Control: a matching REFUSED still fails the NOTIFY.
	if _, err := r32Send(t, 2, func(_ int, req *protocol.Message) [][]byte {
		return [][]byte{r32Reply(req, req.Header.ID, protocol.RcodeRefused)}
	}); err == nil || !strings.Contains(err.Error(), "rcode") {
		t.Fatalf("matching REFUSED: err=%v, want rcode error", err)
	}
}
