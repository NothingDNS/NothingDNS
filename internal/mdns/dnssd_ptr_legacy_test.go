package mdns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rgHarness wires the responder's real send path to a loopback sink. The
// configured "multicast" group is the sink itself, so announcements and
// goodbyes are observable without joining a real multicast group. When
// sinkIsMDNSPort is false the sink's ephemeral port differs from the
// configured mDNS port, so queries from it are legacy unicast (RFC 6762 §6.7).
func rgHarness(t *testing.T, sinkIsMDNSPort bool) (*Responder, *net.UDPConn) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("ListenUDP(sink): %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); _ = sink.Close() })

	cfg := DefaultConfig()
	cfg.MulticastIP = "127.0.0.1"
	cfg.Port = DefaultPort
	if sinkIsMDNSPort {
		cfg.Port = sink.LocalAddr().(*net.UDPAddr).Port
	}
	r := NewResponder(cfg, nil)
	r.conn = conn
	return r, sink
}

func rgDrain(t *testing.T, sink *net.UDPConn) []*protocol.Message {
	t.Helper()
	var out []*protocol.Message
	buf := make([]byte, 65536)
	for {
		if err := sink.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, err := sink.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		m, err := protocol.UnpackMessage(append([]byte(nil), buf[:n]...))
		if err != nil {
			t.Fatalf("unpack reply: %v", err)
		}
		out = append(out, m)
	}
}

func rgPTRs(msgs []*protocol.Message) []*protocol.ResourceRecord {
	var out []*protocol.ResourceRecord
	for _, m := range msgs {
		for _, rr := range m.Answers {
			if rr.Type == protocol.TypePTR {
				out = append(out, rr)
			}
		}
	}
	return out
}

// TestDNSSDBrowseAnswersWithPTR (F97): a DNS-SD browse (PTR query for the
// service type, RFC 6763 §4.1) must be answered with the type -> instance PTR;
// SRV/TXT alone never tell the browser the instance name. Announcements carry
// the PTR as well.
func TestDNSSDBrowseAnswersWithPTR(t *testing.T) {
	r, sink := rgHarness(t, true)
	svc := testWebService()
	r.services[svc.FullServiceName()] = svc
	src := sink.LocalAddr().(*net.UDPAddr)

	r.handleQuery(buildServiceTypeQuery(t, svc.ServiceTypeName(), protocol.TypePTR), src)
	ptrs := rgPTRs(rgDrain(t, sink))
	if len(ptrs) != 1 {
		t.Fatalf("browse answered with %d PTR records, want 1", len(ptrs))
	}
	if got := ptrs[0].Name.String(); got != svc.ServiceTypeName() {
		t.Fatalf("PTR owner = %q, want %q", got, svc.ServiceTypeName())
	}
	// protocol.PackName case-folds uncompressed RDATA names, so compare
	// case-insensitively (DNS names are case-insensitive, RFC 1035 §2.3.3).
	if got := ptrs[0].Data.(*protocol.RDataPTR).PtrDName.String(); !strings.EqualFold(got, svc.FullServiceName()) {
		t.Fatalf("PTR target = %q, want %q", got, svc.FullServiceName())
	}

	r.announceService(svc)
	if n := len(rgPTRs(rgDrain(t, sink))); n != 1 {
		t.Fatalf("announcement carried %d PTR records, want 1", n)
	}
}

// TestLegacyUnicastReplyEchoesIDAndQuestion (F98): a query from a source port
// other than the mDNS port is a legacy unicast query; RFC 6762 §6.7 requires
// the reply to echo its ID and repeat the Question, or the stub resolver drops
// the reply as unmatched. Queries from the mDNS port get no Question section.
func TestLegacyUnicastReplyEchoesIDAndQuestion(t *testing.T) {
	r, sink := rgHarness(t, false)
	r.hostnames["myprinter.local."] = net.ParseIP("10.0.0.7")
	q := buildServiceTypeQuery(t, "myprinter.local.", protocol.TypeA) // ID 0x1234

	r.handleQuery(q, sink.LocalAddr().(*net.UDPAddr))
	msgs := rgDrain(t, sink)
	if len(msgs) != 1 {
		t.Fatalf("got %d replies, want 1", len(msgs))
	}
	if msgs[0].Header.ID != 0x1234 {
		t.Fatalf("legacy reply ID = %#x, want 0x1234", msgs[0].Header.ID)
	}
	if len(msgs[0].Questions) != 1 || msgs[0].Questions[0].Name.String() != "myprinter.local." {
		t.Fatalf("legacy reply questions = %v, want [myprinter.local.]", msgs[0].Questions)
	}

	r2, sink2 := rgHarness(t, true)
	r2.hostnames["myprinter.local."] = net.ParseIP("10.0.0.7")
	r2.handleQuery(q, sink2.LocalAddr().(*net.UDPAddr))
	msgs = rgDrain(t, sink2)
	if len(msgs) != 1 || len(msgs[0].Questions) != 0 || len(msgs[0].Answers) != 1 {
		t.Fatalf("mDNS-port reply: %d msgs, want 1 with no Question and 1 answer", len(msgs))
	}
}

// TestUnregisterServiceGoodbyeIncludesPTR (F99): the goodbye for a withdrawn
// service must include the TTL=0 PTR (RFC 6762 §10.1), or DNS-SD browsers keep
// listing the instance until the PTR's 4500 s TTL lapses.
func TestUnregisterServiceGoodbyeIncludesPTR(t *testing.T) {
	r, sink := rgHarness(t, true)
	svc := testWebService()
	r.services[svc.FullServiceName()] = svc

	r.UnregisterService(svc.FullServiceName())
	msgs := rgDrain(t, sink)
	ptrs := rgPTRs(msgs)
	if len(msgs) != 1 || len(ptrs) != 1 {
		t.Fatalf("goodbye: %d msgs / %d PTR records, want 1 / 1", len(msgs), len(ptrs))
	}
	if ptrs[0].TTL != 0 || ptrs[0].Name.String() != svc.ServiceTypeName() {
		t.Fatalf("goodbye PTR = %v, want %s TTL 0", ptrs[0], svc.ServiceTypeName())
	}
	if int(msgs[0].Header.ANCount) != len(msgs[0].Answers) {
		t.Fatalf("ANCount %d != %d answers", msgs[0].Header.ANCount, len(msgs[0].Answers))
	}
}
