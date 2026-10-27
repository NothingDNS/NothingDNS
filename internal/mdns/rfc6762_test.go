package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 6762 behaviour of the responder and the mdns.hostname wiring (F739):
// answers go to the group with ID 0 unless the query asked for unicast (QU)
// or came from a legacy resolver, which gets its ID back and TTL <= 10.

func rfcListen(t *testing.T, addr string) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func rfcRecv(c *net.UDPConn) *protocol.Message {
	buf := make([]byte, 9000)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	m, err := protocol.UnpackMessage(buf[:n])
	if err != nil {
		return nil
	}
	return m
}

func rfcQuery(t *testing.T, id uint16, qtype uint16) []byte {
	q, _ := protocol.NewQuery(id, "nothingdns.local.", qtype)
	b := make([]byte, 512)
	n, _ := q.Pack(b)
	return b[:n]
}

func rfcResponse(c *net.UDPConn) *protocol.Message {
	for i := 0; i < 10; i++ {
		m := rfcRecv(c)
		if m == nil {
			return nil
		}
		if m.Header.Flags.QR {
			return m
		}
	}
	return nil
}

func rfcAsk(t *testing.T, r *Responder, name string, qtype, qclass uint16, from *net.UDPConn) {
	q, _ := protocol.NewQuery(0, name, qtype)
	q.Questions[0].QClass = qclass
	b := make([]byte, 512)
	n, _ := q.Pack(b)
	r.handleQuery(b[:n], from.LocalAddr().(*net.UDPAddr))
}

func TestConfiguredHostnameAnsweredPerRFC6762(t *testing.T) {
	// Wiring: RegisterConfiguredHostname adds .local and answers with the
	// outbound address.
	group := rfcListen(t, "127.0.0.1")
	defer group.Close()
	port := group.LocalAddr().(*net.UDPAddr).Port
	r := NewResponder(Config{Enabled: true, MulticastIP: "127.0.0.1", Port: port, HostName: "NothingDNS"}, nil)
	r.respLimiter = nil
	r.conn = rfcListen(t, "127.0.0.1")
	defer r.conn.Close()
	ip, err := r.RegisterConfiguredHostname()
	if err != nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("RegisterConfiguredHostname = %v, %v", ip, err)
	}
	if ann := rfcResponse(group); ann == nil || ann.Header.ID != 0 || len(ann.Answers) != 1 {
		t.Fatalf("no announcement with ID 0 on the group: %+v", ann)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	rfcAsk(t, r, "nothingdns.local.", protocol.TypeA, protocol.ClassIN, peer)
	m := rfcResponse(group)
	if m == nil || len(m.Answers) != 1 || m.Answers[0].Data.(*protocol.RDataA).Address != [4]byte{127, 0, 0, 1} {
		t.Fatalf("query for the configured name not answered on the group: %+v", m)
	}

	// QU bit: unicast reply to the querier, not the group.
	rfcAsk(t, r, "nothingdns.local.", protocol.TypeA, protocol.ClassIN|0x8000, peer)
	if u := rfcResponse(peer); u == nil || len(u.Answers) != 1 {
		t.Fatal("QU query got no unicast reply")
	}
	if g := rfcRecv(group); g != nil {
		t.Fatal("QU query was also answered on the group")
	}

	// ANY is answered; an IPv6 host answers AAAA.
	rfcAsk(t, r, "nothingdns.local.", protocol.TypeANY, protocol.ClassIN, peer)
	if m := rfcResponse(group); m == nil || len(m.Answers) != 1 {
		t.Fatal("ANY query not answered")
	}
	r.hostnames["v6.local."] = net.ParseIP("2001:db8::7")
	rfcAsk(t, r, "v6.local.", protocol.TypeAAAA, protocol.ClassIN, peer)
	if m := rfcResponse(group); m == nil || len(m.Answers) != 1 || m.Answers[0].Type != protocol.TypeAAAA {
		t.Fatal("AAAA query for an IPv6 host not answered")
	}

	// No hostname configured: nothing registered.
	r2 := NewResponder(Config{Enabled: true}, nil)
	if ip, err := r2.RegisterConfiguredHostname(); ip != nil || err != nil || len(r2.hostnames) != 0 {
		t.Fatalf("empty hostname registered something: %v %v", ip, err)
	}
}

func TestLegacyReplyCapsTTLAndKeepsID(t *testing.T) {
	group := rfcListen(t, "127.0.0.1")
	defer group.Close()
	r := NewResponder(Config{Enabled: true, MulticastIP: "127.0.0.1", Port: group.LocalAddr().(*net.UDPAddr).Port}, nil)
	r.respLimiter = nil
	r.conn = rfcListen(t, "127.0.0.1")
	defer r.conn.Close()
	r.hostnames["nothingdns.local."] = net.IPv4(192, 0, 2, 7)
	legacy := rfcListen(t, "127.0.0.1")
	defer legacy.Close()

	r.handleQuery(rfcQuery(t, 0x1234, protocol.TypeA), legacy.LocalAddr().(*net.UDPAddr))
	m := rfcRecv(legacy)
	if m == nil || len(m.Answers) != 1 || m.Header.ID != 0x1234 || m.Answers[0].TTL > 10 {
		t.Fatalf("legacy reply: %+v", m)
	}
	// An AAAA question for an IPv4-only host gets no A record.
	r.handleQuery(rfcQuery(t, 0x55, protocol.TypeAAAA), legacy.LocalAddr().(*net.UDPAddr))
	if m := rfcRecv(legacy); m != nil && len(m.Answers) > 0 {
		t.Fatalf("AAAA question answered with %s", protocol.TypeString(m.Answers[0].Type))
	}
}
