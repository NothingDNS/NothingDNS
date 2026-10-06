package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// buildServiceTypeQuery packs a DNS query message for name/qtype with the
// production wire encoder, so the tests below feed handleQuery exactly the
// bytes a link-local DNS-SD peer would put on the wire.
func buildServiceTypeQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()

	q, err := protocol.NewQuestion(name, qtype, protocol.ClassIN)
	if err != nil {
		t.Fatalf("NewQuestion(%q): %v", name, err)
	}
	msg := protocol.NewMessage(protocol.Header{
		ID:      0x1234,
		Flags:   protocol.NewQueryFlags(),
		QDCount: 1,
	})
	msg.Questions = append(msg.Questions, q)

	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack(%q): %v", name, err)
	}
	return buf[:n]
}

// queryHarness wires the responder's real send path to a loopback socket pair.
// The responder answers queries back to the query's source address, so the
// source is the receiving socket and any reply is observed on it.
type queryHarness struct {
	responder *Responder
	conn      *net.UDPConn
	sink      *net.UDPConn
}

func newQueryHarness(t *testing.T) *queryHarness {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(responder conn): %v", err)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("ListenUDP(sink): %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = sink.Close()
	})

	r := NewResponder(DefaultConfig(), nil)
	r.conn = conn

	return &queryHarness{responder: r, conn: conn, sink: sink}
}

// sourceAddr is the address the responder will reply to.
func (h *queryHarness) sourceAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	addr, ok := h.sink.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("sink LocalAddr is %T, want *net.UDPAddr", h.sink.LocalAddr())
	}
	return addr
}

// replies sends one wire query and reports whether the responder answered.
func (h *queryHarness) replies(t *testing.T, name string, qtype uint16) bool {
	t.Helper()

	src := h.sourceAddr(t)
	h.responder.handleQuery(buildServiceTypeQuery(t, name, qtype), src)

	if err := h.sink.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65536)
	n, _, err := h.sink.ReadFromUDP(buf)
	if err != nil {
		return false
	}
	return n > 0
}

func (h *queryHarness) registerService(svc *Service) {
	h.responder.servicesMu.Lock()
	h.responder.services[svc.FullServiceName()] = svc
	h.responder.servicesMu.Unlock()
}

func testWebService() *Service {
	return &Service{
		InstanceName: "WebServer",
		ServiceType:  "_http._tcp",
		Domain:       "local",
		HostName:     "web.local",
		Port:         80,
		TTL:          ServiceTTL,
	}
}

// TestHandleQuery_ServiceTypeEnumeration pins DNS-SD RFC 6763 §9.1: browsing a
// service type puts ServiceTypeName() ("_http._tcp.local.") on the wire, and
// the responder must answer it. Matching the bare ServiceType ("_http._tcp")
// left the standard type browse unresolvable.
func TestHandleQuery_ServiceTypeEnumeration(t *testing.T) {
	h := newQueryHarness(t)
	svc := testWebService()
	h.registerService(svc)

	queryName := svc.ServiceTypeName()
	if !h.replies(t, queryName, protocol.TypePTR) {
		t.Fatalf("no answer to service-type enumeration query %q for registered service %q "+
			"(ServiceType %q); DNS-SD type browse is unresolvable",
			queryName, svc.FullServiceName(), svc.ServiceType)
	}
}

// TestHandleQuery_ServiceTypeEnumerationCaseInsensitive is the boundary check:
// DNS names are case-insensitive (RFC 1035 §2.3.3), so a mixed-case
// enumeration name must also be answered.
func TestHandleQuery_ServiceTypeEnumerationCaseInsensitive(t *testing.T) {
	h := newQueryHarness(t)
	h.registerService(testWebService())

	if !h.replies(t, "_HTTP._TCP.local.", protocol.TypePTR) {
		t.Fatal("no answer to mixed-case service-type query \"_HTTP._TCP.local.\"")
	}
}

// TestHandleQuery_ServiceTypeEnumerationNonDefaultDomain checks the match uses
// the service's own domain rather than a hard-coded "local", since
// ServiceTypeName() is what builds the enumeration name.
func TestHandleQuery_ServiceTypeEnumerationNonDefaultDomain(t *testing.T) {
	h := newQueryHarness(t)
	svc := &Service{
		InstanceName: "Printer",
		ServiceType:  "_ipp._tcp",
		Domain:       "lan",
		HostName:     "printer.lan",
		Port:         631,
		TTL:          ServiceTTL,
	}
	h.registerService(svc)

	if !h.replies(t, svc.ServiceTypeName(), protocol.TypePTR) {
		t.Fatalf("no answer to enumeration query %q for service in domain %q",
			svc.ServiceTypeName(), svc.Domain)
	}
}

// TestHandleQuery_FullInstanceName is the control: a query for the full service
// instance name must still be answered.
func TestHandleQuery_FullInstanceName(t *testing.T) {
	h := newQueryHarness(t)
	svc := testWebService()
	h.registerService(svc)

	if !h.replies(t, svc.FullServiceName(), protocol.TypeSRV) {
		t.Fatalf("no answer to full instance query %q", svc.FullServiceName())
	}
}

// TestHandleQuery_Hostname is a control on a different subsystem (A-record
// answering), confirming matching works in general.
func TestHandleQuery_Hostname(t *testing.T) {
	h := newQueryHarness(t)

	h.responder.hostnamesMu.Lock()
	h.responder.hostnames["myprinter.local."] = net.ParseIP("10.0.0.7")
	h.responder.hostnamesMu.Unlock()

	if !h.replies(t, "myprinter.local.", protocol.TypeA) {
		t.Fatal("no answer to hostname query \"myprinter.local.\"")
	}
}

// TestHandleQuery_UnrelatedServiceTypeNotAnswered is the negative branch: a
// service type the responder does not host must not be answered, so the fix
// did not turn matching into a catch-all.
func TestHandleQuery_UnrelatedServiceTypeNotAnswered(t *testing.T) {
	h := newQueryHarness(t)
	h.registerService(testWebService())

	if h.replies(t, "_ssh._tcp.local.", protocol.TypePTR) {
		t.Fatal("responder answered enumeration query \"_ssh._tcp.local.\" but hosts no _ssh._tcp service")
	}
}
