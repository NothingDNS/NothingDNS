package main

// F587 (P2-H1): a transferred slave zone answers apex queries exactly like
// the same zone served from its zone file — in particular `<zone> SOA` is a
// positive answer (SOA in the answer section), not NODATA with the SOA in the
// authority section. Loopback master → AXFR → slave → ServeDNS.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func f587ParsedZone(t *testing.T, serial uint32) *zone.Zone {
	t.Helper()
	src := fmt.Sprintf(`$ORIGIN example.com.
$TTL 300
@   IN SOA ns1.example.com. admin.example.com. %d 3600 600 86400 300
@   IN NS  ns1.example.com.
@   IN A   192.0.2.1
ns1 IN A   192.0.2.53
www IN A   192.0.2.2
`, serial)
	z, err := zone.ParseFile("example.com.zone", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func f587Answer(h *integratedHandler, qtype uint16, do bool) string {
	w := newCaptureWriter("127.0.0.1", "udp")
	q, _ := protocol.NewQuery(7, "example.com.", qtype)
	if do {
		q.SetEDNS0(1232, true)
	}
	h.ServeDNS(w, q)
	if w.msg == nil {
		return "no response"
	}
	var an, ns []string
	for _, rr := range w.msg.Answers {
		an = append(an, protocol.TypeString(rr.Type)+" "+rr.Data.String())
	}
	for _, rr := range w.msg.Authorities {
		ns = append(ns, protocol.TypeString(rr.Type))
	}
	return fmt.Sprintf("rcode=%s aa=%v an=[%s] ns=[%s]", protocol.RcodeString(int(w.msg.Header.Flags.RCODE)), w.msg.Header.Flags.AA,
		strings.Join(an, "; "), strings.Join(ns, ","))
}

func TestSlaveZone_F587_ApexAnswersMatchStaticZone(t *testing.T) {
	z := f587ParsedZone(t, 2)
	static := newTestHandler()
	static.zones["example.com."] = z
	static.zoneProvider = NewMultiZoneProvider(static.zones, nil, nil, nil)

	m := newSlaveServingMaster(t, z)
	slave := newServingSlave(t, m.addr)
	awaitSlaveSerial(t, slave, 2)

	cases := []struct {
		qtype uint16
		do    bool
		want  string
	}{
		{protocol.TypeSOA, false, "rcode=NOERROR aa=true an=[SOA ns1.example.com. admin.example.com. 2 3600 600 86400 300] ns=[]"},
		{protocol.TypeSOA, true, "rcode=NOERROR aa=true an=[SOA ns1.example.com. admin.example.com. 2 3600 600 86400 300] ns=[]"},
		{protocol.TypeNS, false, "rcode=NOERROR aa=true an=[NS ns1.example.com.] ns=[]"},
		{protocol.TypeA, false, "rcode=NOERROR aa=true an=[A 192.0.2.1] ns=[]"},
		{protocol.TypeMX, false, "rcode=NOERROR aa=true an=[] ns=[SOA]"}, // NODATA stays NODATA
	}
	for _, c := range cases {
		name := fmt.Sprintf("%s do=%v", protocol.TypeString(c.qtype), c.do)
		if got := f587Answer(static, c.qtype, c.do); got != c.want {
			t.Fatalf("control (static) %s: got %q, want %q", name, got, c.want)
		}
		if got := f587Answer(slave, c.qtype, c.do); got != c.want {
			t.Fatalf("slave %s: got %q, want %q", name, got, c.want)
		}
	}

	// After a NOTIFY-triggered re-transfer the answer carries the new serial.
	m.axfr.AddZone(f587ParsedZone(t, 3))
	if rc := sendNotifyIntake(t, slave, "127.0.0.1", 3); rc != protocol.RcodeSuccess {
		t.Fatalf("NOTIFY rcode=%s", protocol.RcodeString(int(rc)))
	}
	awaitSlaveSerial(t, slave, 3)
	if got, want := f587Answer(slave, protocol.TypeSOA, false), "rcode=NOERROR aa=true an=[SOA ns1.example.com. admin.example.com. 3 3600 600 86400 300] ns=[]"; got != want {
		t.Fatalf("slave SOA after re-transfer: got %q, want %q", got, want)
	}
}
