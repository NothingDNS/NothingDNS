package transfer

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestIXFRServerRejectsMissingClientSOA(t *testing.T) {
	zones := map[string]*zone.Zone{}
	srv := NewIXFRServer(NewAXFRServer(zones, WithAllowList([]string{"127.0.0.0/8"})))
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 10}
	zones["example.com."] = z
	origin, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{Questions: []*protocol.Question{{Name: origin, QType: protocol.TypeIXFR, QClass: protocol.ClassIN}}}

	if _, err := srv.HandleIXFR(req, net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("IXFR request without an authority SOA was accepted")
	}
}
