package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Each failed UPDATE prerequisite is answered with its own RCODE (RFC 2136
// §2.4): NXDOMAIN, YXDOMAIN, YXRRSET or NXRRSET — not NXRRSET for all (F766).
func TestUpdatePrerequisiteRcodes(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"}}
	cases := []struct {
		name string
		pre  UpdatePrerequisite
		want uint8
	}{
		{"name in use, absent", UpdatePrerequisite{Name: "nope.example.com.", Type: protocol.TypeANY, Class: protocol.ClassANY, Condition: PrecondNameInUse}, protocol.RcodeNameError},
		{"name not in use, present", UpdatePrerequisite{Name: "www.example.com.", Type: protocol.TypeANY, Class: protocol.ClassNONE, Condition: PrecondNameNotInUse}, protocol.RcodeYXDomain},
		{"rrset must not exist, present", UpdatePrerequisite{Name: "www.example.com.", Type: protocol.TypeA, Class: protocol.ClassNONE, Condition: PrecondNotExists}, protocol.RcodeYXRRSet},
		{"rrset must exist, absent", UpdatePrerequisite{Name: "www.example.com.", Type: protocol.TypeAAAA, Class: protocol.ClassANY, Condition: PrecondExists}, protocol.RcodeNXRRSet},
		{"rrset value mismatch", UpdatePrerequisite{Name: "www.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, Condition: PrecondExistsValue, RData: "192.0.2.9"}, protocol.RcodeNXRRSet},
	}
	for _, c := range cases {
		err := ApplyUpdate(z, &UpdateRequest{ZoneName: "example.com.", Prerequisites: []UpdatePrerequisite{c.pre}})
		if err == nil {
			t.Errorf("%s: prerequisite passed", c.name)
			continue
		}
		if got := updateErrorRcode(err); got != c.want {
			t.Errorf("%s: RCODE %d, want %d", c.name, got, c.want)
		}
	}
}
