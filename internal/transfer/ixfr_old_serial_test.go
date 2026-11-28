package transfer

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func parseIXFRSerials(t *testing.T, serials ...uint32) *IXFRResponse {
	t.Helper()
	name, err := protocol.ParseName("example.")
	if err != nil {
		t.Fatal(err)
	}
	records := make([]*protocol.ResourceRecord, 0, 2*len(serials))
	for i, serial := range serials {
		records = append(records, &protocol.ResourceRecord{
			Name: name, Type: protocol.TypeSOA, Class: protocol.ClassIN,
			Data: &protocol.RDataSOA{Serial: serial, MName: name, RName: name},
		})
		// Between SOAs for deleted and added SOA versions, include an ordinary RR.
		if len(serials) == 4 && (i == 1 || i == 2) {
			records = append(records, &protocol.ResourceRecord{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, byte(i)}}})
		}
	}
	resp, err := NewIXFRClient("").ParseIXFRResponse(records)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestParseIXFRResponseUsesFirstDeltaSerial_F895(t *testing.T) {
	if r := parseIXFRSerials(t, 10, 9, 10, 10); r.OldSerial != 9 || r.NewSerial != 10 || r.IsAXFR {
		t.Fatalf("REGRESSION: response = %+v, want incremental 9 to 10", r)
	}
}
