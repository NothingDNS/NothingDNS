package doh

import (
	"encoding/json"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestEncodeJSONExtendedRCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint8
		ext  uint8
		opt  bool
		want int
	}{
		{"nxdomain without OPT", 3, 0, false, 3},
		{"nxdomain with OPT", 3, 0, true, 3},
		{"badvers", 0, 1, true, 16},
		{"badcookie split", 7, 1, true, 23},
		{"badcookie combined", 23, 1, true, 23},
		{"maximum extended code", 15, 255, true, 4095},
		{"legacy combined code without OPT", 23, 0, false, 23},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := &protocol.Message{Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: tc.code}}}
			if tc.opt {
				msg.Additionals = []*protocol.ResourceRecord{nil, {
					Name: mustName("."), Type: protocol.TypeOPT, Class: 1232,
					TTL: protocol.BuildEDNSTTL(tc.ext, 0, false, 0), Data: &protocol.RDataOPT{},
				}}
			}
			raw, err := EncodeJSON(msg)
			if err != nil {
				t.Fatal(err)
			}
			var out JSONResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.Status != tc.want {
				t.Fatalf("Status = %d, want %d", out.Status, tc.want)
			}
			if len(out.Additional) != 0 {
				t.Fatal("OPT must remain omitted from JSON Additional")
			}
			if msg.Header.Flags.RCODE != tc.code {
				t.Fatal("EncodeJSON mutated the input response code")
			}
		})
	}
}
