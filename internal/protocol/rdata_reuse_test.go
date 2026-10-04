package protocol

import (
	"bytes"
	"testing"
)

func TestSequenceRDataUnpackReplacesPreviousValue(t *testing.T) {
	for _, typ := range []uint16{TypeTXT, TypeOPT} {
		t.Run(TypeString(typ), func(t *testing.T) {
			var reused RData
			if typ == TypeTXT {
				reused = &RDataTXT{}
			} else {
				reused = &RDataOPT{}
			}
			for _, value := range []string{"first", "first", "replacement", ""} {
				var expected RData
				if typ == TypeTXT {
					expected = &RDataTXT{Strings: []string{value}}
				} else {
					expected = &RDataOPT{Options: []EDNS0Option{{Code: 65001, Data: []byte(value)}}}
				}
				packed := make([]byte, 128)
				n, err := expected.Pack(packed, 0)
				if err != nil {
					t.Fatal(err)
				}
				switch r := reused.(type) {
				case *RDataTXT:
					_, err = r.Unpack(packed[:n], 0, uint16(n))
				case *RDataOPT:
					_, err = r.Unpack(packed[:n], 0, uint16(n))
				}
				if err != nil {
					t.Fatal(err)
				}
				actual := make([]byte, 128)
				written, err := reused.Pack(actual, 0)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual[:written], packed[:n]) {
					t.Fatalf("reuse with %q: got %x, want %x", value, actual[:written], packed[:n])
				}
			}
			var err error
			switch r := reused.(type) {
			case *RDataTXT:
				_, err = r.Unpack(nil, 0, 0)
			case *RDataOPT:
				_, err = r.Unpack(nil, 0, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if reused.Len() != 0 {
				t.Fatalf("empty decode retained %d bytes", reused.Len())
			}
		})
	}
}
