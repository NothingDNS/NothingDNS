package protocol

import "testing"

func TestMailAndNamingRDataRejectInvalidOffsets(t *testing.T) {
	buf := make([]byte, 32)
	packers := map[string]func(int) (int, error){
		"MX":    func(o int) (int, error) { return (&RDataMX{}).Pack(buf, o) },
		"TXT":   func(o int) (int, error) { return (&RDataTXT{Strings: []string{"x"}}).Pack(buf, o) },
		"AFSDB": func(o int) (int, error) { return (&RDataAFSDB{}).Pack(buf, o) },
		"KX":    func(o int) (int, error) { return (&RDataKX{}).Pack(buf, o) },
		"NAPTR": func(o int) (int, error) { return (&RDataNAPTR{}).Pack(buf, o) },
	}
	for name, pack := range packers {
		t.Run(name+"/pack", func(t *testing.T) {
			for _, offset := range []int{-1, len(buf) + 1} {
				if n, err := pack(offset); err == nil || n != 0 {
					t.Fatalf("Pack(%d) = (%d, %v), want (0, error)", offset, n, err)
				}
			}
		})
	}
	unpackers := map[string]func(int, uint16) (int, error){
		"AFSDB": func(o int, l uint16) (int, error) { return (&RDataAFSDB{}).Unpack(buf, o, l) },
		"KX":    func(o int, l uint16) (int, error) { return (&RDataKX{}).Unpack(buf, o, l) },
		"NAPTR": func(o int, l uint16) (int, error) { return (&RDataNAPTR{}).Unpack(buf, o, l) },
	}
	for name, unpack := range unpackers {
		t.Run(name+"/unpack", func(t *testing.T) {
			for _, tc := range []struct {
				offset int
				length uint16
			}{{-1, 0}, {len(buf) + 1, 0}, {len(buf) - 1, 2}} {
				if n, err := unpack(tc.offset, tc.length); err == nil || n != 0 {
					t.Fatalf("Unpack(%d, %d) = (%d, %v), want (0, error)", tc.offset, tc.length, n, err)
				}
			}
		})
	}
}
