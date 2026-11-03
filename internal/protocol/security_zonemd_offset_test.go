package protocol

import "testing"

func TestSecurityAndZONEMDRDataRejectInvalidOffsets(t *testing.T) {
	buf := make([]byte, 32)
	unpackers := map[string]func(int, uint16) (int, error){
		"CAA":        func(o int, l uint16) (int, error) { return (&RDataCAA{}).Unpack(buf, o, l) },
		"IPSECKEY":   func(o int, l uint16) (int, error) { return (&RDataIPSECKEY{}).Unpack(buf, o, l) },
		"HIP":        func(o int, l uint16) (int, error) { return (&RDataHIP{}).Unpack(buf, o, l) },
		"CERT":       func(o int, l uint16) (int, error) { return (&RDataCERT{}).Unpack(buf, o, l) },
		"OPENPGPKEY": func(o int, l uint16) (int, error) { return (&RDataOPENPGPKEY{}).Unpack(buf, o, l) },
		"DHCID":      func(o int, l uint16) (int, error) { return (&RDataDHCID{}).Unpack(buf, o, l) },
		"SSHFP":      func(o int, l uint16) (int, error) { return (&RDataSSHFP{}).Unpack(buf, o, l) },
		"TLSA":       func(o int, l uint16) (int, error) { return (&RDataTLSA{}).Unpack(buf, o, l) },
		"ZONEMD":     func(o int, l uint16) (int, error) { return (&RDataZONEMD{}).Unpack(buf, o, l) },
	}
	for name, unpack := range unpackers {
		t.Run(name, func(t *testing.T) {
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
	for _, offset := range []int{-1, len(buf) + 1} {
		if n, err := (&RDataZONEMD{}).Pack(buf, offset); err == nil || n != 0 {
			t.Fatalf("ZONEMD Pack(%d) = (%d, %v), want (0, error)", offset, n, err)
		}
	}
}
