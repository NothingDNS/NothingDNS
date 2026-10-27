package nothingdns

import (
	"encoding/json"
	"testing"
)

// A zone serial is an unsigned 32-bit value (RFC 1982), so it can exceed
// 2^31-1; with an int field that failed to decode on 32-bit platforms (F734).
func TestSerialAboveInt32Decodes(t *testing.T) {
	const serial = 3000000000
	var soa SOA
	if err := json.Unmarshal([]byte(`{"serial":3000000000}`), &soa); err != nil || soa.Serial != serial {
		t.Fatalf("SOA serial = %d, %v", soa.Serial, err)
	}
	var detail ZoneDetail
	if err := json.Unmarshal([]byte(`{"serial":3000000000}`), &detail); err != nil || detail.Serial != serial {
		t.Fatalf("ZoneDetail serial = %d, %v", detail.Serial, err)
	}
}
