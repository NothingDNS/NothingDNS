package resolver

import (
	"testing"
	"time"
)

func TestDNSSLTLVCopiesDomainSlices(t *testing.T) {
	opt := NewDNSSLOption(time.Minute, []string{"example.com"})
	tlv := opt.ToTLV()
	tlv.SearchDomains[0] = "mutated.example"
	if got := opt.SearchDomains[0]; got != "example.com" {
		t.Fatalf("ToTLV aliased source option: got %q", got)
	}

	input := opt.ToTLV()
	parsed, err := ParseDNSSLOption(input)
	if err != nil {
		t.Fatalf("ParseDNSSLOption: %v", err)
	}
	input.SearchDomains[0] = "mutated.example"
	if got := parsed.SearchDomains[0]; got != "example.com" {
		t.Fatalf("ParseDNSSLOption aliased input TLV: got %q", got)
	}
}
