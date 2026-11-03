package resolver

import (
	"strings"
	"testing"
	"time"
)

func TestDNSSLValidateDNSNameWireLimits(t *testing.T) {
	validMax := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{name: "ordinary", domain: "example.com"},
		{name: "trailing dot", domain: "example.com."},
		{name: "maximum wire name", domain: validMax},
		{name: "label too long", domain: strings.Repeat("a", 64) + ".example", wantErr: true},
		{name: "empty interior label", domain: "example..com", wantErr: true},
		{name: "root only", domain: ".", wantErr: true},
		{name: "wire name too long", domain: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NewDNSSLOption(time.Minute, []string{tc.domain}).Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
