package api

import "testing"

// F692: the zone-file round trip accepts trailing junk, comments and
// padding that ParseRDataText (the form the authoritative path serves from)
// rejects, so the API answered 201 for a record that was then never served.
func TestValidateRecordRoundTripRejectsUnservableData(t *testing.T) {
	bad := [][2]string{
		{"A", "192.0.2.1 extra"},
		{"A", "192.0.2.1 ; note"},
		{"MX", "10 mail.example.com. ; x"},
		{"AAAA", "2001:db8::1 junk"},
		{"CNAME", "a.example.com. b.example.com."},
	}
	for _, c := range bad {
		if err := validateRecordRoundTrip(c[0], c[1]); err == nil {
			t.Errorf("%s %q accepted but would never be served", c[0], c[1])
		}
	}
	good := [][2]string{
		{"A", "192.0.2.1"},
		{"MX", "10 mail.example.com."},
		{"TXT", "hello ; world"},
		{"TXT", `"a" "b"`},
	}
	for _, c := range good {
		if err := validateRecordRoundTrip(c[0], c[1]); err != nil {
			t.Errorf("%s %q rejected: %v", c[0], c[1], err)
		}
	}
}
