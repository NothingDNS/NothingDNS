package resolver

import (
	"github.com/nothingdns/nothingdns/internal/protocol"
	"strings"
	"testing"
)

func TestEncode0x20_RandomizesCase(t *testing.T) {
	const name = "www.example.com."
	// Run many iterations — with 11 alpha chars the probability of
	// getting the exact same case every time is vanishingly small.
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		encoded := Encode0x20(name)
		seen[encoded] = true
		// Must always be case-insensitively equal to the original
		if !strings.EqualFold(encoded, name) {
			t.Fatalf("Encode0x20 produced non-equivalent name: %q vs %q", encoded, name)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("Encode0x20 produced no variation over 200 iterations (got %d unique)", len(seen))
	}
}

func TestEncode0x20_PreservesDotsAndNonAlpha(t *testing.T) {
	const name = "a1-b2.c3.example.com."
	for i := 0; i < 50; i++ {
		encoded := Encode0x20(name)
		if len(encoded) != len(name) {
			t.Fatalf("length changed: %d vs %d", len(encoded), len(name))
		}
		for j := 0; j < len(name); j++ {
			orig := name[j]
			enc := encoded[j]
			if !isASCIILetter(orig) {
				// Non-alpha characters must be unchanged
				if enc != orig {
					t.Fatalf("non-alpha byte %d changed: %q -> %q", j, orig, enc)
				}
			}
		}
	}
}

func TestEncode0x20_EmptyAndRootDot(t *testing.T) {
	if got := Encode0x20(""); got != "" {
		t.Fatalf("empty string: got %q", got)
	}
	if got := Encode0x20("."); got != "." {
		t.Fatalf("root dot: got %q", got)
	}
}

func TestVerify0x20_ExactMatch(t *testing.T) {
	cases := []struct {
		query, response string
		want            bool
	}{
		{"wWw.eXaMpLe.CoM.", "wWw.eXaMpLe.CoM.", true},
		{"example.com.", "example.com.", true},
		{".", ".", true},
		{"", "", true},
	}
	for _, tc := range cases {
		if got := Verify0x20(tc.query, tc.response); got != tc.want {
			t.Errorf("Verify0x20(%q, %q) = %v, want %v", tc.query, tc.response, got, tc.want)
		}
	}
}

func TestVerify0x20_Mismatch(t *testing.T) {
	cases := []struct {
		query, response string
	}{
		{"wWw.eXaMpLe.CoM.", "www.example.com."},
		{"wWw.eXaMpLe.CoM.", "WWW.EXAMPLE.COM."},
		{"Example.COM.", "example.com."},
		{"a.b.", "a.c."},
	}
	for _, tc := range cases {
		if Verify0x20(tc.query, tc.response) {
			t.Errorf("Verify0x20(%q, %q) should be false", tc.query, tc.response)
		}
	}
}

func TestVerify0x20Response(t *testing.T) {
	name := protocol.NewName([]string{"www", "example", "com"}, true)

	// Response with matching question name
	resp := &protocol.Message{
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	// Name.String() returns "www.example.com."
	if !verify0x20Response("www.example.com.", resp) {
		t.Error("verify0x20Response should return true for matching name")
	}

	// Response with no questions
	emptyResp := &protocol.Message{
		Questions: []*protocol.Question{},
	}
	if verify0x20Response("www.example.com.", emptyResp) {
		t.Error("verify0x20Response should return false for empty questions")
	}
}
