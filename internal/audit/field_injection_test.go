package audit

import (
	"strings"
	"testing"
)

// F642: query names and zones are attacker-chosen and reach the logger
// unescaped; a space inside a label forged key=value fields.
func TestFormatAuditLines_EscapeFieldSeparators(t *testing.T) {
	q := formatQueryAuditLine(QueryAuditEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		ClientIP:  "10.0.0.1",
		QueryName: "x client=6.6.6.6\trcode=NOERROR.example.com.",
		QueryType: "A",
		Rcode:     "SERVFAIL",
	})
	if n := strings.Count(q, " client="); n != 1 {
		t.Errorf("query line has %d client= fields, want 1: %s", n, q)
	}
	if !strings.Contains(q, `query=x\032client=6.6.6.6\009rcode=NOERROR.example.com. `) {
		t.Errorf("query name not escaped as expected: %s", q)
	}

	a := formatAXFRAuditLine(AXFRAuditEntry{Timestamp: "t", ClientIP: "10.0.0.1", Zone: "evil. action=completed", Action: "failed"})
	if n := strings.Count(a, " action="); n != 1 {
		t.Errorf("AXFR line has %d action= fields, want 1: %s", n, a)
	}

	for in, want := range map[string]string{
		"www.example.com.": "www.example.com.",
		`a\032b.`:          `a\\032b.`,
		"a\nb":             `a\nb`,
		"a\x00b":           "ab",
		"a\x7fb":           `a\127b`,
	} {
		if got := sanitizeLogToken(in); got != want {
			t.Errorf("sanitizeLogToken(%q) = %q, want %q", in, got, want)
		}
	}
}
