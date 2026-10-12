package util

import (
	"bytes"
	"strings"
	"testing"
)

// F705: only CR and LF were neutralised in the text log format. A query name
// is attacker-controlled bytes, so an ESC sequence (clear screen, retitle the
// terminal, fake a coloured line), NEL or U+2028 reached the operator's
// terminal or log viewer intact.
func TestTextLogNeutralisesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(DEBUG, TextFormat, &buf)
	l.Infof("Query: %s", "evil\x1b[2J\x1b]0;pwned\x07.example.com.\u0085 x\x00y\x7f")
	l.WithField("name", "f\x1b[31m").Info("field")
	out := buf.String()
	for _, bad := range []string{"\x1b", "\x07", "\u0085", " ", "\x00", "\x7f"} {
		if strings.Contains(out, bad) {
			t.Errorf("log output holds %q: %q", bad, out)
		}
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("want exactly two log lines, got %q", out)
	}
	// control: ordinary text, tabs and non-ASCII letters pass through
	buf.Reset()
	l.Infof("ok %s\tü 中 ünï", "www.example.com.")
	if got := buf.String(); !strings.Contains(got, "ok www.example.com.\tü 中 ünï") {
		t.Errorf("clean message altered: %q", got)
	}
}
