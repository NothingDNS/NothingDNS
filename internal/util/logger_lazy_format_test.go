package util

import (
	"bytes"
	"strings"
	"testing"
)

type fmtCounter struct{ n *int }

func (c fmtCounter) String() string { *c.n++; return "x" }

// A suppressed level must not pay for fmt.Sprintf: Debugf runs once per DNS
// query on the hot path, and formatting before the level check allocated on
// every query even at level=error.
func TestLeveledFormatSkippedWhenSuppressed(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(ERROR, TextFormat, &buf)
	n := 0
	arg := fmtCounter{&n}

	l.Debugf("d %s", arg)
	l.Infof("i %s", arg)
	l.Warnf("w %s", arg)
	if n != 0 {
		t.Fatalf("formatted %d suppressed messages", n)
	}
	if buf.Len() != 0 {
		t.Fatalf("suppressed messages were written: %q", buf.String())
	}

	l.Errorf("e %s", arg)
	if n != 1 || !strings.Contains(buf.String(), "e x") {
		t.Fatalf("error message not formatted/written: n=%d out=%q", n, buf.String())
	}

	l.SetLevel(DEBUG)
	l.Debugf("d %s", arg)
	if n != 2 || !strings.Contains(buf.String(), "d x") {
		t.Fatalf("debug message not emitted at DEBUG: n=%d", n)
	}

	var nilLogger *Logger
	nilLogger.Debugf("d %s", arg) // must stay nil-safe and not format
	if n != 2 {
		t.Fatal("nil logger formatted a message")
	}
}
