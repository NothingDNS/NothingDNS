package main

// Regression test for the 2026-10-19 proof-driven round 055: serving a query
// through an unwired (zero-value) integratedHandler panicked the pipeline on
// its first log line — *util.Logger methods dereferenced the nil receiver —
// and over DoQ the adapter's recover then dropped the client's query with no
// response (observed as "doq handler panic: runtime error: invalid memory
// address or nil pointer dereference" in a full-suite run). A nil Logger is
// now a discard logger; a query on the zero-value handler must complete.

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestZeroValueHandlerServesQueryWithoutPanic(t *testing.T) {
	h := &integratedHandler{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FAIL: zero-value integratedHandler.ServeDNS panicked: %v", r)
		}
	}()

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "test.com.", protocol.TypeA))

	if w.msg != nil {
		t.Logf("zero-value handler answered rcode=%d", w.msg.Header.Flags.RCODE)
	}
}
