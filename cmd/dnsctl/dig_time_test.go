package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// dig prints the time the query really took, not a fixed "~0ms" (F765).
func TestDigPrintsMeasuredQueryTime(t *testing.T) {
	name, _ := protocol.ParseName("example.com.")
	resp := &protocol.Message{Questions: []*protocol.Question{{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN}}}
	out := captureOutput(func() {
		printDigResponse("example.com.", "A", "127.0.0.1", "127.0.0.1:53", false, resp, 42*time.Millisecond)
	})
	if !strings.Contains(out, ";; Query time: 42 msec") {
		t.Errorf("query time not reported:\n%s", out)
	}
}
