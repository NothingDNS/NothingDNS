package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestOpenLogOutput(t *testing.T) {
	for _, name := range []string{"", "stdout"} {
		w, closeFn, err := openLogOutput(name)
		if err != nil || w != os.Stdout {
			t.Errorf("openLogOutput(%q) = %v, %v; want stdout", name, w, err)
		}
		closeFn()
	}
	if w, closeFn, err := openLogOutput("stderr"); err != nil || w != os.Stderr {
		t.Errorf("openLogOutput(stderr) = %v, %v", w, err)
	} else {
		closeFn()
	}

	path := filepath.Join(t.TempDir(), "server.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	w, closeFn, err := openLogOutput(path)
	if err != nil {
		t.Fatalf("openLogOutput(file): %v", err)
	}
	if _, err := w.Write([]byte("appended\n")); err != nil {
		t.Fatal(err)
	}
	closeFn()
	if got, _ := os.ReadFile(path); string(got) != "existing\nappended\n" {
		t.Errorf("file content = %q, want appended output", got)
	}

	w, closeFn, err = openLogOutput(filepath.Join(t.TempDir(), "missing", "server.log"))
	if err == nil || w != os.Stdout {
		t.Errorf("unopenable file: got %v, %v; want stdout and an error", w, err)
	}
	closeFn()
}

// The query log and dashboard record the RCODE actually sent when no stage
// set one explicitly; an explicit (possibly extended) RCODE wins.
func TestQueryResponseRcode(t *testing.T) {
	q := &query{}
	if _, ok := q.responseRcode(); ok {
		t.Error("no response written: rcode must be unknown")
	}

	hw := newHeaderPolicyWriter(nil, newCaptureWriter("192.0.2.1", "udp"), nil).(*headerPolicyResponseWriter)
	q.policyWriter = hw
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)}}
	if _, err := hw.Write(resp); err != nil {
		t.Fatal(err)
	}
	if rcode, ok := q.responseRcode(); !ok || rcode != protocol.RcodeNameError {
		t.Errorf("rcode = %d, %v; want NXDOMAIN from the written response", rcode, ok)
	}

	q.rcode, q.rcodeSet = protocol.RcodeBadVers, true
	if rcode, _ := q.responseRcode(); rcode != protocol.RcodeBadVers {
		t.Errorf("rcode = %d; want the explicitly set BADVERS", rcode)
	}
}
