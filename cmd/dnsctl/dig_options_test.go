package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// digProbeServer answers every datagram with a bare NOERROR response (the
// query with QR set) and hands the queries it saw to the caller.
func digProbeServer(t *testing.T) (addr string, queries func() [][]byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	seen := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			seen <- q
			resp := append([]byte(nil), q...)
			resp[2] |= 0x80 // QR
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), func() [][]byte {
		time.Sleep(50 * time.Millisecond)
		var out [][]byte
		for {
			select {
			case q := <-seen:
				out = append(out, q)
			default:
				return out
			}
		}
	}
}

// dig used to ignore every +option it did not know (and +cd), read a class as
// the record type, and drop extra arguments, so a user asking for +short or
// +tcp got neither and no message. It now rejects what it does not support,
// accepts IN as the class it always uses, and implements +cd.
func TestDigRejectsUnsupportedArguments(t *testing.T) {
	addr, queries := digProbeServer(t)
	server := "@" + addr

	for name, tc := range map[string]struct {
		args    []string
		wantErr string
	}{
		"+short":              {[]string{server, "example.com", "A", "+short"}, "+short"},
		"+tcp":                {[]string{server, "example.com", "AXFR", "+tcp"}, "+tcp"},
		"+trace":              {[]string{server, "example.com", "NS", "+trace"}, "+trace"},
		"+time=5":             {[]string{server, "example.com", "A", "+time=5"}, "+time=5"},
		"-x":                  {[]string{server, "-x", "192.0.2.1"}, "-x"},
		"class CH":            {[]string{server, "example.com", "CH", "TXT"}, "class CH"},
		"class HS after type": {[]string{server, "example.com", "TXT", "HS"}, "class HS"},
		"extra argument":      {[]string{server, "example.com", "A", "example.net"}, "example.net"},
	} {
		t.Run(name, func(t *testing.T) {
			err := cmdDig(tc.args)
			if err == nil {
				t.Fatal("FAIL: accepted and (partly) ignored")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
	if got := queries(); len(got) != 0 {
		t.Errorf("%d queries were sent for rejected arguments, want none", len(got))
	}
}

func TestDigAcceptsSupportedArguments(t *testing.T) {
	addr, queries := digProbeServer(t)
	server := "@" + addr

	cases := map[string][]string{
		"plain":           {server, "example.com", "MX"},
		"+dnssec":         {server, "example.com", "A", "+dnssec"},
		"+cd":             {server, "example.com", "A", "+cd"},
		"class IN first":  {server, "example.com", "IN", "A"},
		"class IN last":   {server, "example.com", "A", "IN"},
		"order is free":   {"+dnssec", "example.com", server, "TXT"},
		"ANY is a type":   {server, "example.com", "ANY"},
		"option any case": {server, "example.com", "+DNSSEC"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmdDig(args); err != nil {
				t.Fatalf("cmdDig(%v) = %v", args, err)
			}
		})
	}
	if got := len(queries()); got != len(cases) {
		t.Errorf("%d queries sent, want %d", got, len(cases))
	}
}

// +cd sets the CD (checking disabled) bit in the query instead of being
// accepted and dropped.
func TestDigCDSetsCheckingDisabled(t *testing.T) {
	addr, queries := digProbeServer(t)
	if err := cmdDig([]string{"@" + addr, "example.com", "A", "+cd"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDig([]string{"@" + addr, "example.com", "A"}); err != nil {
		t.Fatal(err)
	}
	got := queries()
	if len(got) != 2 {
		t.Fatalf("%d queries, want 2", len(got))
	}
	const cd = 0x10 // CD is bit 4 of the second flags byte
	if got[0][3]&cd == 0 {
		t.Error("FAIL: +cd query does not carry the CD bit")
	}
	if got[1][3]&cd != 0 {
		t.Error("control: a plain query carries the CD bit")
	}
}
