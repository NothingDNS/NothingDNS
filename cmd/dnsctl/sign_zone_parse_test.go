package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// sign-zone reads its input with the server's zone-file parser, so a standard
// BIND file (directives, omitted TTL and class, an inherited owner, a
// parenthesised SOA, relative names) is signed in full, and a line the parser
// cannot read is an error that names the line, never a silently shorter zone.
func TestSignZoneReadsStandardBINDFiles(t *testing.T) {
	const standard = `$ORIGIN example.com.
$TTL 300
@   IN SOA ns1 hostmaster (
        2024010101 ; serial
        3600 900 604800 300 )
    IN NS  ns1
ns1 IN A   192.0.2.1
www 600 A  192.0.2.10
    IN AAAA 2001:db8::10
mail IN MX 10 mailhost
`
	dir := t.TempDir()
	in := filepath.Join(dir, "example.com.zone")
	out := filepath.Join(dir, "example.com.zone.signed")
	if err := os.WriteFile(in, []byte(standard), 0o600); err != nil {
		t.Fatal(err)
	}

	records, err := parseZoneRecords(standard, "example.com.")
	if err != nil {
		t.Fatalf("FAIL: standard BIND file rejected: %v", err)
	}
	type key struct {
		name  string
		rtype uint16
	}
	got := map[key]uint32{}
	for _, rr := range records {
		got[key{rr.Name.String(), rr.Type}] = rr.TTL
	}
	for k, wantTTL := range map[key]uint32{
		{"example.com.", protocol.TypeSOA}:      300,
		{"example.com.", protocol.TypeNS}:       300,
		{"ns1.example.com.", protocol.TypeA}:    300,
		{"www.example.com.", protocol.TypeA}:    600,
		{"www.example.com.", protocol.TypeAAAA}: 300,
		{"mail.example.com.", protocol.TypeMX}:  300,
	} {
		if ttl, ok := got[k]; !ok || ttl != wantTTL {
			t.Errorf("record %v: present=%v ttl=%d, want ttl %d", k, ok, ttl, wantTTL)
		}
	}
	if len(records) != 6 {
		t.Errorf("got %d records, want 6", len(records))
	}

	if err := cmdDNSSECSignZone([]string{"--zone", "example.com", "--input", in, "--output", out, "--keydir", dir}); err != nil {
		t.Fatalf("sign-zone: %v", err)
	}
	output := captureOutput(func() {
		if err := cmdDNSSECValidateZone([]string{"--zone", out}); err != nil {
			t.Fatalf("validate-zone: %v", err)
		}
	})
	if !strings.Contains(output, "Invalid: 0") || strings.Contains(output, "Valid: 0\n") {
		t.Errorf("signed output does not validate:\n%s", output)
	}
}

func TestSignZoneFailsLoudlyOnUnreadableLines(t *testing.T) {
	for name, content := range map[string]string{
		"bad address":  "$ORIGIN example.com.\n@ 300 IN SOA ns1 h 1 3600 900 604800 300\n@ 300 IN NS ns1\nwww 300 IN A not-an-ip\n",
		"unknown type": "$ORIGIN example.com.\n@ 300 IN SOA ns1 h 1 3600 900 604800 300\n@ 300 IN NS ns1\nwww 300 IN BOGUS x\n",
		"bad TTL":      "$ORIGIN example.com.\n@ 300 IN SOA ns1 h 1 3600 900 604800 300\n@ 300 IN NS ns1\nwww notattl IN A 192.0.2.1\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "z.zone")
			out := filepath.Join(dir, "z.zone.signed")
			if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := cmdDNSSECSignZone([]string{"--zone", "example.com", "--input", in, "--output", out, "--keydir", dir})
			if err == nil {
				t.Fatal("FAIL: a zone file with an unreadable line was signed without an error")
			}
			if !strings.Contains(err.Error(), "line 4") {
				t.Errorf("error does not name line 4: %v", err)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Error("an output file was written for a zone that failed to parse")
			}
		})
	}
}

// A file with no $ORIGIN of its own gets one in front; the line numbers in
// errors still count the file's own lines.
func TestParseZoneRecordsErrorLinesWithoutOrigin(t *testing.T) {
	_, err := parseZoneRecords("@ 300 IN A 192.0.2.1\nwww 300 IN A bad\n", "example.com.")
	if err == nil || !strings.Contains(err.Error(), "line 2:") {
		t.Fatalf("error = %v, want one naming line 2", err)
	}
	records, err := parseZoneRecords("@ 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.2\n", "example.com.")
	if err != nil || len(records) != 2 || records[0].Name.String() != "example.com." || records[1].Name.String() != "www.example.com." {
		t.Fatalf("records=%v err=%v, want the two records in file order under the zone origin", records, err)
	}
}
