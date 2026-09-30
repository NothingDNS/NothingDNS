package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// writeValidateZoneFixture writes a zone file whose single RRSIG carries the
// real key tag of the DNSKEY beside it, so the RRSIG passes the DNSKEY lookup
// and actually reaches the covered-RRset check under test. includeRRset
// controls whether the record type the RRSIG covers is present in the file.
func writeValidateZoneFixture(t *testing.T, includeRRset bool) string {
	t.Helper()
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "zone.zone")

	pubB64 := base64.StdEncoding.EncodeToString([]byte("fakepublickey12345"))
	rd := protocol.ParseRDataText("DNSKEY", "257 3 13 "+pubB64)
	dnskey, ok := rd.(*protocol.RDataDNSKEY)
	if !ok {
		t.Fatalf("fixture: DNSKEY did not parse: %T", rd)
	}
	tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	body := fmt.Sprintf("example.com. 300 IN DNSKEY 257 3 13 %s\n", pubB64)
	if includeRRset {
		body += "example.com. 300 IN A 192.0.2.1\n"
	}
	body += fmt.Sprintf("example.com. 300 IN RRSIG A 13 1 300 1609459200 1606786800 %d example.com. %s\n",
		tag, base64.StdEncoding.EncodeToString([]byte("fakesig")))

	if err := os.WriteFile(zoneFile, []byte(body), 0644); err != nil {
		t.Fatalf("writing zone fixture: %v", err)
	}
	return zoneFile
}

func runValidateZone(t *testing.T, zoneFile string) (string, error) {
	t.Helper()
	var err error
	out := captureOutput(func() {
		err = cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
	})
	return out, err
}

// An RRSIG whose covered RRset is absent from the zone file cannot be
// verified. It must still be accounted for in the summary, otherwise
// validate-zone reports "Valid: 0, Invalid: 0" and exits successfully —
// a false "signed and valid" verdict for a zone nothing was checked on.
func TestValidateZoneFailsWhenRRSIGCoversAbsentRRset(t *testing.T) {
	zoneFile := writeValidateZoneFixture(t, false)

	out, err := runValidateZone(t, zoneFile)
	t.Logf("validate-zone output:\n%s", out)

	if err == nil {
		t.Fatalf("expected failure: 1 RRSIG covers an A RRset that is absent, so no " +
			"signature could be verified; validate-zone returned success")
	}
	if !strings.Contains(out, "Invalid: 1") {
		t.Errorf("summary must count the unverifiable RRSIG as invalid; got:\n%s", out)
	}
}

// Control: when the covered RRset IS present, the command still reaches
// signature verification and counts the RRSIG exactly once.
func TestValidateZoneStillVerifiesWhenRRSIGCoversPresentRRset(t *testing.T) {
	zoneFile := writeValidateZoneFixture(t, true)

	out, err := runValidateZone(t, zoneFile)
	t.Logf("validate-zone output:\n%s", out)

	if strings.Contains(out, "No records found for RRSIG covering") {
		t.Fatalf("covered RRset is present, so the missing-RRset path must not trigger; got:\n%s", out)
	}
	if err == nil {
		t.Errorf("expected the bogus signature to be rejected, got success; output:\n%s", out)
	}
	if !strings.Contains(out, "Total RRSIGs: 1") || !strings.Contains(out, "Invalid: 1") {
		t.Errorf("the single RRSIG must be counted exactly once; got:\n%s", out)
	}
}
