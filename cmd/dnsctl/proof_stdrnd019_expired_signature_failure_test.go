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

// buildExpiredSigZone writes a zone file whose DNSKEY carries a REAL generated
// key and whose RRSIG quotes that key's ACTUAL key tag, but whose validity
// window closed in the past.
//
// Matching the real key tag is the whole point: it is what lets the RRSIG reach
// the timestamp branch in cmdDNSSECValidateZone instead of being rejected
// earlier by the "No DNSKEY found for keytag" check. The pre-existing
// TestCmdDNSSECValidateZone_ExpiredSignature uses key tag 12345 against a fake
// key, so it exits via invalidSigs and never exercises the expiry branch at
// all — and its output assertion is satisfied vacuously, because the summary
// line "Expired/Not-yet-valid: %d" prints unconditionally.
func buildExpiredSigZone(t *testing.T) (zoneFile string, sig string) {
	t.Helper()

	key, err := generateKeyPairOnce(protocol.AlgorithmECDSAP256SHA256, false, 0)
	if err != nil {
		t.Fatalf("generateKeyPairOnce: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(key.DNSKEY.PublicKey)
	sig = base64.StdEncoding.EncodeToString([]byte("not-a-real-signature"))

	// inception 2019-01-01, expiration 2020-01-01 — both long past.
	const expired = 1577836800
	const inception = 1546300800

	zone := fmt.Sprintf(`example.com. 300 IN DNSKEY %d 3 %d %s
example.com. 300 IN A 192.0.2.1
example.com. 300 IN RRSIG A %d 1 300 %d %d %d example.com. %s
`,
		key.DNSKEY.Flags, key.DNSKEY.Algorithm, pubB64,
		key.DNSKEY.Algorithm, expired, inception, key.KeyTag, sig)

	zoneFile = filepath.Join(t.TempDir(), "zone.zone")
	if err := os.WriteFile(zoneFile, []byte(zone), 0o644); err != nil {
		t.Fatalf("write zone: %v", err)
	}
	return zoneFile, sig
}

// TestProofRound019_ExpiredSignatureIsAFailure pins the contract that
// `dnssec dnssec validate-zone` must reject a zone whose signatures have all
// expired. The command exposes --ignore-time precisely so that time validity is
// NOT checked; when the operator does not pass it, timestamps are enforced and
// an expired signature is a real validation failure, not a footnote.
//
// Only invalidSigs currently fails the command (dnssec.go:1160), so an
// all-expired zone prints "Valid: 0, Invalid: 0, Expired/Not-yet-valid: 1"
// and exits 0 — a false "signed and valid" verdict from a validation tool,
// which is the exact failure mode the adjacent comment in that same loop
// records as having been fixed for the "no records covered" case.
func TestProofRound019_ExpiredSignatureIsAFailure(t *testing.T) {
	zoneFile, _ := buildExpiredSigZone(t)

	output := captureOutput(func() {
		// No --ignore-time: timestamps ARE being enforced.
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile})
		if err == nil {
			t.Error("FAIL: a zone whose only signature is EXPIRED must fail validation " +
				"(the zone is not currently validly signed), but validate-zone reported success")
		}
	})

	// Guard against a vacuous pass: the signature must actually have been
	// counted as expired, not merely printed in the always-present summary.
	if !strings.Contains(output, "Signature expired for") {
		t.Errorf("expiry branch was not reached; output was: %q", output)
	}
}

// TestProofRound019_ExpiredSignatureControlIgnoringTime is the control: with
// --ignore-time the operator has explicitly asked for timestamps to be skipped,
// so the same zone must instead be judged on its signature bytes. It is a
// garbage signature, so validation must fail via invalidSigs.
//
// This proves the harness reports failures correctly, and that the expired
// timestamp alone is what makes the difference in the test above.
func TestProofRound019_ExpiredSignatureControlIgnoringTime(t *testing.T) {
	zoneFile, _ := buildExpiredSigZone(t)

	output := captureOutput(func() {
		err := cmdDNSSECValidateZone([]string{"--zone", zoneFile, "--ignore-time"})
		if err == nil {
			t.Error("control: with --ignore-time a zone signed by a garbage signature must still fail")
		}
	})
	_ = output
}
