package protocol

import (
	"errors"
	"testing"
)

// TestSSHFPUnpackRejectsShortRDLength locks in the VULN-007 fix.
// rdlength < 2 previously caused make([]byte, negative) to panic on
// attacker-controlled upstream responses, AXFR peers, or zone files.
func TestSSHFPUnpackRejectsShortRDLength(t *testing.T) {
	for _, rdlength := range []uint16{0, 1} {
		var r RDataSSHFP
		// 2-byte buffer so offset+2 would succeed if the early guard were absent.
		buf := []byte{0x01, 0x01}
		_, err := r.Unpack(buf, 0, rdlength)
		if err == nil {
			t.Errorf("SSHFP Unpack rdlength=%d: expected error, got nil", rdlength)
			continue
		}
		if !errors.Is(err, ErrBufferTooSmall) {
			t.Errorf("SSHFP Unpack rdlength=%d: expected ErrBufferTooSmall, got %v", rdlength, err)
		}
	}
}

// TestTLSAUnpackRejectsShortRDLength locks in the VULN-007 fix.
// rdlength < 3 previously caused make([]byte, negative) to panic.
func TestTLSAUnpackRejectsShortRDLength(t *testing.T) {
	for _, rdlength := range []uint16{0, 1, 2} {
		var r RDataTLSA
		buf := []byte{0x01, 0x01, 0x01}
		_, err := r.Unpack(buf, 0, rdlength)
		if err == nil {
			t.Errorf("TLSA Unpack rdlength=%d: expected error, got nil", rdlength)
			continue
		}
		if !errors.Is(err, ErrBufferTooSmall) {
			t.Errorf("TLSA Unpack rdlength=%d: expected ErrBufferTooSmall, got %v", rdlength, err)
		}
	}
}
