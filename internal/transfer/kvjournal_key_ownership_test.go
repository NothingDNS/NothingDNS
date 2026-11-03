package transfer

import (
	"bytes"
	"testing"
)

func TestNewKVJournalStoreCopiesHMACKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	store := NewKVJournalStore(t.TempDir(), key)

	key[0] = 0x22
	if got := store.hmacKey[0]; got != 0x11 {
		t.Fatalf("store HMAC key aliases caller buffer: got first byte %#x", got)
	}
}
