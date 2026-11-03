package protocol

import (
	"bytes"
	"testing"
)

func TestMessageCopyPreservesOwnedTSIGSignedWire(t *testing.T) {
	original := &Message{TSIGSignedWire: []byte{0x12, 0x34, 0x56}}
	copyMessage := original.Copy()
	if !bytes.Equal(copyMessage.TSIGSignedWire, original.TSIGSignedWire) {
		t.Fatalf("TSIGSignedWire copy = %x, want %x", copyMessage.TSIGSignedWire, original.TSIGSignedWire)
	}

	copyMessage.TSIGSignedWire[0] ^= 0xff
	if bytes.Equal(copyMessage.TSIGSignedWire, original.TSIGSignedWire) {
		t.Fatal("Message.Copy retained an alias to TSIGSignedWire")
	}
}
