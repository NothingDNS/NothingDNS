package protocol

import "crypto/rand"

// PaddingBlockSize is the RFC 8467 §4.1 recommended block size for server
// response padding (468 bytes).
const PaddingBlockSize = 468

// HasPaddingOption reports whether msg carries an RFC 7830 Padding option.
// Per RFC 7830 §4 a server pads a response if and only if the query did.
func HasPaddingOption(msg *Message) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Additionals {
		if rr == nil || rr.Type != TypeOPT {
			continue
		}
		if opt, ok := rr.Data.(*RDataOPT); ok && opt.GetOption(OptionCodePadding) != nil {
			return true
		}
	}
	return false
}

// PadResponse appends a zero-filled RFC 7830 Padding option to the response's
// OPT record, sizing the packed response up to a multiple of PaddingBlockSize
// (RFC 8467 §4.1) plus a random offset within one block, never beyond maxLen.
// packedLen is the response's current packed size. Returns false when the
// response carries no OPT record to hold the option or has no room for it
// (nothing padded); otherwise the response must be packed again.
func PadResponse(msg *Message, packedLen, maxLen int) bool {
	var opt *RDataOPT
	for _, rr := range msg.Additionals {
		if rr == nil || rr.Type != TypeOPT {
			continue
		}
		if o, ok := rr.Data.(*RDataOPT); ok {
			opt = o
			break
		}
	}
	if opt == nil {
		return false
	}
	// The option itself costs 4 header bytes; the zero-filled data brings
	// the total up to the next block boundary.
	withOptionHeader := packedLen + 4
	if withOptionHeader > maxLen {
		return false
	}
	blockFill := (PaddingBlockSize - withOptionHeader%PaddingBlockSize) % PaddingBlockSize
	// RFC 8467 §4.1 recommends block-aligned padding but allows randomization
	// within the block boundary to prevent traffic analysis. A fixed padding
	// length makes the underlying response size predictable: given the block
	// boundary, the response size uniquely determines the unpadded payload size.
	// Adding a uniform random offset in [0, PaddingBlockSize) makes the final
	// response size unpredictable to a network observer who knows only the
	// block boundary.
	var extra int
	var randBuf [2]byte
	if _, err := rand.Read(randBuf[:]); err == nil {
		extra = int(randBuf[0])<<8 | int(randBuf[1])
		extra %= PaddingBlockSize
	}
	padLen := min(blockFill+extra, maxLen-withOptionHeader)
	opt.AddOption(OptionCodePadding, make([]byte, padLen))
	return true
}

// PadResponseTo pads resp when query carried a Padding option (RFC 7830 §4),
// adding an OPT record if resp has none: a filtered answer (ACL, RRL,
// recursion) often carries no OPT, and an unpadded one would reveal by its
// size that the query was filtered. packedLen is resp's current packed size.
// Reports whether resp changed and must be packed again.
func PadResponseTo(query, resp *Message, packedLen, maxLen int) bool {
	if resp == nil || !HasPaddingOption(query) {
		return false
	}
	if resp.GetOPT() == nil {
		// SetEDNS0 gives the OPT its root owner name; a bare record with a
		// nil Name failed to pack (F648). The record adds 11 bytes.
		resp.SetEDNS0(4096, false)
		packedLen += 11
	}
	return PadResponse(resp, packedLen, maxLen)
}
