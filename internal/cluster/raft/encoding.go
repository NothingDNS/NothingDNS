package raft

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nothingdns/nothingdns/internal/util"
)

// TLV-encoded RPC framing (replaces gob to close VULN-037/VULN-048).
//
// Frame format (each message):
//   [1 byte msgType] [4 byte length] [length bytes payload]
//   If AEAD is configured, payload is nonce+ciphertext+tag (Seal format).
//
// No slices/maps with attacker-controlled length prefixes (unlike gob).
// maxRPCMessageBytes still applies as a hard cap via LimitReader.

// msgType envelope — stays in plaintext so the receiver knows which
// decryption key to use before attempting Open().
const frameHeaderSize = 5 // 1 msgType + 4 length

// maxRPCMessageBytes caps a single framed Raft RPC payload.
const maxRPCMessageBytes = 16 * 1024 * 1024 // 16 MiB

// frameWriter writes TLV-framed messages.
type frameWriter struct {
	w        io.Writer
	aead     cipher.AEAD
	nonceBuf []byte // scratch buffer sized to aead.NonceSize()
}

func newFrameWriter(w io.Writer, aead cipher.AEAD) *frameWriter {
	var nb []byte
	if aead != nil {
		nb = make([]byte, aead.NonceSize())
	}
	return &frameWriter{w: w, aead: aead, nonceBuf: nb}
}

// writeFramed writes a framed message. msgType is in plaintext; payload is
// encrypted if aead != nil (matching the gossip protocol's model).
func (fw *frameWriter) writeFramed(msgType uint8, msg any) error {
	// Encode the payload first so we know its length.
	var plainPayload []byte
	if fw.aead == nil {
		// Unsafely compact for non-cryptographic paths (dev/test only).
		var err error
		plainPayload, err = encodeNative(msg)
		if err != nil {
			return fmt.Errorf("encode native: %w", err)
		}
		// Send plaintext header + length-prefixed payload.
		return fw.writeRaw(msgType, plainPayload)
	}

	// AEAD path: encode, then seal with random nonce.
	plainPayload, err := encodeNative(msg)
	if err != nil {
		return fmt.Errorf("encode native: %w", err)
	}
	// F148: the reader caps the WIRE length (nonce+ciphertext+tag), so the
	// plaintext budget is the cap minus the AEAD expansion. Checking only the
	// plaintext let a sender emit frames every receiver rejects.
	if maxPlain := maxRPCMessageBytes - fw.aead.NonceSize() - fw.aead.Overhead(); len(plainPayload) > maxPlain {
		return fmt.Errorf("payload exceeds maxRPCMessageBytes after AEAD sealing (%d > %d)", len(plainPayload), maxPlain)
	}
	var msgTypeBuf [1]byte
	msgTypeBuf[0] = msgType
	if err := util.WriteFull(fw.w, msgTypeBuf[:]); err != nil {
		return err
	}
	// Generate random nonce.
	if _, err := io.ReadFull(rand.Reader, fw.nonceBuf); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	// Seal appends ciphertext+tag AFTER the nonce so the wire payload is
	// nonce || ciphertext || tag, matching readFrameBytes which slices the nonce
	// from the front (ciphertext[:NonceSize]). Using nonceBuf[:0] as the dst would
	// drop the nonce from the wire entirely, making every frame undecryptable and
	// silently breaking encrypted Raft clusters. Since nonceBuf has cap==NonceSize,
	// Seal reallocates a fresh backing array (leaving nonceBuf intact for the next
	// random nonce) and reads the nonce before writing output, so aliasing is safe.
	ciphertext := fw.aead.Seal(fw.nonceBuf, fw.nonceBuf, plainPayload, []byte{msgType})
	// Write length prefix.
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(ciphertext)))
	if err := util.WriteFull(fw.w, lengthBuf[:]); err != nil {
		return err
	}
	return util.WriteFull(fw.w, ciphertext)
}

// writeRaw writes a plaintext TLV frame (no AEAD).
func (fw *frameWriter) writeRaw(msgType uint8, plainPayload []byte) error {
	if len(plainPayload) > maxRPCMessageBytes {
		return fmt.Errorf("payload exceeds maxRPCMessageBytes (%d > %d)", len(plainPayload), maxRPCMessageBytes)
	}
	var header [frameHeaderSize]byte
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(plainPayload)))
	if err := util.WriteFull(fw.w, header[:]); err != nil {
		return err
	}
	return util.WriteFull(fw.w, plainPayload)
}

// frameReader reads TLV-framed messages.
type frameReader struct {
	r    io.Reader
	aead cipher.AEAD
}

func newFrameReader(r io.Reader, aead cipher.AEAD) *frameReader {
	return &frameReader{r: r, aead: aead}
}

// readFramed reads a framed message and decodes it into msg.
// Returns the msgType that was on the wire.
func (fr *frameReader) readFramed(msg any) (uint8, error) {
	msgType, payload, err := fr.readFrameBytes()
	if err != nil {
		return msgType, err
	}
	// F147: no message encodes to zero bytes, so an empty payload is
	// truncated input — let decodeNative reject it instead of returning
	// success with msg left at its zero value.
	return msgType, decodeNative(msg, payload)
}

// readFrameBytes reads one frame and returns its message type and decoded
// plaintext payload, WITHOUT decoding into a Go value. The caller chooses the
// target struct based on msgType — essential on the server side, which can't
// know which message type is arriving until it reads the header.
func (fr *frameReader) readFrameBytes() (uint8, []byte, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(fr.r, header[:]); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxRPCMessageBytes {
		return msgType, nil, fmt.Errorf("frame length %d exceeds max %d", length, maxRPCMessageBytes)
	}

	if fr.aead == nil {
		// Plaintext path.
		if length == 0 {
			return msgType, nil, nil
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return msgType, nil, err
		}
		return msgType, payload, nil
	}

	// AEAD path: read nonce+ciphertext+tag, then Open.
	if length < uint32(fr.aead.NonceSize()+fr.aead.Overhead()) {
		return msgType, nil, fmt.Errorf("ciphertext too short for AEAD")
	}
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(fr.r, ciphertext); err != nil {
		return msgType, nil, err
	}
	// AAD binds the msgType to prevent cross-protocol replay.
	plaintext, err := fr.aead.Open(nil, ciphertext[:fr.aead.NonceSize()], ciphertext[fr.aead.NonceSize():], []byte{msgType})
	if err != nil {
		return msgType, nil, fmt.Errorf("aead open: %w", err)
	}
	return msgType, plaintext, nil
}

// encodeNative encodes a native Go value to bytes (replaces gob for RPC).
// Uses a simple type-switch-based TLV format — no reflection-based allocation
// tricks that gob performs on slice/map length prefixes.
func encodeNative(msg any) ([]byte, error) {
	switch m := msg.(type) {
	case VoteRequest:
		return encodeVoteRequest(m)
	case VoteResponse:
		return encodeVoteResponse(m)
	case AppendRequest:
		return encodeAppendRequest(m)
	case AppendResponse:
		return encodeAppendResponse(m)
	case SnapshotRequest:
		return encodeSnapshotRequest(m)
	case SnapshotResponse:
		return encodeSnapshotResponse(m)
	default:
		// Fallback for unknown types — should not reach here in practice.
		return nil, fmt.Errorf("unsupported message type %T", msg)
	}
}

// decodeNative decodes bytes into a native Go value (replaces gob for RPC).
func decodeNative(msg any, data []byte) error {
	switch m := msg.(type) {
	case *VoteRequest:
		return decodeVoteRequest(m, data)
	case *VoteResponse:
		return decodeVoteResponse(m, data)
	case *AppendRequest:
		return decodeAppendRequest(m, data)
	case *AppendResponse:
		return decodeAppendResponse(m, data)
	case *SnapshotRequest:
		return decodeSnapshotRequest(m, data)
	case *SnapshotResponse:
		return decodeSnapshotResponse(m, data)
	default:
		return fmt.Errorf("unsupported message type %T", msg)
	}
}

// --- VoteRequest ---
//
// Wire format (big-endian):
//   Term            8 bytes
//   CandidateID len 4 bytes
//   CandidateID     len bytes
//   LastLogIndex    8 bytes
//   LastLogTerm     8 bytes

func encodeVoteRequest(v VoteRequest) ([]byte, error) {
	size := 8 + 4 + len(v.CandidateID) + 8 + 8
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(v.Term))
	off += 8
	binary.BigEndian.PutUint32(buf[off:], uint32(len(v.CandidateID)))
	off += 4
	copy(buf[off:], v.CandidateID)
	off += len(v.CandidateID)
	binary.BigEndian.PutUint64(buf[off:], uint64(v.LastLogIndex))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], uint64(v.LastLogTerm))
	return buf, nil
}

func decodeVoteRequest(v *VoteRequest, data []byte) error {
	if len(data) < 28 {
		return fmt.Errorf("VoteRequest: short data %d", len(data))
	}
	off := 0
	v.Term = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	candLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	// Bound check: a peer (or inside-keyring attacker) could send
	// candLen > available bytes, causing a slice-bounds panic. Reject
	// rather than crash the Raft member.
	if uint64(off)+uint64(candLen) > uint64(len(data)) {
		return fmt.Errorf("VoteRequest: candLen %d overflows data", candLen)
	}
	v.CandidateID = NodeID(data[off : off+int(candLen)])
	off += int(candLen)
	if off+16 > len(data) {
		return fmt.Errorf("VoteRequest: truncated trailing log fields")
	}
	v.LastLogIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	v.LastLogTerm = Term(binary.BigEndian.Uint64(data[off:]))
	return nil
}

// --- VoteResponse ---
//
// Wire format:
//   Term         8 bytes
//   VoteGranted  1 byte (1=true,0=false)
//   From len     4 bytes
//   From         len bytes

func encodeVoteResponse(v VoteResponse) ([]byte, error) {
	size := 8 + 1 + 4 + len(v.From)
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(v.Term))
	off += 8
	if v.VoteGranted {
		buf[off] = 1
	}
	off++
	binary.BigEndian.PutUint32(buf[off:], uint32(len(v.From)))
	off += 4
	copy(buf[off:], v.From)
	return buf, nil
}

func decodeVoteResponse(v *VoteResponse, data []byte) error {
	if len(data) < 13 {
		return fmt.Errorf("VoteResponse: short data %d", len(data))
	}
	off := 0
	v.Term = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	v.VoteGranted = data[off] == 1
	off++
	fromLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	if uint64(off)+uint64(fromLen) > uint64(len(data)) {
		return fmt.Errorf("VoteResponse: fromLen %d overflows data", fromLen)
	}
	v.From = NodeID(data[off : off+int(fromLen)])
	return nil
}

// --- AppendRequest ---
//
// Wire format:
//   Term            8 bytes
//   LeaderID len     4 bytes
//   LeaderID         len bytes
//   PrevLogIndex     8 bytes
//   PrevLogTerm      8 bytes
//   Entries len      4 bytes
//   Entries         len bytes
//   LeaderCommit     8 bytes
//   [DNSAddr len     2 bytes]  optional (F562); omitted when LeaderDNSAddr is ""
//   [DNSAddr         len bytes]
//
// The optional trailer is additive: decoders that predate it stop after
// LeaderCommit and ignore it; this decoder treats its absence as "".

// maxLeaderDNSAddrLen bounds LeaderDNSAddr on the wire (a host:port).
const maxLeaderDNSAddrLen = 255

func encodeAppendRequest(a AppendRequest) ([]byte, error) {
	entriesBytes, err := encodeEntrySlice(a.Entries)
	if err != nil {
		return nil, err
	}
	if len(a.LeaderDNSAddr) > maxLeaderDNSAddrLen {
		return nil, fmt.Errorf("AppendRequest: LeaderDNSAddr longer than %d bytes", maxLeaderDNSAddrLen)
	}
	size := 8 + 4 + len(a.LeaderID) + 8 + 8 + 4 + len(entriesBytes) + 8
	if a.LeaderDNSAddr != "" {
		size += 2 + len(a.LeaderDNSAddr)
	}
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(a.Term))
	off += 8
	binary.BigEndian.PutUint32(buf[off:], uint32(len(a.LeaderID)))
	off += 4
	copy(buf[off:], a.LeaderID)
	off += len(a.LeaderID)
	binary.BigEndian.PutUint64(buf[off:], uint64(a.PrevLogIndex))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], uint64(a.PrevLogTerm))
	off += 8
	binary.BigEndian.PutUint32(buf[off:], uint32(len(entriesBytes)))
	off += 4
	copy(buf[off:], entriesBytes)
	off += len(entriesBytes)
	binary.BigEndian.PutUint64(buf[off:], uint64(a.LeaderCommit))
	off += 8
	if a.LeaderDNSAddr != "" {
		binary.BigEndian.PutUint16(buf[off:], uint16(len(a.LeaderDNSAddr)))
		copy(buf[off+2:], a.LeaderDNSAddr)
	}
	return buf, nil
}

func decodeAppendRequest(a *AppendRequest, data []byte) error {
	if len(data) < 36 {
		return fmt.Errorf("AppendRequest: short data %d", len(data))
	}
	off := 0
	a.Term = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	leaderLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	if uint64(off)+uint64(leaderLen) > uint64(len(data)) {
		return fmt.Errorf("AppendRequest: leaderLen %d overflows data", leaderLen)
	}
	a.LeaderID = NodeID(data[off : off+int(leaderLen)])
	off += int(leaderLen)
	if off+20 > len(data) {
		return fmt.Errorf("AppendRequest: truncated after LeaderID")
	}
	a.PrevLogIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	a.PrevLogTerm = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	entriesLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	entriesEnd := off + int(entriesLen)
	if entriesEnd > len(data) || entriesEnd < off {
		return fmt.Errorf("AppendRequest: entries overflow")
	}
	if err := decodeEntrySlice(&a.Entries, data[off:entriesEnd]); err != nil {
		return err
	}
	off = entriesEnd
	// Trailing LeaderCommit. A peer that packs entriesLen to consume
	// every remaining byte would leave data[off:] empty, and the
	// Uint64 read below would panic with index-out-of-range — a
	// single-message DoS primitive against any Raft member.
	if off+8 > len(data) {
		return fmt.Errorf("AppendRequest: truncated LeaderCommit")
	}
	a.LeaderCommit = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	// Optional LeaderDNSAddr trailer (F562).
	a.LeaderDNSAddr = ""
	if rest := data[off:]; len(rest) > 0 {
		if len(rest) < 2 {
			return fmt.Errorf("AppendRequest: truncated LeaderDNSAddr length")
		}
		l := int(binary.BigEndian.Uint16(rest))
		if l > maxLeaderDNSAddrLen || 2+l > len(rest) {
			return fmt.Errorf("AppendRequest: LeaderDNSAddr length %d overflows data", l)
		}
		a.LeaderDNSAddr = string(rest[2 : 2+l])
	}
	return nil
}

// --- AppendResponse ---
//
// Wire format:
//   Term         8 bytes
//   Success      1 byte
//   From len     4 bytes
//   From         len bytes
//   MatchIndex   8 bytes
//   Commitment  8 bytes

func encodeAppendResponse(a AppendResponse) ([]byte, error) {
	size := 8 + 1 + 4 + len(a.From) + 8 + 8
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(a.Term))
	off += 8
	if a.Success {
		buf[off] = 1
	}
	off++
	binary.BigEndian.PutUint32(buf[off:], uint32(len(a.From)))
	off += 4
	copy(buf[off:], a.From)
	off += len(a.From)
	binary.BigEndian.PutUint64(buf[off:], uint64(a.MatchIndex))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], a.Commitment)
	return buf, nil
}

func decodeAppendResponse(a *AppendResponse, data []byte) error {
	if len(data) < 21 {
		return fmt.Errorf("AppendResponse: short data %d", len(data))
	}
	off := 0
	a.Term = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	a.Success = data[off] == 1
	off++
	fromLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	if uint64(off)+uint64(fromLen) > uint64(len(data)) {
		return fmt.Errorf("AppendResponse: fromLen %d overflows data", fromLen)
	}
	a.From = NodeID(data[off : off+int(fromLen)])
	off += int(fromLen)
	if off+16 > len(data) {
		return fmt.Errorf("AppendResponse: truncated trailing index fields")
	}
	a.MatchIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	a.Commitment = binary.BigEndian.Uint64(data[off:])
	return nil
}

// --- SnapshotRequest ---
//
// Wire format:
//   Term        8 bytes
//   LeaderID len 4 bytes
//   LeaderID    len bytes
//   Data len   8 bytes
//   Data       len bytes
//   LastIndex  8 bytes
//   LastTerm   8 bytes
//   [Offset    8 bytes]  only for a chunk (Total != 0)
//   [Total     8 bytes]  only for a chunk (Total != 0)

func encodeSnapshotRequest(s SnapshotRequest) ([]byte, error) {
	size := 8 + 4 + len(s.LeaderID) + 8 + len(s.Data) + 8 + 8
	if s.Total != 0 {
		size += 16
	}
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(s.Term))
	off += 8
	binary.BigEndian.PutUint32(buf[off:], uint32(len(s.LeaderID)))
	off += 4
	copy(buf[off:], s.LeaderID)
	off += len(s.LeaderID)
	binary.BigEndian.PutUint64(buf[off:], uint64(len(s.Data)))
	off += 8
	copy(buf[off:], s.Data)
	off += len(s.Data)
	binary.BigEndian.PutUint64(buf[off:], uint64(s.LastIndex))
	off += 8
	binary.BigEndian.PutUint64(buf[off:], uint64(s.LastTerm))
	if s.Total != 0 {
		off += 8
		binary.BigEndian.PutUint64(buf[off:], s.Offset)
		off += 8
		binary.BigEndian.PutUint64(buf[off:], s.Total)
	}
	return buf, nil
}

func decodeSnapshotRequest(s *SnapshotRequest, data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("SnapshotRequest: short data %d", len(data))
	}
	off := 0
	s.Term = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	leaderLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	if uint64(off)+uint64(leaderLen) > uint64(len(data)) {
		return fmt.Errorf("SnapshotRequest: leaderLen %d overflows data", leaderLen)
	}
	s.LeaderID = NodeID(data[off : off+int(leaderLen)])
	off += int(leaderLen)
	if off+8 > len(data) {
		return fmt.Errorf("SnapshotRequest: truncated at data length")
	}
	dataLen := binary.BigEndian.Uint64(data[off:])
	off += 8
	// Bound the snapshot payload — the outer frame already caps total
	// bytes at maxRPCMessageBytes, but a leader sending dataLen > MaxInt
	// would wrap int(dataLen) negative, fall through the dataEnd check,
	// and then \`make([]byte, dataLen)\` would request the full uint64
	// → OOM panic. Bound dataLen against the remaining buffer.
	if dataLen > uint64(len(data)-off) {
		return fmt.Errorf("SnapshotRequest: dataLen %d exceeds remaining %d", dataLen, len(data)-off)
	}
	dataEnd := off + int(dataLen)
	if dataEnd > len(data) || dataEnd < off {
		return fmt.Errorf("SnapshotRequest: data overflow")
	}
	s.Data = make([]byte, dataLen)
	copy(s.Data, data[off:dataEnd])
	off = dataEnd
	if off+16 > len(data) {
		return fmt.Errorf("SnapshotRequest: truncated trailing index fields")
	}
	s.LastIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	s.LastTerm = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	if len(data)-off >= 16 {
		s.Offset = binary.BigEndian.Uint64(data[off:])
		s.Total = binary.BigEndian.Uint64(data[off+8:])
		if s.Total == 0 {
			return fmt.Errorf("SnapshotRequest: chunk trailer with zero total")
		}
	}
	return nil
}

// --- entry slice ---
//
// Wire format:
//   Count 4 bytes
//   Each: index 8 + term 8 + type 1 + cmdLen 4 + cmdLen bytes + commitment 8

func encodeEntrySlice(entries []entry) ([]byte, error) {
	size := 4
	for _, e := range entries {
		size += 8 + 8 + 1 + 4 + len(e.Command) + 8
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[:], uint32(len(entries)))
	off := 4
	for _, e := range entries {
		binary.BigEndian.PutUint64(buf[off:], uint64(e.Index))
		off += 8
		binary.BigEndian.PutUint64(buf[off:], uint64(e.Term))
		off += 8
		buf[off] = byte(e.Type)
		off++
		binary.BigEndian.PutUint32(buf[off:], uint32(len(e.Command)))
		off += 4
		copy(buf[off:], e.Command)
		off += len(e.Command)
		binary.BigEndian.PutUint64(buf[off:], e.Commitment)
		off += 8
	}
	return buf, nil
}

func decodeEntrySlice(entries *[]entry, data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("entry slice: short header")
	}
	count := binary.BigEndian.Uint32(data[:4])
	off := 4
	// Bound count by remaining data. Each entry consumes at least 25
	// bytes (8 Index + 8 Term + 1 Type + 4 cmdLen + 0+ cmd + 8 Commitment).
	// A peer sending count = 2^32-1 with no actual entry bytes would
	// otherwise have us \`make([]entry, 0, count)\` — ~160 GB up front
	// for the ~40-byte entry struct — OOM-panic the Raft member.
	const minEntryBytes = 25
	maxPossible := uint32(len(data)-off) / minEntryBytes
	if count > maxPossible {
		return fmt.Errorf("entry slice: count %d exceeds possible %d in %d remaining bytes", count, maxPossible, len(data)-off)
	}
	*entries = make([]entry, 0, count)
	for i := uint32(0); i < count; i++ {
		if off+25 > len(data) {
			return fmt.Errorf("entry slice: entry %d overflow", i)
		}
		var e entry
		e.Index = Index(binary.BigEndian.Uint64(data[off:]))
		off += 8
		e.Term = Term(binary.BigEndian.Uint64(data[off:]))
		off += 8
		e.Type = EntryType(data[off])
		off++
		cmdLen := binary.BigEndian.Uint32(data[off:])
		off += 4
		// Bounds-check in uint64: on 32-bit platforms off+int(cmdLen)+8 (cmdLen
		// is uint32) can overflow int and wrap negative, bypassing the guard and
		// allowing a huge make()/out-of-bounds copy below (V15).
		if uint64(off)+uint64(cmdLen)+8 > uint64(len(data)) {
			return fmt.Errorf("entry slice: command %d overflow", i)
		}
		if cmdLen > 0 {
			e.Command = make([]byte, cmdLen)
			copy(e.Command, data[off:])
		}
		off += int(cmdLen)
		e.Commitment = binary.BigEndian.Uint64(data[off:])
		off += 8
		*entries = append(*entries, e)
	}
	return nil
}

// --- SnapshotResponse ---
//
// Wire format:
//   Term     8 bytes
//   Success  1 byte

func encodeSnapshotResponse(s SnapshotResponse) ([]byte, error) {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint64(buf[0:], uint64(s.Term))
	if s.Success {
		buf[8] = 1
	}
	return buf, nil
}

func decodeSnapshotResponse(s *SnapshotResponse, data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("SnapshotResponse: short data %d", len(data))
	}
	s.Term = Term(binary.BigEndian.Uint64(data[0:]))
	s.Success = data[8] == 1
	return nil
}
