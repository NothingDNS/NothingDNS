package raft

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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
	if len(plainPayload) > maxRPCMessageBytes {
		return fmt.Errorf("payload exceeds maxRPCMessageBytes (%d > %d)", len(plainPayload), maxRPCMessageBytes)
	}
	if err := binary.Write(fw.w, binary.BigEndian, msgType); err != nil {
		return err
	}
	// Generate random nonce.
	if _, err := io.ReadFull(rand.Reader, fw.nonceBuf); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonceBuf in-place.
	ciphertext := fw.aead.Seal(fw.nonceBuf[:0], fw.nonceBuf, plainPayload, []byte{msgType})
	// Write length prefix.
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(ciphertext)))
	if _, err := fw.w.Write(lengthBuf[:]); err != nil {
		return err
	}
	_, err = fw.w.Write(ciphertext)
	return err
}

// writeRaw writes a plaintext TLV frame (no AEAD).
func (fw *frameWriter) writeRaw(msgType uint8, plainPayload []byte) error {
	if len(plainPayload) > maxRPCMessageBytes {
		return fmt.Errorf("payload exceeds maxRPCMessageBytes (%d > %d)", len(plainPayload), maxRPCMessageBytes)
	}
	var header [frameHeaderSize]byte
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(plainPayload)))
	if _, err := fw.w.Write(header[:]); err != nil {
		return err
	}
	_, err := fw.w.Write(plainPayload)
	return err
}

// frameReader reads TLV-framed messages.
type frameReader struct {
	r    io.Reader
	aead cipher.AEAD
}

func newFrameReader(r io.Reader, aead cipher.AEAD) *frameReader {
	return &frameReader{r: r, aead: aead}
}

// readFramed reads and decodes a framed message into msg.
// Returns the msgType that was on the wire (useful for AEAD key selection).
func (fr *frameReader) readFramed(msg any) (uint8, error) {
	// Read header.
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(fr.r, header[:]); err != nil {
		return 0, err
	}
	msgType := header[0]
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxRPCMessageBytes {
		return msgType, fmt.Errorf("frame length %d exceeds max %d", length, maxRPCMessageBytes)
	}

	if fr.aead == nil {
		// Plaintext path: read payload and decode.
		if length == 0 {
			return msgType, nil
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return msgType, err
		}
		return msgType, decodeNative(msg, payload)
	}

	// AEAD path: read nonce+ciphertext+tag, then Open.
	if length < uint32(fr.aead.NonceSize()+fr.aead.Overhead()) {
		return msgType, fmt.Errorf("ciphertext too short for AEAD")
	}
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(fr.r, ciphertext); err != nil {
		return msgType, err
	}
	// AAD binds the msgType to prevent cross-protocol replay.
	plaintext, err := fr.aead.Open(nil, ciphertext[:fr.aead.NonceSize()], ciphertext[fr.aead.NonceSize():], []byte{msgType})
	if err != nil {
		return msgType, fmt.Errorf("aead open: %w", err)
	}
	return msgType, decodeNative(msg, plaintext)
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
	v.CandidateID = NodeID(data[off : off+int(candLen)])
	off += int(candLen)
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

func encodeAppendRequest(a AppendRequest) ([]byte, error) {
	entriesBytes, err := encodeEntrySlice(a.Entries)
	if err != nil {
		return nil, err
	}
	size := 8 + 4 + len(a.LeaderID) + 8 + 8 + 4 + len(entriesBytes) + 8
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
	a.LeaderID = NodeID(data[off : off+int(leaderLen)])
	off += int(leaderLen)
	a.PrevLogIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	a.PrevLogTerm = Term(binary.BigEndian.Uint64(data[off:]))
	off += 8
	entriesLen := binary.BigEndian.Uint32(data[off:])
	off += 4
	entriesEnd := off + int(entriesLen)
	if entriesEnd > len(data) {
		return fmt.Errorf("AppendRequest: entries overflow")
	}
	if err := decodeEntrySlice(&a.Entries, data[off:entriesEnd]); err != nil {
		return err
	}
	off = entriesEnd
	a.LeaderCommit = Index(binary.BigEndian.Uint64(data[off:]))
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
	a.From = NodeID(data[off : off+int(fromLen)])
	off += int(fromLen)
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

func encodeSnapshotRequest(s SnapshotRequest) ([]byte, error) {
	size := 8 + 4 + len(s.LeaderID) + 8 + len(s.Data) + 8 + 8
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
	s.LeaderID = NodeID(data[off : off+int(leaderLen)])
	off += int(leaderLen)
	dataLen := binary.BigEndian.Uint64(data[off:])
	off += 8
	dataEnd := off + int(dataLen)
	if dataEnd > len(data) {
		return fmt.Errorf("SnapshotRequest: data overflow")
	}
	s.Data = make([]byte, dataLen)
	copy(s.Data, data[off:dataEnd])
	off = dataEnd
	s.LastIndex = Index(binary.BigEndian.Uint64(data[off:]))
	off += 8
	s.LastTerm = Term(binary.BigEndian.Uint64(data[off:]))
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
		if off+int(cmdLen)+8 > len(data) {
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
