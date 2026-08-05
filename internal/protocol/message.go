package protocol

import (
	"fmt"
	"sync"
)

// Maximum number of records per section to prevent memory exhaustion DoS.
// RFC 1035 allows up to 65535 per section, but real-world DNS never exceeds ~100.
// These limits are enforced during wire format unpacking.
const (
	MaxQuestions   = 256
	MaxAnswers     = 512
	MaxAuthorities = 512
	MaxAdditionals = 512
	MaxRecords     = MaxQuestions + MaxAnswers + MaxAuthorities + MaxAdditionals
)

// Message represents a complete DNS message (RFC 1035).
//
// RawBody is only populated for DSO messages (OPCODE 6, RFC 8490 §5.2),
// whose body is an opaque TLV stream sitting directly after the header
// rather than the conventional Question / Answer / Authority / Additional
// sections. For all other opcodes RawBody is nil.
type Message struct {
	Header      Header
	Questions   []*Question
	Answers     []*ResourceRecord
	Authorities []*ResourceRecord
	Additionals []*ResourceRecord

	// RawBody is the byte slice of the DSO TLV stream (header excluded).
	// Populated by UnpackMessage when Header.Flags.Opcode == OpcodeDSO.
	RawBody []byte
}

// NewMessage creates a new DNS message with the given header.
func NewMessage(header Header) *Message {
	return &Message{
		Header:      header,
		Questions:   make([]*Question, 0),
		Answers:     make([]*ResourceRecord, 0),
		Authorities: make([]*ResourceRecord, 0),
		Additionals: make([]*ResourceRecord, 0),
	}
}

// NewQuery creates a new DNS query message.
func NewQuery(id uint16, name string, qtype uint16) (*Message, error) {
	msg := &Message{
		Header: Header{
			ID:      id,
			Flags:   NewQueryFlags(),
			QDCount: 1,
		},
		Questions:   make([]*Question, 0, 1),
		Answers:     make([]*ResourceRecord, 0),
		Authorities: make([]*ResourceRecord, 0),
		Additionals: make([]*ResourceRecord, 0),
	}

	q, err := NewQuestion(name, qtype, ClassIN)
	if err != nil {
		return nil, err
	}
	msg.Questions = append(msg.Questions, q)

	return msg, nil
}

// IsQuery returns true if this is a query message.
func (m *Message) IsQuery() bool {
	if m == nil {
		return false
	}
	return !m.Header.Flags.QR
}

// IsResponse returns true if this is a response message.
func (m *Message) IsResponse() bool {
	if m == nil {
		return false
	}
	return m.Header.Flags.QR
}

// SetResponse converts this message to a response with the given RCODE.
func (m *Message) SetResponse(rcode uint8) {
	if m == nil {
		return
	}
	m.Header.SetResponse(rcode)
}

// AddQuestion adds a question to the message.
func (m *Message) AddQuestion(q *Question) {
	if m == nil {
		return
	}
	m.Questions = append(m.Questions, q)
	m.Header.QDCount = uint16(len(m.Questions))
}

// AddAnswer adds an answer record to the message.
func (m *Message) AddAnswer(rr *ResourceRecord) {
	if m == nil {
		return
	}
	m.Answers = append(m.Answers, rr)
	m.Header.ANCount = uint16(len(m.Answers))
}

// AddAuthority adds an authority record to the message.
func (m *Message) AddAuthority(rr *ResourceRecord) {
	if m == nil {
		return
	}
	m.Authorities = append(m.Authorities, rr)
	m.Header.NSCount = uint16(len(m.Authorities))
}

// AddAdditional adds an additional record to the message.
func (m *Message) AddAdditional(rr *ResourceRecord) {
	if m == nil {
		return
	}
	m.Additionals = append(m.Additionals, rr)
	m.Header.ARCount = uint16(len(m.Additionals))
}

// GetOPT returns the OPT record from the additional section, or nil if not present.
func (m *Message) GetOPT() *ResourceRecord {
	if m == nil {
		return nil
	}
	for _, rr := range m.Additionals {
		if rr != nil && rr.Type == TypeOPT {
			return rr
		}
	}
	return nil
}

// SetEDNS0 adds an OPT record for EDNS0 support.
func (m *Message) SetEDNS0(udpPayloadSize uint16, do bool) {
	if m == nil {
		return
	}
	// Remove invalid entries and existing OPT records before appending the new one.
	additionals := m.Additionals[:0]
	for _, rr := range m.Additionals {
		if rr == nil || rr.Type == TypeOPT {
			continue
		}
		additionals = append(additionals, rr)
	}
	m.Additionals = additionals

	// Build the TTL field with DO bit and version 0
	ttl := BuildEDNSTTL(0, 0, do, 0)

	opt := &ResourceRecord{
		Name:  NewName([]string{}, true), // Root name for OPT
		Type:  TypeOPT,
		Class: udpPayloadSize, // UDP payload size goes in Class field
		TTL:   ttl,
		Data:  &RDataOPT{},
	}

	m.AddAdditional(opt)
}

// WireLength returns the total length of the message in wire format.
func (m *Message) WireLength() int {
	if m == nil {
		return 0
	}
	length := HeaderLen
	if m.Header.Flags.Opcode == OpcodeDSO {
		return length + len(m.RawBody)
	}

	for _, q := range m.Questions {
		length += q.WireLength()
	}
	for _, rr := range m.Answers {
		length += rr.WireLength()
	}
	for _, rr := range m.Authorities {
		length += rr.WireLength()
	}
	for _, rr := range m.Additionals {
		length += rr.WireLength()
	}

	return length
}

// compressionPool reuses compression maps across Pack calls to avoid allocation.
var compressionPool = sync.Pool{
	New: func() any {
		return make(map[string]int, 16)
	},
}

// messagePool reuses *Message instances across UnpackMessage calls. The
// pre-allocated section slices stay attached to the Message between uses
// so their backing arrays are reused, eliminating slice allocs as well as
// the *Message alloc when callers Release() after handling. Capacities
// reflect typical DNS responses: 1 question, a few answers, a small
// authority section, and 1 additional (often the OPT record).
var messagePool = sync.Pool{
	New: func() any {
		return &Message{
			Questions:   make([]*Question, 0, 1),
			Answers:     make([]*ResourceRecord, 0, 4),
			Authorities: make([]*ResourceRecord, 0, 2),
			Additionals: make([]*ResourceRecord, 0, 1),
		}
	},
}

// Release returns the Message to the internal pool so its struct and
// section-slice backing arrays can be reused by a future UnpackMessage.
// After calling Release the Message and any sub-objects (Questions,
// Answers, Authorities, Additionals, and their nested Names/RData) MUST
// NOT be accessed — the pointers may be reissued to a different request.
//
// If the Message (or parts of it) outlives the request — e.g. cached or
// queued for later — call Copy() before Release(). It's safe to call
// Release on a nil Message.
//
// Phase 3A: only the *Message and its section-slice backing arrays are
// pooled. Per-record structs (Question, ResourceRecord, Name, label
// slices, RData) still allocate fresh on Unpack and are reclaimed by GC
// after Release nils them in the slice.
func (m *Message) Release() {
	if m == nil {
		return
	}
	for i := range m.Questions {
		if m.Questions[i] != nil {
			m.Questions[i].Release()
			m.Questions[i] = nil
		}
	}
	m.Questions = m.Questions[:0]
	for i := range m.Answers {
		if m.Answers[i] != nil {
			m.Answers[i].Release()
			m.Answers[i] = nil
		}
	}
	m.Answers = m.Answers[:0]
	for i := range m.Authorities {
		if m.Authorities[i] != nil {
			m.Authorities[i].Release()
			m.Authorities[i] = nil
		}
	}
	m.Authorities = m.Authorities[:0]
	for i := range m.Additionals {
		if m.Additionals[i] != nil {
			m.Additionals[i].Release()
			m.Additionals[i] = nil
		}
	}
	m.Additionals = m.Additionals[:0]
	m.Header = Header{}
	// Clear the DSO body reference so a Released-but-not-yet-Reused
	// message in the pool doesn't keep a (potentially large) TLV
	// stream alive. UnpackMessage also nils this on each Get, but
	// nil-on-Release is the right symmetric place for it — the
	// window between Put and Get can be arbitrarily long under
	// light load.
	m.RawBody = nil
	messagePool.Put(m)
}

// Pack serializes the DNS message to wire format.
func (m *Message) Pack(buf []byte) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("nil message")
	}
	// Update header counts
	if err := m.updateHeaderCounts(); err != nil {
		return 0, err
	}

	// Check buffer size
	if len(buf) < m.WireLength() {
		return 0, ErrBufferTooSmall
	}

	// Pack header
	if err := m.Header.Pack(buf[:HeaderLen]); err != nil {
		return 0, fmt.Errorf("packing header: %w", err)
	}
	offset := HeaderLen
	if m.Header.Flags.Opcode == OpcodeDSO {
		copy(buf[offset:], m.RawBody)
		return offset + len(m.RawBody), nil
	}

	// Compression map for name compression (pooled to avoid per-call allocation)
	compression := compressionPool.Get().(map[string]int)
	defer func() {
		clear(compression)
		compressionPool.Put(compression)
	}()

	// Pack questions
	for _, q := range m.Questions {
		n, err := q.Pack(buf, offset, compression)
		if err != nil {
			return 0, fmt.Errorf("packing question: %w", err)
		}
		offset += n
	}

	// Pack answers
	for _, rr := range m.Answers {
		n, err := rr.Pack(buf, offset, compression)
		if err != nil {
			return 0, fmt.Errorf("packing answer: %w", err)
		}
		offset += n
	}

	// Pack authorities
	for _, rr := range m.Authorities {
		n, err := rr.Pack(buf, offset, compression)
		if err != nil {
			return 0, fmt.Errorf("packing authority: %w", err)
		}
		offset += n
	}

	// Pack additionals
	for _, rr := range m.Additionals {
		n, err := rr.Pack(buf, offset, compression)
		if err != nil {
			return 0, fmt.Errorf("packing additional: %w", err)
		}
		offset += n
	}

	return offset, nil
}

func (m *Message) updateHeaderCounts() error {
	if m == nil {
		return fmt.Errorf("nil message")
	}
	if m.Header.Flags.Opcode == OpcodeDSO {
		m.Header.QDCount = 0
		m.Header.ANCount = 0
		m.Header.NSCount = 0
		m.Header.ARCount = 0
		return nil
	}
	if err := validateQuestionsForPack(m.Questions); err != nil {
		return err
	}
	if err := validateResourceRecordsForPack("answer", m.Answers); err != nil {
		return err
	}
	if err := validateResourceRecordsForPack("authority", m.Authorities); err != nil {
		return err
	}
	if err := validateResourceRecordsForPack("additional", m.Additionals); err != nil {
		return err
	}

	qd, err := sectionCount("questions", len(m.Questions))
	if err != nil {
		return err
	}
	an, err := sectionCount("answers", len(m.Answers))
	if err != nil {
		return err
	}
	ns, err := sectionCount("authorities", len(m.Authorities))
	if err != nil {
		return err
	}
	ar, err := sectionCount("additionals", len(m.Additionals))
	if err != nil {
		return err
	}
	m.Header.QDCount = qd
	m.Header.ANCount = an
	m.Header.NSCount = ns
	m.Header.ARCount = ar
	return nil
}

func sectionCount(section string, n int) (uint16, error) {
	if n > 0xffff {
		return 0, fmt.Errorf("too many %s: %d (max 65535)", section, n)
	}
	return uint16(n), nil
}

func validateQuestionsForPack(questions []*Question) error {
	for i, q := range questions {
		if q == nil {
			return fmt.Errorf("nil question at index %d", i)
		}
		if q.Name == nil {
			return fmt.Errorf("nil question name at index %d", i)
		}
	}
	return nil
}

func validateResourceRecordsForPack(section string, records []*ResourceRecord) error {
	for i, rr := range records {
		if rr == nil {
			return fmt.Errorf("nil %s record at index %d", section, i)
		}
		if rr.Name == nil {
			return fmt.Errorf("nil %s record name at index %d", section, i)
		}
		if isNilRData(rr.Data) {
			return fmt.Errorf("nil %s record data at index %d", section, i)
		}
	}
	return nil
}

// Unpack deserializes a DNS message from wire format. The returned
// Message is drawn from a sync.Pool; callers that no longer need the
// Message after handling SHOULD call (*Message).Release() to return it
// to the pool. Failure to Release just falls back to GC reclamation —
// no leak, only a missed pooling opportunity.
func UnpackMessage(buf []byte) (*Message, error) {
	if len(buf) < HeaderLen {
		return nil, ErrBufferTooSmall
	}

	msg := messagePool.Get().(*Message)
	msg.RawBody = nil

	// Unpack header
	if err := msg.Header.Unpack(buf[:HeaderLen]); err != nil {
		msg.Release()
		return nil, fmt.Errorf("unpacking header: %w", err)
	}
	offset := HeaderLen

	// RFC 8490 §5.2: DSO messages do not use the conventional QD/AN/NS/AR
	// sections. The body that follows the header is an opaque TLV stream.
	// Capture it as RawBody and return early; section counts MUST be zero
	// for a conformant DSO message but we don't enforce that here — strict
	// validation is the DSO layer's responsibility.
	if msg.Header.Flags.Opcode == OpcodeDSO {
		if len(buf) > HeaderLen {
			body := make([]byte, len(buf)-HeaderLen)
			copy(body, buf[HeaderLen:])
			msg.RawBody = body
		}
		return msg, nil
	}

	// Pooled section slices already exist (zero-length, with backing array
	// from the previous Release or the pool's New func). append() grows
	// them as needed; no per-call slice allocation in the steady state.

	// Unpack questions
	if int(msg.Header.QDCount) > MaxQuestions {
		msg.Release()
		return nil, fmt.Errorf("too many questions: %d (max %d)", msg.Header.QDCount, MaxQuestions)
	}
	for i := 0; i < int(msg.Header.QDCount); i++ {
		if offset >= len(buf) {
			msg.Release()
			return nil, ErrBufferTooSmall
		}
		q, n, err := UnpackQuestion(buf, offset)
		if err != nil {
			msg.Release()
			return nil, fmt.Errorf("unpacking question %d: %w", i, err)
		}
		msg.Questions = append(msg.Questions, q)
		offset += n
	}

	// Unpack answers
	if int(msg.Header.ANCount) > MaxAnswers {
		msg.Release()
		return nil, fmt.Errorf("too many answer records: %d (max %d)", msg.Header.ANCount, MaxAnswers)
	}
	for i := 0; i < int(msg.Header.ANCount); i++ {
		if offset >= len(buf) {
			msg.Release()
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			msg.Release()
			return nil, fmt.Errorf("unpacking answer %d: %w", i, err)
		}
		msg.Answers = append(msg.Answers, rr)
		offset += n
	}

	// Unpack authorities
	if int(msg.Header.NSCount) > MaxAuthorities {
		msg.Release()
		return nil, fmt.Errorf("too many authority records: %d (max %d)", msg.Header.NSCount, MaxAuthorities)
	}
	for i := 0; i < int(msg.Header.NSCount); i++ {
		if offset >= len(buf) {
			msg.Release()
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			msg.Release()
			return nil, fmt.Errorf("unpacking authority %d: %w", i, err)
		}
		msg.Authorities = append(msg.Authorities, rr)
		offset += n
	}

	// Unpack additionals
	if int(msg.Header.ARCount) > MaxAdditionals {
		msg.Release()
		return nil, fmt.Errorf("too many additional records: %d (max %d)", msg.Header.ARCount, MaxAdditionals)
	}
	for i := 0; i < int(msg.Header.ARCount); i++ {
		if offset >= len(buf) {
			msg.Release()
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			msg.Release()
			return nil, fmt.Errorf("unpacking additional %d: %w", i, err)
		}
		msg.Additionals = append(msg.Additionals, rr)
		offset += n
	}

	return msg, nil
}

// String returns a human-readable representation of the message (like dig output).
func (m *Message) String() string {
	if m == nil {
		return "<nil message>"
	}
	result := m.Header.String() + "\n"

	// Questions
	if len(m.Questions) > 0 {
		result += "\n;; QUESTION SECTION:\n"
		for _, q := range m.Questions {
			result += q.String() + "\n"
		}
	}

	// Answers
	if len(m.Answers) > 0 {
		result += "\n;; ANSWER SECTION:\n"
		for _, rr := range m.Answers {
			result += rr.String() + "\n"
		}
	}

	// Authorities
	if len(m.Authorities) > 0 {
		result += "\n;; AUTHORITY SECTION:\n"
		for _, rr := range m.Authorities {
			result += rr.String() + "\n"
		}
	}

	// Additionals
	if len(m.Additionals) > 0 {
		result += "\n;; ADDITIONAL SECTION:\n"
		for _, rr := range m.Additionals {
			result += rr.String() + "\n"
		}
	}

	return result
}

// Copy creates a deep copy of the message.
func (m *Message) Copy() *Message {
	if m == nil {
		return nil
	}
	msg := &Message{
		Header: *m.Header.Copy(),
	}
	if len(m.RawBody) > 0 {
		msg.RawBody = append([]byte(nil), m.RawBody...)
	}

	for _, q := range m.Questions {
		if q != nil {
			msg.Questions = append(msg.Questions, q.Copy())
		}
	}
	for _, rr := range m.Answers {
		if rr != nil {
			msg.Answers = append(msg.Answers, rr.Copy())
		}
	}
	for _, rr := range m.Authorities {
		if rr != nil {
			msg.Authorities = append(msg.Authorities, rr.Copy())
		}
	}
	for _, rr := range m.Additionals {
		if rr != nil {
			msg.Additionals = append(msg.Additionals, rr.Copy())
		}
	}

	return msg
}

// Clear removes all sections but keeps the header.
func (m *Message) Clear() {
	if m == nil {
		return
	}
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
	m.Header.ClearCounts()
}

// Truncate truncates the message to fit within the given size limit.
//
// Per RFC 2181 §9 the TC bit means that *required* data was omitted, so it
// is set only when records are removed from the Answer or Authority
// sections (or the message still does not fit after removing everything).
// Dropping Additional-section records (OPT, glue, ...) alone does not set
// TC. Removal is always on whole-record boundaries.
func (m *Message) Truncate(maxSize int) {
	if m == nil {
		return
	}
	currentLength := m.WireLength()
	if currentLength <= maxSize {
		return
	}

	removeLast := func(records []*ResourceRecord) []*ResourceRecord {
		last := len(records) - 1
		if records[last] != nil {
			currentLength -= records[last].WireLength()
		}
		return records[:last]
	}

	// Try removing additional records first. These are optional data, so
	// dropping them does not set the TC bit (RFC 2181 §9).
	for len(m.Additionals) > 0 && currentLength > maxSize {
		m.Additionals = removeLast(m.Additionals)
	}
	m.Header.ARCount = uint16(len(m.Additionals))

	if currentLength <= maxSize {
		return
	}

	truncated := false

	// Try removing authority records.
	for len(m.Authorities) > 0 && currentLength > maxSize {
		m.Authorities = removeLast(m.Authorities)
		truncated = true
	}
	m.Header.NSCount = uint16(len(m.Authorities))

	if currentLength <= maxSize {
		if truncated {
			m.Header.SetTruncated(true)
		}
		return
	}

	// Try removing answer records.
	for len(m.Answers) > 0 && currentLength > maxSize {
		m.Answers = removeLast(m.Answers)
		truncated = true
	}
	m.Header.ANCount = uint16(len(m.Answers))

	// If required records were removed or we still do not fit, set TC bit.
	if truncated || currentLength > maxSize {
		m.Header.SetTruncated(true)
	}
}
