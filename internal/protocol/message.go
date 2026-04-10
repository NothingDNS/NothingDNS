package protocol

import (
	"fmt"
)

// Message represents a complete DNS message (RFC 1035).
type Message struct {
	Header      Header
	Questions   []*Question
	Answers     []*ResourceRecord
	Authorities []*ResourceRecord
	Additionals []*ResourceRecord
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
	return !m.Header.Flags.QR
}

// IsResponse returns true if this is a response message.
func (m *Message) IsResponse() bool {
	return m.Header.Flags.QR
}

// SetResponse converts this message to a response with the given RCODE.
func (m *Message) SetResponse(rcode uint8) {
	m.Header.SetResponse(rcode)
}

// AddQuestion adds a question to the message.
func (m *Message) AddQuestion(q *Question) {
	m.Questions = append(m.Questions, q)
	m.Header.QDCount = uint16(len(m.Questions))
}

// AddAnswer adds an answer record to the message.
func (m *Message) AddAnswer(rr *ResourceRecord) {
	m.Answers = append(m.Answers, rr)
	m.Header.ANCount = uint16(len(m.Answers))
}

// AddAuthority adds an authority record to the message.
func (m *Message) AddAuthority(rr *ResourceRecord) {
	m.Authorities = append(m.Authorities, rr)
	m.Header.NSCount = uint16(len(m.Authorities))
}

// AddAdditional adds an additional record to the message.
func (m *Message) AddAdditional(rr *ResourceRecord) {
	m.Additionals = append(m.Additionals, rr)
	m.Header.ARCount = uint16(len(m.Additionals))
}

// GetOPT returns the OPT record from the additional section, or nil if not present.
func (m *Message) GetOPT() *ResourceRecord {
	for _, rr := range m.Additionals {
		if rr != nil && rr.Type == TypeOPT {
			return rr
		}
	}
	return nil
}

// SetEDNS0 adds an OPT record for EDNS0 support.
func (m *Message) SetEDNS0(udpPayloadSize uint16, do bool) {
	// Remove existing OPT record if present
	for i, rr := range m.Additionals {
		if rr.Type == TypeOPT {
			m.Additionals = append(m.Additionals[:i], m.Additionals[i+1:]...)
			break
		}
	}

	// Build the TTL field with DO bit and version 0
	ttl := BuildEDNSTTL(0, 0, do, 0)

	opt := &ResourceRecord{
		Name:  &Name{Labels: []string{}, FQDN: true}, // Root name for OPT
		Type:  TypeOPT,
		Class: udpPayloadSize, // UDP payload size goes in Class field
		TTL:   ttl,
		Data:  &RDataOPT{},
	}

	m.AddAdditional(opt)
}

// WireLength returns the total length of the message in wire format.
func (m *Message) WireLength() int {
	length := HeaderLen

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

// Pack serializes the DNS message to wire format.
func (m *Message) Pack(buf []byte) (int, error) {
	// Update header counts
	m.Header.QDCount = uint16(len(m.Questions))
	m.Header.ANCount = uint16(len(m.Answers))
	m.Header.NSCount = uint16(len(m.Authorities))
	m.Header.ARCount = uint16(len(m.Additionals))

	// Check buffer size
	if len(buf) < m.WireLength() {
		return 0, ErrBufferTooSmall
	}

	// Pack header
	if err := m.Header.Pack(buf[:HeaderLen]); err != nil {
		return 0, fmt.Errorf("packing header: %w", err)
	}
	offset := HeaderLen

	// Compression map for name compression
	compression := make(map[string]int)

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

// Unpack deserializes a DNS message from wire format.
func UnpackMessage(buf []byte) (*Message, error) {
	if len(buf) < HeaderLen {
		return nil, ErrBufferTooSmall
	}

	msg := &Message{}

	// Unpack header
	if err := msg.Header.Unpack(buf[:HeaderLen]); err != nil {
		return nil, fmt.Errorf("unpacking header: %w", err)
	}
	offset := HeaderLen

	// Unpack questions
	for i := 0; i < int(msg.Header.QDCount); i++ {
		if offset >= len(buf) {
			return nil, ErrBufferTooSmall
		}
		q, n, err := UnpackQuestion(buf, offset)
		if err != nil {
			return nil, fmt.Errorf("unpacking question %d: %w", i, err)
		}
		msg.Questions = append(msg.Questions, q)
		offset += n
	}

	// Unpack answers
	for i := 0; i < int(msg.Header.ANCount); i++ {
		if offset >= len(buf) {
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			return nil, fmt.Errorf("unpacking answer %d: %w", i, err)
		}
		msg.Answers = append(msg.Answers, rr)
		offset += n
	}

	// Unpack authorities
	for i := 0; i < int(msg.Header.NSCount); i++ {
		if offset >= len(buf) {
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			return nil, fmt.Errorf("unpacking authority %d: %w", i, err)
		}
		msg.Authorities = append(msg.Authorities, rr)
		offset += n
	}

	// Unpack additionals
	for i := 0; i < int(msg.Header.ARCount); i++ {
		if offset >= len(buf) {
			return nil, ErrBufferTooSmall
		}
		rr, n, err := UnpackResourceRecord(buf, offset)
		if err != nil {
			return nil, fmt.Errorf("unpacking additional %d: %w", i, err)
		}
		msg.Additionals = append(msg.Additionals, rr)
		offset += n
	}

	return msg, nil
}

// String returns a human-readable representation of the message (like dig output).
func (m *Message) String() string {
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
	msg := &Message{
		Header: *m.Header.Copy(),
	}

	for _, q := range m.Questions {
		msg.Questions = append(msg.Questions, q.Copy())
	}
	for _, rr := range m.Answers {
		msg.Answers = append(msg.Answers, rr.Copy())
	}
	for _, rr := range m.Authorities {
		msg.Authorities = append(msg.Authorities, rr.Copy())
	}
	for _, rr := range m.Additionals {
		msg.Additionals = append(msg.Additionals, rr.Copy())
	}

	return msg
}

// Clear removes all sections but keeps the header.
func (m *Message) Clear() {
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
	m.Header.ClearCounts()
}

// Truncate truncates the message to fit within the given size limit.
// Sets the TC bit if truncation occurred.
func (m *Message) Truncate(maxSize int) {
	if m.WireLength() <= maxSize {
		return
	}

	// Try removing additional records first
	for len(m.Additionals) > 0 && m.WireLength() > maxSize {
		m.Additionals = m.Additionals[:len(m.Additionals)-1]
	}
	m.Header.ARCount = uint16(len(m.Additionals))

	if m.WireLength() <= maxSize {
		return
	}

	// Try removing authority records
	for len(m.Authorities) > 0 && m.WireLength() > maxSize {
		m.Authorities = m.Authorities[:len(m.Authorities)-1]
	}
	m.Header.NSCount = uint16(len(m.Authorities))

	if m.WireLength() <= maxSize {
		return
	}

	// Try removing answer records
	for len(m.Answers) > 0 && m.WireLength() > maxSize {
		m.Answers = m.Answers[:len(m.Answers)-1]
	}
	m.Header.ANCount = uint16(len(m.Answers))

	// If we still don't fit, set TC bit
	if m.WireLength() > maxSize {
		m.Header.SetTruncated(true)
	}
}
