package protocol

import (
	"fmt"
)

// Question represents a question in the question section of a DNS message.
// RFC 1035 §4.1.2
type Question struct {
	// Name is the domain name being queried.
	Name *Name

	// QType is the type of query (e.g., TypeA, TypeAAAA, TypeMX).
	QType uint16

	// QClass is the class of query (usually ClassIN).
	QClass uint16
}

// NewQuestion creates a new Question with the given name, type, and class.
func NewQuestion(name string, qtype, qclass uint16) (*Question, error) {
	n, err := ParseName(name)
	if err != nil {
		return nil, err
	}

	q := acquireQuestion()
	q.Name = n
	q.QType = qtype
	q.QClass = qclass
	return q, nil
}

// NewAQuestion creates a new Question for an A record query.
func NewAQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeA, ClassIN)
}

// NewAAAAQuestion creates a new Question for an AAAA record query.
func NewAAAAQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeAAAA, ClassIN)
}

// NewMXQuestion creates a new Question for an MX record query.
func NewMXQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeMX, ClassIN)
}

// NewNSQuestion creates a new Question for an NS record query.
func NewNSQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeNS, ClassIN)
}

// NewSOAQuestion creates a new Question for an SOA record query.
func NewSOAQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeSOA, ClassIN)
}

// NewTXTQuestion creates a new Question for a TXT record query.
func NewTXTQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeTXT, ClassIN)
}

// NewCNAMEQuestion creates a new Question for a CNAME record query.
func NewCNAMEQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeCNAME, ClassIN)
}

// NewPTRQuestion creates a new Question for a PTR record query.
func NewPTRQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypePTR, ClassIN)
}

// NewSRVQuestion creates a new Question for an SRV record query.
func NewSRVQuestion(name string) (*Question, error) {
	return NewQuestion(name, TypeSRV, ClassIN)
}

// WireLength returns the length of the question in wire format.
func (q *Question) WireLength() int {
	if q == nil || q.Name == nil {
		return 0
	}
	return q.Name.WireLength() + 4 // 2 bytes for QType + 2 bytes for QClass
}

// Pack serializes the question to wire format.
// Returns the number of bytes written.
func (q *Question) Pack(buf []byte, offset int, compression map[string]int) (int, error) {
	if q == nil {
		return 0, fmt.Errorf("nil question")
	}
	if q.Name == nil {
		return 0, fmt.Errorf("nil question name")
	}

	// Pack the name
	n, err := PackName(q.Name, buf, offset, compression)
	if err != nil {
		return 0, err
	}
	offset += n

	// Pack QType
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], q.QType)
	offset += 2

	// Pack QClass
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], q.QClass)
	offset += 2

	return offset - (offset - n - 4), nil
}

// Release returns the Question's pooled children (the Name wire buffer) to
// their pools.
func (q *Question) Release() {
	if q == nil {
		return
	}
	if q.Name != nil {
		q.Name.Release()
		q.Name = nil
	}
	q.QType = 0
	q.QClass = 0
	// Struct recycling removed: Release can run twice on one shared
	// *Question (reply()-style Questions-slice sharing between a response
	// and its query, both Released), and the double Put aliased the struct
	// across unrelated acquisitions. The struct is left to the GC; the
	// Name wire buffer is still recycled by Name.Release.
}

// Unpack deserializes a question from wire format.
// Returns the question and the number of bytes consumed.
func UnpackQuestion(buf []byte, offset int) (*Question, int, error) {
	// Unpack the name
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += n

	// Check bounds for QType and QClass
	if offset+4 > len(buf) {
		name.Release()
		return nil, 0, ErrBufferTooSmall
	}

	q := acquireQuestion()
	q.Name = name
	q.QType = Uint16(buf[offset:])
	offset += 2
	q.QClass = Uint16(buf[offset:])
	offset += 2

	return q, offset - (offset - n - 4), nil
}

// String returns a human-readable representation of the question.
func (q *Question) String() string {
	if q == nil {
		return "<nil question>"
	}
	classStr := ClassString(q.QClass)
	typeStr := TypeString(q.QType)
	name := "<nil>"
	if q.Name != nil {
		name = q.Name.String()
	}

	return fmt.Sprintf(";%s\t\t%s\t%s",
		name,
		classStr,
		typeStr,
	)
}

// Copy creates a deep copy of the question.
func (q *Question) Copy() *Question {
	if q == nil {
		return nil
	}

	var name *Name
	if q.Name != nil {
		name = q.Name.Copy()
	}

	copyQ := acquireQuestion()
	copyQ.Name = name
	copyQ.QType = q.QType
	copyQ.QClass = q.QClass
	return copyQ
}

// IsEDNS returns true if this is an EDNS (OPT) query.
func (q *Question) IsEDNS() bool {
	if q == nil {
		return false
	}
	return q.QType == TypeOPT
}

// IsClassANY returns true if this is an ANY class query.
func (q *Question) IsClassANY() bool {
	if q == nil {
		return false
	}
	return q.QClass == ClassANY
}

// MatchesType returns true if the question matches the given type.
// Handles TypeANY wildcard.
func (q *Question) MatchesType(qtype uint16) bool {
	if q == nil {
		return false
	}
	if q.QType == TypeANY {
		return true
	}
	return q.QType == qtype
}

// MatchesClass returns true if the question matches the given class.
// Handles ClassANY wildcard.
func (q *Question) MatchesClass(qclass uint16) bool {
	if q == nil {
		return false
	}
	if q.QClass == ClassANY {
		return true
	}
	return q.QClass == qclass
}
