// Package protocol provides DNS protocol primitives.
// This file implements RFC 8618 - Compacted DNS (C-DNS) Packet Capture Format.
// C-DNS provides a highly efficient binary format for DNS packet capture,
// significantly reducing storage requirements compared to pcap files.
package protocol

import (
	"fmt"
	"time"
)

// C-DNS Constants
const (
	// C-DNS Format Version
	CDNSVersionMajor = 1
	CDNSVersionMinor = 1

	// Block Parameters
	CDNSMaxBlockItems = 65536
)

// C-DNS OPCodes and RCODEs as compact identifiers
const (
	// OPCodes
	CDNSOpQuery        = 0
	CDNSOpIQuery       = 1
	CDNSOpStatus       = 2
	CDNSOpNotify       = 4
	CDNSOpUpdate       = 5

	// RCODEs (0-22 valid)
	CDNSRcodeNoError   = 0
	CDNSRcodeFormErr   = 1
	CDNSRcodeServFail  = 2
	CDNSRcodeNXDomain  = 3
	CDNSRcodeRefused   = 5
)

// C-DNS Storage Types
type CDNSStorageType uint8

const (
	CDNSTypeRef       CDNSStorageType = 0  // Reference to earlier entry
	CDNSTypeInline    CDNSStorageType = 1  // Inline value
	CDNSTypeMissing   CDNSStorageType = 2  // Not present
)

// CDNSQuerySignature represents the metadata for a DNS query/response pair.
type CDNSQuerySignature struct {
	// QR indicates if this is a query (0) or response (1)
	QR uint8

	// OPCode
	OPCode uint8

	// Flags
	AA bool // Authoritative Answer
	TC bool // Truncated
	RD bool // Recursion Desired
	RA bool // Recursion Available
	AD bool // Authentic Data
	CD bool // Checking Disabled

	// RDCODE (Response code for response, 0 for query)
	RDCODE uint8

	// Question type and class (for queries)
	QuestionType  uint16
	QuestionClass uint16

	// Query/Response timing (optional)
	QueryTime   uint32  // ms since start of block
	ResponseTime uint32  // ms since start of block

	// Query identifier
	ID uint16
}

// CDNSName represents a domain name in C-DNS format.
type CDNSName struct {
	// Labels are the domain name labels, stored with length bytes
	Labels []byte

	// Total length of the name
	Length uint8
}

// CDNSQuestion represents a question in C-DNS format.
type CDNSQuestion struct {
	Name    CDNSName
	Type    uint16
	Class   uint16
	// NameRaw is the raw wire-format name
	NameRaw []byte
}

// CDNSResourceRecord represents an RR in C-DNS format.
type CDNSResourceRecord struct {
	Name     CDNSName
	Type     uint16
	Class    uint16
	TTL      uint32
	RData    []byte
	NameRaw  []byte
}

// CDNSQueryResponse represents a query/response pair in C-DNS.
type CDNSQueryResponse struct {
	// Index into the Query/Response Signature array
	SignatureIndex uint32

	// Question (only for queries)
	Question *CDNSQuestion

	// Answer RRs (only for responses)
	Answers []CDNSResourceRecord

	// Authority RRs (only for responses)
	Authority []CDNSResourceRecord

	// Additional RRs
	Additional []CDNSResourceRecord

	// Timing information
	TimeOffset uint32 // milliseconds from block start
}

// CDNSBlock represents a block of C-DNS records.
type CDNSBlock struct {
	// Block preamble
	VersionMajor uint16
	VersionMinor uint16

	// Block metadata
	BlockParameters *CDNSBlockParameters

	// Block statistics
	BlockStatistics *CDNSBlockStatistics

	// Query/Response pairs
	QueryResponses []CDNSQueryResponse

	// Query signatures (shared across pairs)
	Signatures []CDNSQuerySignature

	// Question records
	Questions []CDNSQuestion

	// Resource records (shared across pairs)
	ResourceRecords []CDNSResourceRecord

	// Name records (shared across pairs)
	NameRecords []CDNSName
}

// CDNSBlockParameters contains parameters for a block.
type CDNSBlockParameters struct {
	// Storage parameters
	QueryResponseStorage    uint32
	QueryResponseExtraStorage uint32
	NameStorage             uint32
	RRStorage               uint32

	// Client address information present
	HasClientAddress    bool
	HasClientPort       bool

	// Server address information present
	HasServerAddress    bool
	HasServerPort       bool

	// Query/Response timing present
	HasQueryTime        bool
	HasResponseTime     bool

	// Original TTL present
	HasOriginalTTL      bool

	// Response sizes present
	HasResponseSize     bool

	// Query/Response signature present
	HasQuerySignature   bool
}

// CDNSBlockStatistics contains statistics for a block.
type CDNSBlockStatistics struct {
	// Number of queries in block
	QueryCount uint32

	// Number of responses in block
	ResponseCount uint32

	// Number of invalid records
	InvalidRecordCount uint32
}

// C-DNS File Format
type CDNSFile struct {
	// File header
	Magic     [8]byte
	Version   [4]byte
	FileParameters *CDNSFileParameters

	// Blocks
	Blocks []*CDNSBlock
}

// CDNSFileParameters contains file-level parameters.
type CDNSFileParameters struct {
	// Block parameters
	BlockParameters *CDNSBlockParameters

	// Storage hints
	StorageHints *CDNSStorageHints
}

// CDNSStorageHints provides storage hints for the file.
type CDNSStorageHints struct {
	// Maximum number of items in a block
	MaxBlockItems uint32

	// Maximum name length
	MaxNameLength uint8

	// Maximum RR data length
	MaxRRDataLength uint32
}

// CDNSFileHeaderMagic is the C-DNS file magic number
var CDNSFileHeaderMagic = [8]byte{0xC0, 0x4B, 0x19, 0x86, 0x4C, 0x6F, 0x4B, 0xC1}

// NewCDNSFile creates a new C-DNS file.
func NewCDNSFile() *CDNSFile {
	return &CDNSFile{
		Magic: CDNSFileHeaderMagic,
		Version: [4]byte{CDNSVersionMajor, CDNSVersionMinor, 0, 0},
		Blocks: make([]*CDNSBlock, 0),
	}
}

// NewCDNSBlock creates a new C-DNS block with default parameters.
func NewCDNSBlock() *CDNSBlock {
	return &CDNSBlock{
		VersionMajor: CDNSVersionMajor,
		VersionMinor: CDNSVersionMinor,
		BlockParameters: &CDNSBlockParameters{
			QueryResponseStorage:     0, // Ref
			QueryResponseExtraStorage: 0,
			NameStorage:              0, // Ref
			RRStorage:                0, // Ref
			HasClientAddress:        true,
			HasClientPort:           true,
			HasServerAddress:        true,
			HasServerPort:           true,
			HasQueryTime:            true,
			HasResponseTime:         true,
			HasOriginalTTL:          true,
			HasResponseSize:         true,
			HasQuerySignature:       true,
		},
		BlockStatistics: &CDNSBlockStatistics{},
		QueryResponses:  make([]CDNSQueryResponse, 0),
		Signatures:      make([]CDNSQuerySignature, 0),
		Questions:       make([]CDNSQuestion, 0),
		ResourceRecords: make([]CDNSResourceRecord, 0),
		NameRecords:     make([]CDNSName, 0),
	}
}

// AddQueryResponse adds a query/response pair to the block.
func (b *CDNSBlock) AddQueryResponse(qr *CDNSQueryResponse) error {
	if len(b.QueryResponses) >= CDNSMaxBlockItems {
		return fmt.Errorf("block has maximum number of items")
	}
	b.QueryResponses = append(b.QueryResponses, *qr)
	b.BlockStatistics.QueryCount++
	return nil
}

// AddSignature adds a query signature and returns its index.
func (b *CDNSBlock) AddSignature(sig CDNSQuerySignature) uint32 {
	b.Signatures = append(b.Signatures, sig)
	return uint32(len(b.Signatures) - 1)
}

// FindSignature finds a matching signature and returns its index, or adds it.
func (b *CDNSBlock) FindOrAddSignature(sig CDNSQuerySignature) uint32 {
	for i, s := range b.Signatures {
		if s.Equal(sig) {
			return uint32(i)
		}
	}
	return b.AddSignature(sig)
}

// Equal compares two query signatures for equality.
func (s *CDNSQuerySignature) Equal(other CDNSQuerySignature) bool {
	return s.QR == other.QR &&
		s.OPCode == other.OPCode &&
		s.AA == other.AA &&
		s.TC == other.TC &&
		s.RD == other.RD &&
		s.RA == other.RA &&
		s.AD == other.AD &&
		s.CD == other.CD &&
		s.RDCODE == other.RDCODE &&
		s.QuestionType == other.QuestionType &&
		s.QuestionClass == other.QuestionClass &&
		s.ID == other.ID
}

// CDNSMessage represents a DNS message converted to C-DNS format.
type CDNSMessage struct {
	// Timestamp of the message
	Timestamp time.Time

	// IP version and addresses
	IPVersion uint8 // 4 or 6
	SrcAddr   []byte
	DstAddr   []byte
	SrcPort   uint16
	DstPort   uint16

	// DNS message
	ID       uint16
	QR       bool
	OPCode   uint8
	AA       bool
	TC       bool
	RD       bool
	RA       bool
	AD       bool
	CD       bool
	RCODE    uint8

	// Questions
	Questions []CDNSQuestion

	// Answers
	Answers []CDNSResourceRecord

	// Authority
	Authority []CDNSResourceRecord

	// Additional
	Additional []CDNSResourceRecord
}

// ToQuerySignature converts a CDNSMessage to a query signature.
func (m *CDNSMessage) ToQuerySignature() CDNSQuerySignature {
	sig := CDNSQuerySignature{
		QR:      boolToUint8(m.QR),
		OPCode:  m.OPCode,
		AA:      m.AA,
		TC:      m.TC,
		RD:      m.RD,
		RA:      m.RA,
		AD:      m.AD,
		CD:      m.CD,
		ID:      m.ID,
	}

	if !m.QR && len(m.Questions) > 0 {
		sig.QuestionType = m.Questions[0].Type
		sig.QuestionClass = m.Questions[0].Class
	} else {
		sig.RDCODE = m.RCODE
	}

	return sig
}

// boolToUint8 converts a bool to uint8 (0 or 1).
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// CDNSBlockBuilder builds C-DNS blocks from DNS messages.
type CDNSBlockBuilder struct {
	block     *CDNSBlock
	startTime time.Time
}

// NewCDNSBlockBuilder creates a new C-DNS block builder.
func NewCDNSBlockBuilder() *CDNSBlockBuilder {
	return &CDNSBlockBuilder{
		block: NewCDNSBlock(),
	}
}

// StartBlock starts a new block with the given start time.
func (b *CDNSBlockBuilder) StartBlock(startTime time.Time) {
	b.block = NewCDNSBlock()
	b.startTime = startTime
}

// AddMessage adds a DNS message to the current block.
func (b *CDNSBlockBuilder) AddMessage(msg *CDNSMessage) error {
	qr := &CDNSQueryResponse{
		SignatureIndex: b.block.FindOrAddSignature(msg.ToQuerySignature()),
	}

	if !msg.QR {
		// Query - add question
		if len(msg.Questions) > 0 {
			qr.Question = &msg.Questions[0]
		}
	} else {
		// Response - add answers
		qr.Answers = msg.Answers
		qr.Authority = msg.Authority
	}

	// Calculate time offset
	if !msg.Timestamp.IsZero() && !b.startTime.IsZero() {
		qr.TimeOffset = uint32(msg.Timestamp.Sub(b.startTime).Milliseconds())
	}

	return b.block.AddQueryResponse(qr)
}

// GetBlock returns the current block.
func (b *CDNSBlockBuilder) GetBlock() *CDNSBlock {
	return b.block
}

// BlockSize returns the number of query/response pairs in the current block.
func (b *CDNSBlockBuilder) BlockSize() int {
	return len(b.block.QueryResponses)
}

// IsBlockFull returns true if the block has reached maximum size.
func (b *CDNSBlockBuilder) IsBlockFull() bool {
	return len(b.block.QueryResponses) >= CDNSMaxBlockItems
}

// CDNSFileBuilder builds C-DNS files from DNS messages.
type CDNSFileBuilder struct {
	file    *CDNSFile
	builder *CDNSBlockBuilder
}

// NewCDNSFileBuilder creates a new C-DNS file builder.
func NewCDNSFileBuilder() *CDNSFileBuilder {
	file := NewCDNSFile()
	return &CDNSFileBuilder{
		file:    file,
		builder: NewCDNSBlockBuilder(),
	}
}

// AddMessage adds a DNS message to the current block.
func (f *CDNSFileBuilder) AddMessage(msg *CDNSMessage) error {
	if f.builder.IsBlockFull() {
		// Finalize current block and start a new one
		f.file.Blocks = append(f.file.Blocks, f.builder.GetBlock())
		f.builder.StartBlock(msg.Timestamp)
	}
	return f.builder.AddMessage(msg)
}

// GetFile returns the C-DNS file with all blocks.
func (f *CDNSFileBuilder) GetFile() *CDNSFile {
	if len(f.file.Blocks) == 0 || f.builder.BlockSize() > 0 {
		f.file.Blocks = append(f.file.Blocks, f.builder.GetBlock())
	}
	return f.file
}

// FlattenReferences converts all references to inline values for export.
func (b *CDNSBlock) FlattenReferences() {
	// This would expand all Ref types to Inline types
	// for formats that don't support references
}

// CDNSStatistics holds overall C-DNS statistics.
type CDNSStatistics struct {
	// Total blocks processed
	BlockCount uint64

	// Total query/response pairs
	QueryResponseCount uint64

	// Total bytes in original pcap
	OriginalSize uint64

	// Total bytes in C-DNS format
	CompactedSize uint64
}

// CompressionRatio returns the compression ratio achieved.
func (s *CDNSStatistics) CompressionRatio() float64 {
	if s.OriginalSize == 0 {
		return 0
	}
	return float64(s.CompactedSize) / float64(s.OriginalSize)
}

// EstimateSize estimates the C-DNS block size in bytes.
func (b *CDNSBlock) EstimateSize() int {
	size := 0

	// Block header (simplified)
	size += 16 // version + parameters + stats

	// Signatures
	size += len(b.Signatures) * 16 // rough estimate per signature

	// Query/Responses
	size += len(b.QueryResponses) * 64 // rough estimate per QR pair

	return size
}
