package geodns

// MaxMind DB binary format parser.
//
// Reference: https://maxmind.github.io/MaxMind-DB/
//
// File layout, from offset 0:
//
//	+-------------------------+
//	| binary search tree       |  node_count nodes, each 2*record_size/8 bytes
//	+-------------------------+
//	| 16 zero bytes (separator)|
//	+-------------------------+
//	| data section             |  variable-length typed records
//	+-------------------------+
//	| 0xab 0xcd 0xef           |  metadata marker ("MaxMind.com")
//	| metadata (typed map)     |
//	+-------------------------+
//
// Each tree node holds two records of record_size bits (24, 28, or 32).
// A record value of node_count means "no data found"; any value greater
// than node_count is a data-section offset relative to the *end* of the
// tree + 16-byte separator; values below node_count are child-node
// indices used to descend further.

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

// mmdbDecodeError indicates a malformed MaxMind DB file.
type mmdbDecodeError struct {
	msg string
}

func (e *mmdbDecodeError) Error() string { return "geodns/mmdb: " + e.msg }

// MaxMind type codes (RFC §3.3, "Output Data Section").
const (
	mmdbTypeExtended  = 0
	mmdbTypePointer   = 1
	mmdbTypeUTF8      = 2
	mmdbTypeDouble    = 3
	mmdbTypeBytes     = 4
	mmdbTypeUint16    = 5
	mmdbTypeUint32    = 6
	mmdbTypeMap       = 7
	mmdbTypeInt32     = 8
	mmdbTypeUint64    = 9
	mmdbTypeUint128   = 10
	mmdbTypeArray     = 11
	mmdbTypeContainer = 12
	mmdbTypeEndMarker = 13
	mmdbTypeBoolean   = 14
	mmdbTypeFloat     = 15
)

// mmdbMaxPrealloc caps the capacity preallocated for an MMDB map or array;
// larger containers grow as their entries are decoded (F874).
const mmdbMaxPrealloc = 64

// mmdbDecoder reads typed values from a MMDB data section. The data
// section bytes are the *whole file* — the decoder is given absolute
// offsets and an explicit data-section start so that pointer arithmetic
// (relative to the section base) works correctly.
type mmdbDecoder struct {
	buf       []byte
	dataStart int // first byte of the data section (== treeSize + 16)
}

// readControlByte returns the type tag and the payload size (in bytes,
// or the count for maps/arrays) starting at offset. It advances offset
// past any size extension bytes.
func (d *mmdbDecoder) readControlByte(offset int) (typeCode, size, newOff int, err error) {
	if offset >= len(d.buf) {
		return 0, 0, 0, &mmdbDecodeError{"control byte past end of buffer"}
	}
	ctrl := d.buf[offset]
	offset++

	typeCode = int(ctrl >> 5)
	if typeCode == mmdbTypeExtended {
		if offset >= len(d.buf) {
			return 0, 0, 0, &mmdbDecodeError{"extended type past end of buffer"}
		}
		typeCode = int(d.buf[offset]) + 7
		offset++
	}

	size = int(ctrl & 0x1f)
	// Pointers encode their size in the top bits; size handling is
	// done inside decodePointer, not here.
	if typeCode == mmdbTypePointer {
		return typeCode, size, offset, nil
	}

	switch {
	case size < 29:
		// size is the literal payload length
	case size == 29:
		if offset >= len(d.buf) {
			return 0, 0, 0, &mmdbDecodeError{"size29 extension past end"}
		}
		size = 29 + int(d.buf[offset])
		offset++
	case size == 30:
		if offset+2 > len(d.buf) {
			return 0, 0, 0, &mmdbDecodeError{"size30 extension past end"}
		}
		size = 285 + int(binary.BigEndian.Uint16(d.buf[offset:offset+2]))
		offset += 2
	case size == 31:
		if offset+3 > len(d.buf) {
			return 0, 0, 0, &mmdbDecodeError{"size31 extension past end"}
		}
		size = 65821 + int(uint32(d.buf[offset])<<16|uint32(d.buf[offset+1])<<8|uint32(d.buf[offset+2]))
		offset += 3
	}
	return typeCode, size, offset, nil
}

// decodePointer interprets a pointer control byte (top 3 bits = 1).
// The size sub-field selects the pointer encoding format. Returns the
// absolute byte offset within d.buf that the pointer references and
// the offset of the first byte after the pointer payload.
func (d *mmdbDecoder) decodePointer(ctrl byte, offset int) (target, newOff int, err error) {
	pSize := int((ctrl >> 3) & 0x3)
	low := int(ctrl & 0x7)
	switch pSize {
	case 0:
		// 11-bit pointer (low 3 bits + next byte)
		if offset >= len(d.buf) {
			return 0, 0, &mmdbDecodeError{"pointer size 0 past end"}
		}
		target = (low << 8) | int(d.buf[offset])
		newOff = offset + 1
	case 1:
		// 19-bit pointer; base = 2048
		if offset+1 >= len(d.buf) {
			return 0, 0, &mmdbDecodeError{"pointer size 1 past end"}
		}
		target = 2048 + ((low << 16) | (int(d.buf[offset]) << 8) | int(d.buf[offset+1]))
		newOff = offset + 2
	case 2:
		// 27-bit pointer; base = 526336
		if offset+2 >= len(d.buf) {
			return 0, 0, &mmdbDecodeError{"pointer size 2 past end"}
		}
		target = 526336 + ((low << 24) | (int(d.buf[offset]) << 16) |
			(int(d.buf[offset+1]) << 8) | int(d.buf[offset+2]))
		newOff = offset + 3
	case 3:
		// 32-bit pointer (low 3 bits unused)
		if offset+3 >= len(d.buf) {
			return 0, 0, &mmdbDecodeError{"pointer size 3 past end"}
		}
		target = (int(d.buf[offset]) << 24) | (int(d.buf[offset+1]) << 16) |
			(int(d.buf[offset+2]) << 8) | int(d.buf[offset+3])
		newOff = offset + 4
	}
	// Pointers are relative to the start of the data section.
	target += d.dataStart
	if target < 0 || target >= len(d.buf) {
		return 0, 0, &mmdbDecodeError{"pointer target out of range"}
	}
	return target, newOff, nil
}

// decodeValue parses one MMDB value starting at offset and returns the
// decoded Go value plus the offset of the byte after it. Recursive for
// maps, arrays, and pointers.
//
// maxDepth bounds recursion (defends against pointer cycles or pathological
// inputs that hash-chain through the file).
func (d *mmdbDecoder) decodeValue(offset, maxDepth int) (interface{}, int, error) {
	if maxDepth <= 0 {
		return nil, 0, &mmdbDecodeError{"recursion depth exceeded"}
	}
	if offset < 0 || offset >= len(d.buf) {
		return nil, 0, &mmdbDecodeError{"value offset out of range"}
	}

	ctrl := d.buf[offset]
	typeCode, size, off2, err := d.readControlByte(offset)
	if err != nil {
		return nil, 0, err
	}

	switch typeCode {
	case mmdbTypePointer:
		target, after, err := d.decodePointer(ctrl, off2)
		if err != nil {
			return nil, 0, err
		}
		v, _, err := d.decodeValue(target, maxDepth-1)
		if err != nil {
			return nil, 0, err
		}
		return v, after, nil

	case mmdbTypeUTF8:
		if off2+size > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"utf8 past end"}
		}
		return string(d.buf[off2 : off2+size]), off2 + size, nil

	case mmdbTypeBytes:
		if off2+size > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"bytes past end"}
		}
		b := make([]byte, size)
		copy(b, d.buf[off2:off2+size])
		return b, off2 + size, nil

	case mmdbTypeUint16, mmdbTypeUint32, mmdbTypeUint64:
		if off2+size > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"uint past end"}
		}
		var v uint64
		for i := 0; i < size; i++ {
			v = (v << 8) | uint64(d.buf[off2+i])
		}
		return v, off2 + size, nil

	case mmdbTypeUint128:
		if off2+size > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"uint128 past end"}
		}
		// Return as []byte for callers that care; geo-routing doesn't.
		b := make([]byte, size)
		copy(b, d.buf[off2:off2+size])
		return b, off2 + size, nil

	case mmdbTypeInt32:
		if off2+size > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"int32 past end"}
		}
		var v int32
		for i := 0; i < size; i++ {
			v = (v << 8) | int32(d.buf[off2+i])
		}
		return v, off2 + size, nil

	case mmdbTypeBoolean:
		// Boolean encoding: size field is 0 or 1 with no payload bytes.
		return size != 0, off2, nil

	case mmdbTypeFloat:
		if off2+4 > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"float past end"}
		}
		return math.Float32frombits(binary.BigEndian.Uint32(d.buf[off2 : off2+4])), off2 + 4, nil

	case mmdbTypeDouble:
		if off2+8 > len(d.buf) {
			return nil, 0, &mmdbDecodeError{"double past end"}
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d.buf[off2 : off2+8])), off2 + 8, nil

	case mmdbTypeMap:
		// Each entry takes at least two bytes (key and value control
		// bytes); a larger count is malformed. Preallocation is capped so
		// memory follows the entries actually decoded: the size field alone
		// made a 4-byte value allocate over a gigabyte, per lookup (F874).
		if size > (len(d.buf)-off2)/2 {
			return nil, 0, &mmdbDecodeError{"map size exceeds remaining data"}
		}
		m := make(map[string]interface{}, min(size, mmdbMaxPrealloc))
		cur := off2
		for i := 0; i < size; i++ {
			// Map keys must be UTF-8 strings (or pointers to them).
			k, nextK, err := d.decodeValue(cur, maxDepth-1)
			if err != nil {
				return nil, 0, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, 0, &mmdbDecodeError{"map key not string"}
			}
			v, nextV, err := d.decodeValue(nextK, maxDepth-1)
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			cur = nextV
		}
		return m, cur, nil

	case mmdbTypeArray:
		// Each element takes at least one byte (F874, as for maps).
		if size > len(d.buf)-off2 {
			return nil, 0, &mmdbDecodeError{"array size exceeds remaining data"}
		}
		arr := make([]interface{}, 0, min(size, mmdbMaxPrealloc))
		cur := off2
		for i := 0; i < size; i++ {
			v, next, err := d.decodeValue(cur, maxDepth-1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			cur = next
		}
		return arr, cur, nil

	case mmdbTypeEndMarker:
		return nil, off2, nil

	default:
		return nil, 0, fmt.Errorf("geodns/mmdb: unsupported type %d", typeCode)
	}
}

// mmdbParseMetadata locates the metadata block by scanning for the magic
// marker near the end of the file, decodes it as a typed map, and extracts
// the fields the rest of the package needs.
//
// Returned: nodeCount (BST node count), recordSize (24/28/32), ipVersion,
// metadataStart (offset of marker), and the decoded metadata map itself.
func mmdbParseMetadata(data []byte) (nodeCount uint32, recordSize uint32, ipVersion uint32, metadataStart int, meta map[string]interface{}, err error) {
	marker := []byte(mmdbMetadataMarker)
	// Scan from EOF backwards up to the last 128 KiB; metadata is always
	// shorter than this in practice.
	const scanLimit = 128 * 1024
	start := len(data) - len(marker)
	if start < 0 {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"file shorter than marker"}
	}
	min := len(data) - scanLimit
	if min < 0 {
		min = 0
	}
	found := -1
	for i := start; i >= min; i-- {
		if i+len(marker) <= len(data) && string(data[i:i+len(marker)]) == string(marker) {
			found = i
			break
		}
	}
	if found < 0 {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"metadata marker not found in last 128 KiB"}
	}

	// The metadata is itself a typed map starting *after* the marker. We
	// decode using a dedicated decoder whose dataStart is the byte after
	// the marker, so any pointers inside the metadata point relative to
	// that start (per MaxMind spec §1.1).
	metaOffset := found + len(marker)
	dec := &mmdbDecoder{buf: data, dataStart: metaOffset}
	v, _, err := dec.decodeValue(metaOffset, 16)
	if err != nil {
		return 0, 0, 0, 0, nil, fmt.Errorf("decode metadata: %w", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"metadata not a map"}
	}

	nc, ok := m["node_count"].(uint64)
	if !ok {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"metadata.node_count missing or wrong type"}
	}
	if nc > uint64(^uint32(0)) {
		return 0, 0, 0, 0, nil, fmt.Errorf("geodns/mmdb: node_count too large %d", nc)
	}
	rs, ok := m["record_size"].(uint64)
	if !ok {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"metadata.record_size missing or wrong type"}
	}
	if rs != 24 && rs != 28 && rs != 32 {
		return 0, 0, 0, 0, nil, fmt.Errorf("geodns/mmdb: unsupported record_size %d", rs)
	}
	ipv, ok := m["ip_version"].(uint64)
	if !ok {
		return 0, 0, 0, 0, nil, &mmdbDecodeError{"metadata.ip_version missing or wrong type"}
	}
	if ipv != 4 && ipv != 6 {
		return 0, 0, 0, 0, nil, fmt.Errorf("geodns/mmdb: unsupported ip_version %d", ipv)
	}

	return uint32(nc), uint32(rs), uint32(ipv), found, m, nil
}

// mmdbReadRecord extracts one record (left or right child) from a tree
// node. record_size is 24/28/32. The two records of one node share bits
// when record_size == 28.
func mmdbReadRecord(data []byte, nodeIdx uint32, recordSize uint32, isRight bool) (uint32, error) {
	nodeByteSize := uint64(recordSize*2) / 8
	nodeStart := uint64(nodeIdx) * nodeByteSize
	nodeEnd := nodeStart + nodeByteSize
	if nodeEnd < nodeStart || nodeEnd > uint64(len(data)) {
		return 0, &mmdbDecodeError{"tree node past end of file"}
	}
	node := data[int(nodeStart):int(nodeEnd)]

	switch recordSize {
	case 24:
		if isRight {
			return uint32(node[3])<<16 | uint32(node[4])<<8 | uint32(node[5]), nil
		}
		return uint32(node[0])<<16 | uint32(node[1])<<8 | uint32(node[2]), nil
	case 28:
		// Left record: bytes [0,1,2] + high nibble of byte[3]
		// Right record: low nibble of byte[3] + bytes [4,5,6]
		if isRight {
			return uint32(node[3]&0x0f)<<24 | uint32(node[4])<<16 | uint32(node[5])<<8 | uint32(node[6]), nil
		}
		return uint32(node[3]&0xf0)<<20 | uint32(node[0])<<16 | uint32(node[1])<<8 | uint32(node[2]), nil
	case 32:
		if isRight {
			return binary.BigEndian.Uint32(node[4:8]), nil
		}
		return binary.BigEndian.Uint32(node[0:4]), nil
	default:
		return 0, fmt.Errorf("geodns/mmdb: unsupported record_size %d", recordSize)
	}
}

// mmdbLookup walks the tree for ip and returns the absolute file offset
// of the data record, or ok=false if the IP is not in the database.
// Bit-by-bit traversal: at each level, bit i (MSB first) selects left (0)
// or right (1).
//
// ipBits = 32 for IPv4 lookups on an IPv4-only DB; 128 for IPv6 lookups;
// for IPv6 DBs that store IPv4 in the ::ffff:0:0/96 range, IPv4 queries
// should be expanded to 16 bytes before being passed in.
//
// MMDB spec pointer arithmetic:
//
//	abs_file_offset = treeBytes + (record_value - node_count)
//
// Reference implementations: MaxMind-DB-Reader-python (_resolve_data_pointer)
// and the spec at https://maxmind.github.io/MaxMind-DB/ §"Data Section Separator".
func mmdbLookup(data []byte, nodeCount, recordSize uint32, ip net.IP, ipBits int) (dataOffset uint32, ok bool, err error) {
	if len(ip) == 0 {
		return 0, false, nil
	}
	nodeIdx := uint32(0)
	for bit := 0; bit < ipBits; bit++ {
		// Pick the bit (MSB-first).
		byteIdx := bit / 8
		if byteIdx >= len(ip) {
			return 0, false, nil
		}
		isRight := (ip[byteIdx] >> (7 - uint(bit%8)) & 1) == 1
		rec, err := mmdbReadRecord(data, nodeIdx, recordSize, isRight)
		if err != nil {
			return 0, false, err
		}
		if rec == nodeCount {
			// Documented "no data" sentinel.
			return 0, false, nil
		}
		if rec > nodeCount {
			treeBytes := uint64(nodeCount) * uint64(recordSize*2) / 8
			dataOffset := treeBytes + uint64(rec-nodeCount)
			if dataOffset > uint64(^uint32(0)) {
				return 0, false, &mmdbDecodeError{"data offset exceeds uint32"}
			}
			return uint32(dataOffset), true, nil
		}
		// Descend into next node.
		nodeIdx = rec
	}
	// Walked off the bottom of the tree without finding a leaf.
	return 0, false, nil
}
