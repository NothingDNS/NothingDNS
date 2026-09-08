// Package protocol provides DNS protocol types for NothingDNS.
//
// Service Binding record types: SVCB, HTTPS.

package protocol

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SvcParam key constants per RFC 9460 Section 14.3.2.
const (
	SvcParamKeyMandatory     = 0
	SvcParamKeyALPN          = 1
	SvcParamKeyNoDefaultALPN = 2
	SvcParamKeyPort          = 3
	SvcParamKeyIPv4Hint      = 4
	SvcParamKeyECH           = 5
	SvcParamKeyIPv6Hint      = 6
	SvcParamKeyDOHPath       = 7
)

const maxSvcParamValueLen = 0xffff

func validateSvcParamOrder(key, previousKey uint16, havePrevious bool) error {
	if havePrevious && key <= previousKey {
		return fmt.Errorf("SvcParam keys must be strictly increasing: key %d after %d", key, previousKey)
	}
	return nil
}

func validateSvcParamValue(p SvcParam) error {
	switch p.Key {
	case SvcParamKeyMandatory:
		if len(p.Value) == 0 || len(p.Value)%2 != 0 {
			return fmt.Errorf("invalid SvcParam %s length: %d", svcParamName(p.Key), len(p.Value))
		}
		if err := validateMandatoryValue(p.Value); err != nil {
			return fmt.Errorf("invalid SvcParam %s: %w", svcParamName(p.Key), err)
		}
	case SvcParamKeyALPN:
		if err := validateALPNValue(p.Value); err != nil {
			return fmt.Errorf("invalid SvcParam %s: %w", svcParamName(p.Key), err)
		}
	case SvcParamKeyNoDefaultALPN:
		if len(p.Value) != 0 {
			return fmt.Errorf("invalid SvcParam %s length: %d", svcParamName(p.Key), len(p.Value))
		}
	case SvcParamKeyPort:
		if len(p.Value) != 2 {
			return fmt.Errorf("invalid SvcParam %s length: %d", svcParamName(p.Key), len(p.Value))
		}
	case SvcParamKeyIPv4Hint:
		if len(p.Value) == 0 || len(p.Value)%net.IPv4len != 0 {
			return fmt.Errorf("invalid SvcParam %s length: %d", svcParamName(p.Key), len(p.Value))
		}
	case SvcParamKeyIPv6Hint:
		if len(p.Value) == 0 || len(p.Value)%net.IPv6len != 0 {
			return fmt.Errorf("invalid SvcParam %s length: %d", svcParamName(p.Key), len(p.Value))
		}
	}
	return nil
}

func validateSvcParams(params []SvcParam) error {
	keys := make(map[uint16]struct{}, len(params))
	mandatory := make([]uint16, 0)
	var previousKey uint16
	havePreviousKey := false
	hasALPN := false
	hasNoDefaultALPN := false

	for _, p := range params {
		if err := validateSvcParamOrder(p.Key, previousKey, havePreviousKey); err != nil {
			return err
		}
		if len(p.Value) > maxSvcParamValueLen {
			return fmt.Errorf("SvcParam value too long: %d bytes (max 65535)", len(p.Value))
		}
		if err := validateSvcParamValue(p); err != nil {
			return err
		}

		keys[p.Key] = struct{}{}
		if p.Key == SvcParamKeyALPN {
			hasALPN = true
		}
		if p.Key == SvcParamKeyNoDefaultALPN {
			hasNoDefaultALPN = true
		}
		if p.Key == SvcParamKeyMandatory {
			mandatory = mandatoryKeys(p.Value)
		}
		previousKey = p.Key
		havePreviousKey = true
	}

	if hasNoDefaultALPN && !hasALPN {
		return fmt.Errorf("invalid SvcParams: no-default-alpn requires alpn")
	}
	for _, key := range mandatory {
		if _, ok := keys[key]; !ok {
			return fmt.Errorf("invalid SvcParams: mandatory key %s is missing", svcParamName(key))
		}
	}
	return nil
}

func validateMandatoryValue(value []byte) error {
	var previousKey uint16
	havePreviousKey := false
	for _, key := range mandatoryKeys(value) {
		if key == SvcParamKeyMandatory {
			return fmt.Errorf("must not include mandatory")
		}
		if err := validateSvcParamOrder(key, previousKey, havePreviousKey); err != nil {
			return err
		}
		previousKey = key
		havePreviousKey = true
	}
	return nil
}

func mandatoryKeys(value []byte) []uint16 {
	keys := make([]uint16, 0, len(value)/2)
	for i := 0; i+2 <= len(value); i += 2 {
		keys = append(keys, Uint16(value[i:]))
	}
	return keys
}

func validateALPNValue(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("empty protocol list")
	}

	offset := 0
	for offset < len(value) {
		protoLen := int(value[offset])
		offset++
		if protoLen == 0 {
			return fmt.Errorf("empty protocol identifier")
		}
		if offset+protoLen > len(value) {
			return fmt.Errorf("truncated protocol identifier")
		}
		offset += protoLen
	}
	return nil
}

func svcParamName(key uint16) string {
	if name, ok := svcParamKeyToString[key]; ok {
		return name
	}
	return fmt.Sprintf("key%d", key)
}

// svcParamKeyToString maps SvcParam keys to their string representation.
var svcParamKeyToString = map[uint16]string{
	SvcParamKeyMandatory:     "mandatory",
	SvcParamKeyALPN:          "alpn",
	SvcParamKeyNoDefaultALPN: "no-default-alpn",
	SvcParamKeyPort:          "port",
	SvcParamKeyIPv4Hint:      "ipv4hint",
	SvcParamKeyECH:           "ech",
	SvcParamKeyIPv6Hint:      "ipv6hint",
	SvcParamKeyDOHPath:       "dohpath",
}

// svcParamKeysByName is the reverse of svcParamKeyToString. Together they form
// the single source of truth for SvcParam name⇄number mappings: both
// parseSvcParam and svcParamKeyFromString (rdata_text.go) consult this map, so
// a new SvcParamKey only needs to be added to svcParamKeyToString above.
var svcParamKeysByName = func() map[string]uint16 {
	m := make(map[string]uint16, len(svcParamKeyToString))
	for key, name := range svcParamKeyToString {
		m[name] = key
	}
	return m
}()

// SvcParam represents a single SvcParam key-value pair in an SVCB/HTTPS record.
type SvcParam struct {
	Key   uint16
	Value []byte
}

// RDataSVCB represents an SVCB (type 64) record per RFC 9460.
type RDataSVCB struct {
	Priority uint16
	Target   *Name
	Params   []SvcParam
}

// Type returns TypeSVCB.
func (r *RDataSVCB) Type() uint16 { return TypeSVCB }

// Pack serializes the SVCB record to wire format.
// Per RFC 9460 Section 2.2, the TargetName MUST NOT use name compression.
func (r *RDataSVCB) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SVCB record")
	}

	startOffset := offset

	// SvcPriority (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Priority)
	offset += 2

	// TargetName — no compression per RFC 9460
	n, err := packNameUncompressed(r.Target, buf, offset)
	if err != nil {
		return 0, err
	}
	offset += n

	// SvcParams — must be in strictly increasing key order per RFC 9460
	params := svcParamsForMode(r.Priority, r.Params)
	if err := validateSvcParams(params); err != nil {
		return 0, err
	}
	for _, p := range params {
		// Key (2 bytes) + ValueLength (2 bytes) + Value
		if offset+4+len(p.Value) > len(buf) {
			return 0, ErrBufferTooSmall
		}
		PutUint16(buf[offset:], p.Key)
		offset += 2
		PutUint16(buf[offset:], uint16(len(p.Value)))
		offset += 2
		copy(buf[offset:], p.Value)
		offset += len(p.Value)
	}

	return offset - startOffset, nil
}

// Unpack deserializes the SVCB record from wire format.
func (r *RDataSVCB) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SVCB record")
	}

	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// SvcPriority (2 bytes)
	if offset+2 > endOffset {
		return 0, ErrBufferTooSmall
	}
	r.Priority = Uint16(buf[offset:])
	offset += 2

	// TargetName — use standard UnpackName (handles wire format labels)
	target, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	if offset+n > endOffset {
		target.Release()
		return 0, ErrBufferTooSmall
	}
	r.Target = target
	offset += n

	// SvcParams — consume remaining bytes
	params := make([]SvcParam, 0)
	for offset < endOffset {
		if offset+4 > endOffset {
			return 0, ErrBufferTooSmall
		}
		key := Uint16(buf[offset:])
		offset += 2
		valueLen := int(Uint16(buf[offset:]))
		offset += 2

		if offset+valueLen > endOffset {
			return 0, ErrBufferTooSmall
		}
		value := make([]byte, valueLen)
		copy(value, buf[offset:offset+valueLen])
		offset += valueLen

		params = append(params, SvcParam{Key: key, Value: value})
	}
	if r.Priority == 0 {
		r.Params = nil
		return offset - startOffset, nil
	}

	// Deliberately lenient: no validateSvcParams here. Per RFC 9460 §4.3 a
	// recursive resolver/forwarder treats SvcParams as opaque data and passes
	// them through verbatim; the RR-malformed rules (strictly increasing keys,
	// no-default-alpn requires alpn, mandatory-key presence, per-key value
	// shapes) apply to the consuming end client, which rejects the individual
	// RR at RRSet level. Rejecting here would make one quirky SVCB/HTTPS
	// record from an upstream fail the entire message (including valid A/AAAA
	// answers) and falsely mark the upstream unhealthy. Only the structural
	// wire-format bounds checks above are required to parse safely. Pack still
	// validates: records WE emit must be well-formed.
	r.Params = params

	return offset - startOffset, nil
}

// String returns a human-readable representation of the SVCB record.
func (r *RDataSVCB) String() string {
	if r == nil {
		return ""
	}

	target := "."
	if r.Target != nil {
		target = r.Target.String()
	}

	if len(r.Params) == 0 {
		return fmt.Sprintf("%d %s", r.Priority, target)
	}

	params := svcParamsForMode(r.Priority, r.Params)
	if len(params) == 0 {
		return fmt.Sprintf("%d %s", r.Priority, target)
	}

	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, formatSvcParam(p))
	}
	return fmt.Sprintf("%d %s %s", r.Priority, target, strings.Join(parts, " "))
}

// Len returns the wire length of the SVCB record.
func (r *RDataSVCB) Len() int {
	if r == nil {
		return 0
	}

	length := 2 // Priority
	if r.Target == nil {
		length++ // root label only
	} else {
		length += r.Target.WireLength()
	}
	for _, p := range svcParamsForMode(r.Priority, r.Params) {
		length += 4 + len(p.Value) // key (2) + length (2) + value
	}
	return length
}

func svcParamsForMode(priority uint16, params []SvcParam) []SvcParam {
	if priority == 0 {
		return nil
	}
	return params
}

// Copy creates a deep copy of the SVCB record.
func (r *RDataSVCB) Copy() RData {
	if r == nil {
		return nil
	}

	var target *Name
	if r.Target != nil {
		target = r.Target.Copy()
	}
	params := make([]SvcParam, len(r.Params))
	for i, p := range r.Params {
		val := make([]byte, len(p.Value))
		copy(val, p.Value)
		params[i] = SvcParam{Key: p.Key, Value: val}
	}
	return &RDataSVCB{
		Priority: r.Priority,
		Target:   target,
		Params:   params,
	}
}

// RDataHTTPS represents an HTTPS (type 65) record per RFC 9460.
// It is wire-identical to SVCB but returns TypeHTTPS.
type RDataHTTPS struct {
	Priority uint16
	Target   *Name
	Params   []SvcParam
}

// Type returns TypeHTTPS.
func (r *RDataHTTPS) Type() uint16 { return TypeHTTPS }

// Pack serializes the HTTPS record to wire format.
func (r *RDataHTTPS) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HTTPS record")
	}

	inner := &RDataSVCB{Priority: r.Priority, Target: r.Target, Params: r.Params}
	return inner.Pack(buf, offset)
}

// Unpack deserializes the HTTPS record from wire format.
func (r *RDataHTTPS) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil HTTPS record")
	}

	inner := &RDataSVCB{}
	n, err := inner.Unpack(buf, offset, rdlength)
	if err != nil {
		return 0, err
	}
	r.Priority = inner.Priority
	r.Target = inner.Target
	r.Params = inner.Params
	return n, nil
}

// String returns a human-readable representation of the HTTPS record.
func (r *RDataHTTPS) String() string {
	if r == nil {
		return ""
	}

	inner := &RDataSVCB{Priority: r.Priority, Target: r.Target, Params: r.Params}
	return inner.String()
}

// Len returns the wire length of the HTTPS record.
func (r *RDataHTTPS) Len() int {
	if r == nil {
		return 0
	}

	inner := &RDataSVCB{Priority: r.Priority, Target: r.Target, Params: r.Params}
	return inner.Len()
}

// Copy creates a deep copy of the HTTPS record.
func (r *RDataHTTPS) Copy() RData {
	if r == nil {
		return nil
	}

	var target *Name
	if r.Target != nil {
		target = r.Target.Copy()
	}
	params := make([]SvcParam, len(r.Params))
	for i, p := range r.Params {
		val := make([]byte, len(p.Value))
		copy(val, p.Value)
		params[i] = SvcParam{Key: p.Key, Value: val}
	}
	return &RDataHTTPS{
		Priority: r.Priority,
		Target:   target,
		Params:   params,
	}
}

// packNameUncompressed packs a DNS name in wire format without name compression.
// Per RFC 9460 Section 2.2, SVCB TargetName MUST NOT be compressed.
func packNameUncompressed(name *Name, buf []byte, offset int) (int, error) {
	startOffset := offset

	if name == nil || name.IsRoot() {
		// Root domain: single zero byte
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}
		buf[offset] = 0
		return 1, nil
	}

	var packErr error
	name.ForEachLabel(func(label string) bool {
		labelLen := len(label)
		if labelLen > MaxLabelLength {
			packErr = ErrLabelTooLong
			return false
		}
		if offset+1+labelLen > len(buf) {
			packErr = ErrBufferTooSmall
			return false
		}
		buf[offset] = byte(labelLen)
		offset++
		for i := 0; i < labelLen; i++ {
			buf[offset] = toLower(label[i])
			offset++
		}
		return true
	})
	if packErr != nil {
		return 0, packErr
	}

	// Terminating zero byte
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = 0
	offset++

	// Validate total length
	if offset-startOffset > MaxNameLength {
		return 0, ErrNameTooLong
	}

	return offset - startOffset, nil
}

// formatSvcParam formats a single SvcParam for display.
func formatSvcParam(p SvcParam) string {
	switch p.Key {
	case SvcParamKeyALPN:
		return "alpn=" + formatALPNValue(p.Value)
	case SvcParamKeyNoDefaultALPN:
		return "no-default-alpn"
	case SvcParamKeyPort:
		if len(p.Value) == 2 {
			return fmt.Sprintf("port=%d", Uint16(p.Value))
		}
		return fmt.Sprintf("port=%x", p.Value)
	case SvcParamKeyIPv4Hint:
		return "ipv4hint=" + formatIPv4HintValue(p.Value)
	case SvcParamKeyIPv6Hint:
		return "ipv6hint=" + formatIPv6HintValue(p.Value)
	case SvcParamKeyECH:
		return "ech=" + formatECHValue(p.Value)
	case SvcParamKeyDOHPath:
		return "dohpath=" + string(p.Value)
	case SvcParamKeyMandatory:
		return "mandatory=" + formatMandatoryValue(p.Value)
	default:
		keyName, ok := svcParamKeyToString[p.Key]
		if !ok {
			keyName = fmt.Sprintf("key%d", p.Key)
		}
		if len(p.Value) == 0 {
			return keyName
		}
		return fmt.Sprintf("%s=%x", keyName, p.Value)
	}
}

// formatALPNValue decodes an ALPN wire-format value into a comma-separated string.
// Wire format: repeated [length][protocol-id] pairs.
func formatALPNValue(value []byte) string {
	var protocols []string
	offset := 0
	for offset < len(value) {
		if offset >= len(value) {
			break
		}
		protoLen := int(value[offset])
		offset++
		if offset+protoLen > len(value) {
			break
		}
		protocols = append(protocols, string(value[offset:offset+protoLen]))
		offset += protoLen
	}
	return strconv.Quote(strings.Join(protocols, ","))
}

// formatIPv4HintValue formats IPv4 addresses from wire format.
func formatIPv4HintValue(value []byte) string {
	var addrs []string
	for i := 0; i+4 <= len(value); i += 4 {
		addrs = append(addrs, net.IP(value[i:i+4]).String())
	}
	return strings.Join(addrs, ",")
}

// formatIPv6HintValue formats IPv6 addresses from wire format.
func formatIPv6HintValue(value []byte) string {
	var addrs []string
	for i := 0; i+16 <= len(value); i += 16 {
		addrs = append(addrs, net.IP(value[i:i+16]).String())
	}
	return strings.Join(addrs, ",")
}

// formatECHValue formats an ECH config as base64-like hex.
func formatECHValue(value []byte) string {
	return fmt.Sprintf("%x", value)
}

// formatMandatoryValue decodes the mandatory param as a list of key names.
func formatMandatoryValue(value []byte) string {
	var keys []string
	for i := 0; i+2 <= len(value); i += 2 {
		k := Uint16(value[i:])
		if name, ok := svcParamKeyToString[k]; ok {
			keys = append(keys, name)
		} else {
			keys = append(keys, fmt.Sprintf("key%d", k))
		}
	}
	return strings.Join(keys, ",")
}

// RDataZONEMD represents the ZONEMD record type (RFC 8976).
// ZONEMD provides a cryptographic digest of zone contents for integrity verification.
