// NothingDNS - presentation-format (text) RData parsing.
//
// This file converts DNS record data from its zone-file/presentation form
// into wire-format RData structures. It is shared by the server (zone
// records, DDNS), zone transfer code, and the CLI.

package protocol

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RecordTypeFromText converts a record type mnemonic to its DNS type number.
// It accepts the DKIM alias (mapped to TXT) and RFC 3597 TYPE### numeric
// names (e.g. "TYPE61", case-insensitive, value <= 65535). It returns 0 for
// unknown types.
func RecordTypeFromText(s string) uint16 {
	upper := strings.ToUpper(s)
	if upper == "DKIM" {
		return TypeTXT
	}
	if t, ok := StringToType[upper]; ok {
		return t
	}
	if strings.HasPrefix(upper, "TYPE") {
		if value, err := strconv.ParseUint(strings.TrimPrefix(upper, "TYPE"), 10, 16); err == nil {
			return uint16(value)
		}
	}
	return 0
}

// ParseRDataText parses presentation-format RData based on record type.
// It returns nil if the RData cannot be parsed.
func ParseRDataText(rtype, rdata string) RData {
	switch strings.ToUpper(rtype) {
	case "A":
		ip := net.ParseIP(rdata)
		if ip != nil {
			ipv4 := ip.To4()
			if ipv4 == nil {
				return nil
			}
			var addr [4]byte
			copy(addr[:], ipv4)
			rd := rdataAPool.Get().(*RDataA)
			rd.Address = addr
			return rd
		}
	case "AAAA":
		ip := net.ParseIP(rdata)
		if ip != nil {
			var addr [16]byte
			copy(addr[:], ip.To16())
			rd := rdataAAAAPool.Get().(*RDataAAAA)
			rd.Address = addr
			return rd
		}
	case "CNAME":
		name, err := ParseName(rdata)
		if err == nil {
			rd := rdataCNAMEPool.Get().(*RDataCNAME)
			rd.CName = name
			return rd
		}
	case "DNAME":
		name, err := ParseName(rdata)
		if err == nil {
			rd := rdataDNAMEPool.Get().(*RDataDNAME)
			rd.DName = name
			return rd
		}
	case "NS":
		name, err := ParseName(rdata)
		if err == nil {
			rd := rdataNSPool.Get().(*RDataNS)
			rd.NSDName = name
			return rd
		}
	case "PTR":
		name, err := ParseName(rdata)
		if err == nil {
			rd := rdataPTRPool.Get().(*RDataPTR)
			rd.PtrDName = name
			return rd
		}
	case "MX":
		parts := strings.Fields(rdata)
		if len(parts) >= 2 {
			pref, ok := parseUintField(parts[0], 16)
			if !ok {
				return nil
			}
			exchange, err := ParseName(parts[1])
			if err == nil {
				rd := rdataMXPool.Get().(*RDataMX)
				rd.Preference = uint16(pref)
				rd.Exchange = exchange
				return rd
			}
		}
	case "TXT":
		return parseTXTRData(rdata)
	case "DKIM":
		return parseTXTRData(rdata)
	case "HINFO":
		return parseHINFORData(rdata)
	case "RP":
		return parseRPRData(rdata)
	case "AFSDB":
		return parseAFSDBRData(rdata)
	case "SIG":
		return parseRRSIGRData(rdata)
	case "KEY":
		return parseDNSKEYRData(rdata)
	case "SPF":
		return parseTXTRData(rdata)
	case "LOC":
		return parseLOCRData(rdata)
	case "SOA":
		return parseSOARData(rdata)
	case "SRV":
		return parseSRVRData(rdata)
	case "KX":
		return parseKXRData(rdata)
	case "CERT":
		return parseCERTRData(rdata)
	case "APL":
		return parseAPLRData(rdata)
	case "CAA":
		return parseCAARData(rdata)
	case "URI":
		return parseURIRData(rdata)
	case "NAPTR":
		return parseNAPTRRData(rdata)
	case "SSHFP":
		return parseSSHFPRData(rdata)
	case "HIP":
		return parseHIPRData(rdata)
	case "IPSECKEY":
		return parseIPSECKEYRData(rdata)
	case "TLSA":
		return parseTLSARData(rdata)
	case "DHCID":
		return parseDHCIDRData(rdata)
	case "DS":
		return parseDSRData(rdata)
	case "CDS":
		return parseDSRData(rdata)
	case "DNSKEY":
		return parseDNSKEYRData(rdata)
	case "CDNSKEY":
		return parseDNSKEYRData(rdata)
	case "TA":
		return parseDSRData(rdata)
	case "OPENPGPKEY":
		return parseOPENPGPKEYRData(rdata)
	case "RRSIG":
		return parseRRSIGRData(rdata)
	case "ZONEMD":
		return parseZONEMDRData(rdata)
	case "NSEC":
		return parseNSECRData(rdata)
	case "NSEC3":
		return parseNSEC3RData(rdata)
	case "NSEC3PARAM":
		return parseNSEC3PARAMRData(rdata)
	case "SVCB":
		return parseSVCBRData(rdata)
	case "HTTPS":
		return parseHTTPSRData(rdata)
	}
	return nil
}

// parseSOARData parses SOA RData: "mname rname serial refresh retry expire minimum"
func parseSOARData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 7 {
		return nil
	}
	mname, err := ParseName(fields[0])
	if err != nil {
		return nil
	}
	rname, err := ParseName(fields[1])
	if err != nil {
		return nil
	}
	serial, ok := parseUintField(fields[2], 32)
	if !ok {
		return nil
	}
	refresh, ok := parseUintField(fields[3], 32)
	if !ok {
		return nil
	}
	retry, ok := parseUintField(fields[4], 32)
	if !ok {
		return nil
	}
	expire, ok := parseUintField(fields[5], 32)
	if !ok {
		return nil
	}
	minimum, ok := parseUintField(fields[6], 32)
	if !ok {
		return nil
	}
	rd := rdataSOAPool.Get().(*RDataSOA)
	rd.MName = mname
	rd.RName = rname
	rd.Serial = uint32(serial)
	rd.Refresh = uint32(refresh)
	rd.Retry = uint32(retry)
	rd.Expire = uint32(expire)
	rd.Minimum = uint32(minimum)
	return rd
}

// parseSRVRData parses SRV RData: "priority weight port target"
func parseSRVRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	priority, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	weight, ok := parseUintField(fields[1], 16)
	if !ok {
		return nil
	}
	port, ok := parseUintField(fields[2], 16)
	if !ok {
		return nil
	}
	target, err := ParseName(fields[3])
	if err != nil {
		return nil
	}
	rd := rdataSRVPool.Get().(*RDataSRV)
	rd.Priority = uint16(priority)
	rd.Weight = uint16(weight)
	rd.Port = uint16(port)
	rd.Target = target
	return rd
}

// parseCAARData parses CAA RData: "flags tag value"
// parseCAARData parses CAA RData: `flags tag value`. The value is normally a
// quoted character-string (RFC 8659 §4.1.1, e.g. `0 issue "ca.example; a=1"`);
// the quotes are presentation syntax and must not reach the wire. An unquoted
// value is taken verbatim.
func parseCAARData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 3 {
		return nil
	}
	flags, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	value := strings.Join(fields[2:], " ")
	if strings.Contains(value, "\"") {
		quoted, ok := parseQuotedRDataFields(value)
		if !ok || len(quoted) != 1 {
			return nil
		}
		value = quoted[0]
	}
	return &RDataCAA{
		Flags: uint8(flags),
		Tag:   fields[1],
		Value: value,
	}
}

func parseTXTRData(rdata string) RData {
	text := strings.TrimSpace(rdata)
	stringsToPack := []string{text}
	if strings.Contains(text, "\"") {
		// BIND presentation form: split into quoted character-strings.
		// Stored rdata is not guaranteed to be presentation form, though —
		// the zone parser stores unescaped raw text, so a legal TXT value
		// containing a literal `"` (e.g. from `"ab\"cd"`) looks unbalanced
		// here. Serve such values verbatim (the pre-parser behavior)
		// instead of silently dropping the record.
		if fields, ok := parseQuotedRDataFields(text); ok {
			stringsToPack = fields
		}
	}
	rd := rdataTXTPool.Get().(*RDataTXT)
	rd.Strings = splitCharacterStrings(stringsToPack)
	return rd
}

func splitCharacterStrings(fields []string) []string {
	var out []string
	for _, field := range fields {
		if field == "" {
			out = append(out, "")
			continue
		}
		for len(field) > 255 {
			out = append(out, field[:255])
			field = field[255:]
		}
		out = append(out, field)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// parseHINFORData parses HINFO RData: `cpu os`.
func parseHINFORData(rdata string) RData {
	fields, ok := parseQuotedRDataFields(rdata)
	if !ok || len(fields) != 2 {
		return nil
	}
	rd := &RDataHINFO{CPU: fields[0], OS: fields[1]}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseRPRData parses RP RData: `mbox txt`.
func parseRPRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) != 2 {
		return nil
	}
	mbox, err := ParseName(fields[0])
	if err != nil {
		return nil
	}
	txt, err := ParseName(fields[1])
	if err != nil {
		return nil
	}
	rd := &RDataRP{MBox: mbox, Txt: txt}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseAFSDBRData parses AFSDB RData: `subtype hostname`.
func parseAFSDBRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) != 2 {
		return nil
	}
	subtype, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	hostname, err := ParseName(fields[1])
	if err != nil {
		return nil
	}
	rd := &RDataAFSDB{Subtype: uint16(subtype), Hostname: hostname}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseKXRData parses KX RData: `preference exchanger`.
func parseKXRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) != 2 {
		return nil
	}
	preference, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	exchanger, err := ParseName(fields[1])
	if err != nil {
		return nil
	}
	rd := &RDataKX{Preference: uint16(preference), Exchanger: exchanger}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseCERTRData parses CERT RData: `cert-type key-tag algorithm certificate`.
func parseCERTRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	certType, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	keyTag, ok := parseUintField(fields[1], 16)
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	certificate, ok := decodeBase64RData(strings.Join(fields[3:], ""))
	if !ok {
		return nil
	}
	rd := &RDataCERT{
		CertType:    uint16(certType),
		KeyTag:      uint16(keyTag),
		Algorithm:   uint8(algorithm),
		Certificate: certificate,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseOPENPGPKEYRData parses OPENPGPKEY RData as base64-encoded public key data.
func parseOPENPGPKEYRData(rdata string) RData {
	publicKey, ok := decodeBase64RData(strings.Join(strings.Fields(rdata), ""))
	if !ok {
		return nil
	}
	rd := &RDataOPENPGPKEY{PublicKey: publicKey}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseAPLRData parses APL RData: `[!]afi:address/prefix ...`.
func parseAPLRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) == 0 {
		return nil
	}
	items := make([]APLItem, 0, len(fields))
	for _, field := range fields {
		item, ok := parseAPLItem(field)
		if !ok {
			return nil
		}
		items = append(items, item)
	}
	rd := &RDataAPL{Items: items}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseAPLItem(field string) (APLItem, bool) {
	item := APLItem{}
	if strings.HasPrefix(field, "!") {
		item.Negation = true
		field = strings.TrimPrefix(field, "!")
	}
	afiPart, rest, ok := strings.Cut(field, ":")
	if !ok {
		return APLItem{}, false
	}
	addressPart, prefixPart, ok := strings.Cut(rest, "/")
	if !ok {
		return APLItem{}, false
	}
	afi, ok := parseUintField(afiPart, 16)
	if !ok {
		return APLItem{}, false
	}
	prefix, ok := parseUintField(prefixPart, 8)
	if !ok {
		return APLItem{}, false
	}

	item.AddressFamily = uint16(afi)
	item.Prefix = uint8(prefix)
	switch item.AddressFamily {
	case 1:
		if item.Prefix > 32 {
			return APLItem{}, false
		}
		ip := net.ParseIP(addressPart).To4()
		if ip == nil {
			return APLItem{}, false
		}
		item.Address = trimAPLAddress(ip)
	case 2:
		if item.Prefix > 128 {
			return APLItem{}, false
		}
		ip := net.ParseIP(addressPart)
		if ip == nil || ip.To4() != nil {
			return APLItem{}, false
		}
		item.Address = trimAPLAddress(ip.To16())
	default:
		return APLItem{}, false
	}
	return item, true
}

func trimAPLAddress(address []byte) []byte {
	end := len(address)
	for end > 0 && address[end-1] == 0 {
		end--
	}
	out := make([]byte, end)
	copy(out, address[:end])
	return out
}

// parseLOCRData parses LOC RData in RFC 1876 presentation format.
func parseLOCRData(rdata string) RData {
	fields := strings.Fields(rdata)
	// RFC 1876 §3: minutes, seconds, size, and precisions are all optional.
	// The minimal valid form is `d1 {N|S} d2 {E|W} alt` — five fields.
	if len(fields) < 5 {
		return nil
	}
	latitude, idx, ok := parseLOCCoordinate(fields, 0, "N", "S", 90)
	if !ok {
		return nil
	}
	longitude, idx, ok := parseLOCCoordinate(fields, idx, "E", "W", 180)
	if !ok || idx >= len(fields) {
		return nil
	}
	altitude, ok := parseLOCAltitude(fields[idx])
	if !ok {
		return nil
	}
	idx++

	size := uint8(0x12)
	horizPrecision := uint8(0x16)
	vertPrecision := uint8(0x13)
	if idx < len(fields) {
		size, ok = parseLOCPrecision(fields[idx])
		if !ok {
			return nil
		}
		idx++
	}
	if idx < len(fields) {
		horizPrecision, ok = parseLOCPrecision(fields[idx])
		if !ok {
			return nil
		}
		idx++
	}
	if idx < len(fields) {
		vertPrecision, ok = parseLOCPrecision(fields[idx])
		if !ok {
			return nil
		}
		idx++
	}
	if idx != len(fields) {
		return nil
	}

	rd := &RDataLOC{
		Version:        0,
		Size:           size,
		HorizPrecision: horizPrecision,
		VertPrecision:  vertPrecision,
		Latitude:       latitude,
		Longitude:      longitude,
		Altitude:       altitude,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseLOCCoordinate(fields []string, idx int, positiveHemisphere, negativeHemisphere string, maxDegrees uint64) (uint32, int, bool) {
	degrees, ok := parseUintFieldAt(fields, idx, 32)
	if !ok || degrees > maxDegrees {
		return 0, idx, false
	}
	idx++

	minutes := uint64(0)
	secondsMS := int64(0)
	if idx < len(fields) && !isLOCHemisphere(fields[idx], positiveHemisphere, negativeHemisphere) {
		minutes, ok = parseUintFieldAt(fields, idx, 32)
		if !ok || minutes > 59 {
			return 0, idx, false
		}
		idx++
	}
	if idx < len(fields) && !isLOCHemisphere(fields[idx], positiveHemisphere, negativeHemisphere) {
		seconds, err := strconv.ParseFloat(fields[idx], 64)
		if err != nil || seconds < 0 || seconds >= 60 {
			return 0, idx, false
		}
		secondsMS = roundFloatToInt64(seconds * 1000)
		if secondsMS >= 60000 {
			return 0, idx, false
		}
		idx++
	}
	if idx >= len(fields) {
		return 0, idx, false
	}
	hemisphere := strings.ToUpper(fields[idx])
	if !isLOCHemisphere(hemisphere, positiveHemisphere, negativeHemisphere) {
		return 0, idx, false
	}
	idx++

	totalMS := int64(degrees*3600+minutes*60)*1000 + secondsMS
	if degrees == maxDegrees && (minutes != 0 || secondsMS != 0) {
		return 0, idx, false
	}
	value := int64(1<<31) + totalMS
	if hemisphere == negativeHemisphere {
		value = int64(1<<31) - totalMS
	}
	if value < 0 || value > int64(^uint32(0)) {
		return 0, idx, false
	}
	return uint32(value), idx, true
}

func parseUintFieldAt(fields []string, idx int, bitSize int) (uint64, bool) {
	if idx >= len(fields) {
		return 0, false
	}
	return parseUintField(fields[idx], bitSize)
}

func isLOCHemisphere(field, positiveHemisphere, negativeHemisphere string) bool {
	upper := strings.ToUpper(field)
	return upper == positiveHemisphere || upper == negativeHemisphere
}

func parseLOCAltitude(field string) (uint32, bool) {
	centimeters, ok := parseLOCMeters(field, true)
	if !ok {
		return 0, false
	}
	encoded := centimeters + 10000000
	if encoded < 0 || encoded > int64(^uint32(0)) {
		return 0, false
	}
	return uint32(encoded), true
}

func parseLOCPrecision(field string) (uint8, bool) {
	centimeters, ok := parseLOCMeters(field, false)
	if !ok || centimeters < 0 {
		return 0, false
	}
	if centimeters == 0 {
		// RFC 1876: a zero size/precision is valid and encodes as 0e0.
		return 0, true
	}
	exponent := uint8(0)
	value := centimeters
	for value > 9 {
		value = roundDiv10(value)
		exponent++
		if exponent > 9 {
			return 0, false
		}
	}
	if value <= 0 || value > 9 {
		return 0, false
	}
	return uint8(value)<<4 | exponent, true
}

func parseLOCMeters(field string, allowNegative bool) (int64, bool) {
	value := strings.TrimSuffix(strings.ToLower(field), "m")
	if value == "" {
		return 0, false
	}
	meters, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	if !allowNegative && meters < 0 {
		return 0, false
	}
	return roundFloatToInt64(meters * 100), true
}

func roundFloatToInt64(value float64) int64 {
	if value < 0 {
		return int64(value - 0.5)
	}
	return int64(value + 0.5)
}

func roundDiv10(value int64) int64 {
	return (value + 5) / 10
}

// parseHIPRData parses HIP RData: `algorithm hit public-key [rendezvous-server ...]`.
func parseHIPRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 3 {
		return nil
	}
	algorithm, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	hit, err := hex.DecodeString(fields[1])
	if err != nil || len(hit) == 0 || len(hit) > 255 {
		return nil
	}
	publicKey, ok := decodeBase64RData(fields[2])
	if !ok || len(publicKey) > 65535 {
		return nil
	}
	servers := make([]*Name, 0, len(fields)-3)
	for _, field := range fields[3:] {
		server, err := ParseName(field)
		if err != nil {
			return nil
		}
		servers = append(servers, server)
	}
	rd := &RDataHIP{
		HIT:                hit,
		PublicKeyAlgorithm: uint8(algorithm),
		PublicKey:          publicKey,
		RendezvousServers:  servers,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseIPSECKEYRData parses IPSECKEY RData: `precedence gateway-type algorithm gateway public-key`.
func parseIPSECKEYRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 5 {
		return nil
	}
	precedence, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	gatewayType, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	publicKey, ok := decodeBase64RData(strings.Join(fields[4:], ""))
	if !ok {
		return nil
	}

	rd := &RDataIPSECKEY{
		Precedence:  uint8(precedence),
		GatewayType: uint8(gatewayType),
		Algorithm:   uint8(algorithm),
		PublicKey:   publicKey,
	}

	switch rd.GatewayType {
	case 0:
		if fields[3] != "." {
			return nil
		}
	case 1:
		ip := net.ParseIP(fields[3]).To4()
		if ip == nil {
			return nil
		}
		rd.Gateway = append([]byte(nil), ip...)
	case 2:
		ip := net.ParseIP(fields[3])
		if ip == nil || ip.To4() != nil {
			return nil
		}
		rd.Gateway = append([]byte(nil), ip.To16()...)
	case 3:
		name, err := ParseName(fields[3])
		if err != nil {
			return nil
		}
		rd.GatewayName = name
	default:
		return nil
	}

	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseURIRData parses URI RData: `priority weight target`.
func parseURIRData(rdata string) RData {
	fields, ok := parseQuotedRDataFields(rdata)
	if !ok || len(fields) != 3 {
		return nil
	}
	priority, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	weight, ok := parseUintField(fields[1], 16)
	if !ok {
		return nil
	}
	rd := &RDataURI{
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Target:   fields[2],
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseNAPTRRData parses NAPTR RData: `order preference flags service regexp replacement`.
func parseNAPTRRData(rdata string) RData {
	fields, ok := parseQuotedRDataFields(rdata)
	if !ok || len(fields) != 6 {
		return nil
	}
	order, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	preference, ok := parseUintField(fields[1], 16)
	if !ok {
		return nil
	}
	replacement, err := ParseName(fields[5])
	if err != nil {
		return nil
	}
	rd := &RDataNAPTR{
		Order:       uint16(order),
		Preference:  uint16(preference),
		Flags:       fields[2],
		Service:     fields[3],
		Regexp:      fields[4],
		Replacement: replacement,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseQuotedRDataFields(line string) ([]string, bool) {
	var fields []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	fieldStarted := false

	for _, r := range line {
		if inQuotes && escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			if inQuotes {
				escaped = true
				fieldStarted = true
			} else {
				current.WriteRune(r)
				fieldStarted = true
			}
		case '"':
			if inQuotes {
				fields = append(fields, current.String())
				current.Reset()
				inQuotes = false
				fieldStarted = false
			} else {
				if current.Len() > 0 {
					fields = append(fields, current.String())
					current.Reset()
				}
				inQuotes = true
				fieldStarted = true
			}
		case ' ', '\t':
			if inQuotes {
				current.WriteRune(r)
				fieldStarted = true
			} else if current.Len() > 0 || fieldStarted {
				fields = append(fields, current.String())
				current.Reset()
				fieldStarted = false
			}
		default:
			current.WriteRune(r)
			fieldStarted = true
		}
	}
	if escaped {
		current.WriteRune('\\')
	}
	if inQuotes {
		return nil, false
	}
	if current.Len() > 0 || fieldStarted {
		fields = append(fields, current.String())
	}
	return fields, true
}

// parseSSHFPRData parses SSHFP RData: "algorithm fingerprint-type fingerprint"
func parseSSHFPRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 3 {
		return nil
	}
	algorithm, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	fpType, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	fingerprint, err := hex.DecodeString(strings.Join(fields[2:], ""))
	if err != nil {
		return nil
	}
	return &RDataSSHFP{
		Algorithm:   uint8(algorithm),
		FPType:      uint8(fpType),
		Fingerprint: fingerprint,
	}
}

// parseTLSARData parses TLSA RData: "usage selector matching-type certificate"
func parseTLSARData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	usage, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	selector, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	matchingType, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	certificate, err := hex.DecodeString(strings.Join(fields[3:], ""))
	if err != nil {
		return nil
	}
	return &RDataTLSA{
		Usage:        uint8(usage),
		Selector:     uint8(selector),
		MatchingType: uint8(matchingType),
		Certificate:  certificate,
	}
}

// parseDHCIDRData parses DHCID RData as base64-encoded opaque data.
func parseDHCIDRData(rdata string) RData {
	data, ok := decodeBase64RData(strings.Join(strings.Fields(rdata), ""))
	if !ok {
		return nil
	}
	return &RDataDHCID{Data: data}
}

// parseDSRData parses DS RData: "key-tag algorithm digest-type digest"
func parseDSRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	keyTag, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	digestType, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	digest, err := hex.DecodeString(strings.Join(fields[3:], ""))
	if err != nil || len(digest) == 0 {
		return nil
	}
	return &RDataDS{
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}
}

// parseDNSKEYRData parses DNSKEY RData: "flags protocol algorithm public-key"
func parseDNSKEYRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	flags, ok := parseUintField(fields[0], 16)
	if !ok {
		return nil
	}
	proto, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	publicKey, ok := decodeBase64RData(strings.Join(fields[3:], ""))
	if !ok {
		return nil
	}
	return &RDataDNSKEY{
		Flags:     uint16(flags),
		Protocol:  uint8(proto),
		Algorithm: uint8(algorithm),
		PublicKey: publicKey,
	}
}

func decodeBase64RData(encoded string) ([]byte, bool) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// parseRRSIGRData parses RRSIG RData:
// "type-covered algorithm labels original-ttl expiration inception key-tag signer signature".
func parseRRSIGRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 9 {
		return nil
	}
	typeCovered, ok := parseNSECTypeField(fields[0])
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	labels, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	originalTTL, ok := parseUintField(fields[3], 32)
	if !ok {
		return nil
	}
	expiration, ok := parseRRSIGTimeField(fields[4])
	if !ok {
		return nil
	}
	inception, ok := parseRRSIGTimeField(fields[5])
	if !ok {
		return nil
	}
	keyTag, ok := parseUintField(fields[6], 16)
	if !ok {
		return nil
	}
	signer, err := ParseName(fields[7])
	if err != nil {
		return nil
	}
	signature, ok := decodeBase64RData(strings.Join(fields[8:], ""))
	if !ok {
		return nil
	}
	rd := &RDataRRSIG{
		TypeCovered: typeCovered,
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      uint16(keyTag),
		SignerName:  signer,
		Signature:   signature,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseRRSIGTimeField(s string) (uint32, bool) {
	if len(s) == 14 {
		t, err := time.Parse("20060102150405", s)
		if err != nil {
			return 0, false
		}
		sec := t.Unix()
		if sec < 0 || sec > int64(^uint32(0)) {
			return 0, false
		}
		return uint32(sec), true
	}
	v, ok := parseUintField(s, 32)
	if !ok {
		return 0, false
	}
	return uint32(v), true
}

// parseZONEMDRData parses ZONEMD RData: "serial scheme algorithm digest"
func parseZONEMDRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	serial, ok := parseUintField(fields[0], 32)
	if !ok {
		return nil
	}
	scheme, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	algorithm, ok := parseUintField(fields[2], 8)
	if !ok {
		return nil
	}
	digest, err := hex.DecodeString(strings.Join(fields[3:], ""))
	if err != nil || len(digest) == 0 {
		return nil
	}
	rd := &RDataZONEMD{
		Serial:    uint32(serial),
		Scheme:    uint8(scheme),
		Algorithm: uint8(algorithm),
		Digest:    digest,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseNSECRData parses NSEC RData: "next-domain type..."
func parseNSECRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 2 {
		return nil
	}
	next, err := ParseName(fields[0])
	if err != nil {
		return nil
	}
	types := make([]uint16, 0, len(fields)-1)
	for _, field := range fields[1:] {
		rrtype, ok := parseNSECTypeField(field)
		if !ok {
			return nil
		}
		types = append(types, rrtype)
	}
	rd := &RDataNSEC{
		NextDomain: next,
		TypeBitMap: types,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseNSECTypeField resolves a type mnemonic (or TYPE###) in an NSEC/NSEC3
// type bitmap via RecordTypeFromText, but is stricter than the latter: type 0
// is rejected, and the DKIM→TXT presentation alias does not apply because the
// bitmap must list actual RR type numbers.
func parseNSECTypeField(s string) (uint16, bool) {
	if strings.EqualFold(s, "DKIM") {
		return 0, false
	}
	rrtype := RecordTypeFromText(s)
	return rrtype, rrtype != 0
}

// parseNSEC3RData parses NSEC3 RData: "hash flags iterations salt next-hash [type...]"
func parseNSEC3RData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 5 {
		return nil
	}
	hashAlgorithm, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	flags, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	iterations, ok := parseUintField(fields[2], 16)
	if !ok {
		return nil
	}
	salt, ok := parseNSEC3Salt(fields[3])
	if !ok {
		return nil
	}
	nextHash, ok := decodeNSEC3Hash(fields[4])
	if !ok {
		return nil
	}
	types := make([]uint16, 0, len(fields)-5)
	for _, field := range fields[5:] {
		rrtype, ok := parseNSECTypeField(field)
		if !ok {
			return nil
		}
		types = append(types, rrtype)
	}
	rd := &RDataNSEC3{
		HashAlgorithm: uint8(hashAlgorithm),
		Flags:         uint8(flags),
		Iterations:    uint16(iterations),
		Salt:          salt,
		HashLength:    uint8(len(nextHash)),
		NextHashed:    nextHash,
		TypeBitMap:    types,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func decodeNSEC3Hash(s string) ([]byte, bool) {
	hash, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
	if err != nil || len(hash) == 0 {
		return nil, false
	}
	return hash, true
}

// parseNSEC3PARAMRData parses NSEC3PARAM RData: "hash flags iterations salt"
func parseNSEC3PARAMRData(rdata string) RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	hashAlgorithm, ok := parseUintField(fields[0], 8)
	if !ok {
		return nil
	}
	flags, ok := parseUintField(fields[1], 8)
	if !ok {
		return nil
	}
	iterations, ok := parseUintField(fields[2], 16)
	if !ok {
		return nil
	}
	salt, ok := parseNSEC3Salt(strings.Join(fields[3:], ""))
	if !ok {
		return nil
	}
	rd := &RDataNSEC3PARAM{
		HashAlgorithm: uint8(hashAlgorithm),
		Flags:         uint8(flags),
		Iterations:    uint16(iterations),
		Salt:          salt,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseNSEC3Salt(s string) ([]byte, bool) {
	if s == "-" {
		return nil, true
	}
	salt, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return salt, true
}

// parseSVCBRData parses SVCB RData: "priority target [svcparams...]"
func parseSVCBRData(rdata string) RData {
	priority, target, params, ok := parseSVCBFields(rdata)
	if !ok {
		return nil
	}
	rd := &RDataSVCB{
		Priority: priority,
		Target:   target,
		Params:   params,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

// parseHTTPSRData parses HTTPS RData: "priority target [svcparams...]"
func parseHTTPSRData(rdata string) RData {
	priority, target, params, ok := parseSVCBFields(rdata)
	if !ok {
		return nil
	}
	rd := &RDataHTTPS{
		Priority: priority,
		Target:   target,
		Params:   params,
	}
	if !RDataPacksText(rd) {
		return nil
	}
	return rd
}

func parseSVCBFields(rdata string) (uint16, *Name, []SvcParam, bool) {
	fields := strings.Fields(rdata)
	if len(fields) < 2 {
		return 0, nil, nil, false
	}
	priority, ok := parseUintField(fields[0], 16)
	if !ok {
		return 0, nil, nil, false
	}
	target, err := ParseName(fields[1])
	if err != nil {
		return 0, nil, nil, false
	}
	params, ok := parseSvcParams(fields[2:])
	if !ok {
		return 0, nil, nil, false
	}
	if priority == 0 && len(params) != 0 {
		return 0, nil, nil, false
	}
	sort.Slice(params, func(i, j int) bool {
		return params[i].Key < params[j].Key
	})
	return uint16(priority), target, params, true
}

func parseSvcParams(fields []string) ([]SvcParam, bool) {
	params := make([]SvcParam, 0, len(fields))
	for _, field := range fields {
		param, ok := parseSvcParam(field)
		if !ok {
			return nil, false
		}
		params = append(params, param)
	}
	return params, true
}

func parseSvcParam(field string) (SvcParam, bool) {
	keyName, value, hasValue := strings.Cut(field, "=")
	key, known := svcParamKeysByName[strings.ToLower(keyName)]
	if !known {
		key, ok := parseGenericSvcParamKey(keyName)
		if !ok {
			return SvcParam{}, false
		}
		if !hasValue {
			return SvcParam{Key: key}, true
		}
		wire, err := hex.DecodeString(value)
		if err != nil {
			return SvcParam{}, false
		}
		return SvcParam{Key: key, Value: wire}, true
	}
	if key == SvcParamKeyNoDefaultALPN {
		if hasValue {
			return SvcParam{}, false
		}
		return SvcParam{Key: key}, true
	}
	if !hasValue {
		return SvcParam{}, false
	}
	switch key {
	case SvcParamKeyMandatory:
		wire, ok := parseMandatorySvcParam(value)
		return SvcParam{Key: key, Value: wire}, ok
	case SvcParamKeyALPN:
		wire, ok := parseALPNSvcParam(value)
		return SvcParam{Key: key, Value: wire}, ok
	case SvcParamKeyPort:
		port, ok := parseUintField(value, 16)
		if !ok {
			return SvcParam{}, false
		}
		wire := make([]byte, 2)
		PutUint16(wire, uint16(port))
		return SvcParam{Key: key, Value: wire}, true
	case SvcParamKeyIPv4Hint:
		wire, ok := parseIPHintSvcParam(value, false)
		return SvcParam{Key: key, Value: wire}, ok
	case SvcParamKeyIPv6Hint:
		wire, ok := parseIPHintSvcParam(value, true)
		return SvcParam{Key: key, Value: wire}, ok
	case SvcParamKeyECH:
		wire, err := hex.DecodeString(value)
		if err != nil {
			return SvcParam{}, false
		}
		return SvcParam{Key: key, Value: wire}, true
	case SvcParamKeyDOHPath:
		return SvcParam{Key: key, Value: []byte(unquoteSvcParamValue(value))}, true
	default:
		// Named in svcParamKeysByName but without dedicated presentation
		// syntax yet: accept the value in generic hex form like keyNNNNN.
		wire, err := hex.DecodeString(value)
		if err != nil {
			return SvcParam{}, false
		}
		return SvcParam{Key: key, Value: wire}, true
	}
}

func parseMandatorySvcParam(value string) ([]byte, bool) {
	keys := strings.Split(unquoteSvcParamValue(value), ",")
	wire := make([]byte, 0, len(keys)*2)
	for _, keyName := range keys {
		key, ok := svcParamKeyFromString(keyName)
		if !ok {
			return nil, false
		}
		encoded := make([]byte, 2)
		PutUint16(encoded, key)
		wire = append(wire, encoded...)
	}
	return wire, true
}

func parseALPNSvcParam(value string) ([]byte, bool) {
	protocols := strings.Split(unquoteSvcParamValue(value), ",")
	wire := make([]byte, 0, len(value))
	for _, proto := range protocols {
		if proto == "" || len(proto) > 255 {
			return nil, false
		}
		wire = append(wire, byte(len(proto)))
		wire = append(wire, proto...)
	}
	return wire, true
}

func parseIPHintSvcParam(value string, ipv6 bool) ([]byte, bool) {
	parts := strings.Split(unquoteSvcParamValue(value), ",")
	var wire []byte
	for _, part := range parts {
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, false
		}
		if ipv6 {
			addr := ip.To16()
			if addr == nil || ip.To4() != nil {
				return nil, false
			}
			wire = append(wire, addr...)
			continue
		}
		addr := ip.To4()
		if addr == nil {
			return nil, false
		}
		wire = append(wire, addr...)
	}
	return wire, len(wire) != 0
}

func parseGenericSvcParamKey(keyName string) (uint16, bool) {
	keyName = strings.ToLower(keyName)
	if !strings.HasPrefix(keyName, "key") {
		return 0, false
	}
	key, ok := parseUintField(strings.TrimPrefix(keyName, "key"), 16)
	if !ok {
		return 0, false
	}
	return uint16(key), true
}

func svcParamKeyFromString(keyName string) (uint16, bool) {
	// "mandatory" must not appear inside its own key list (RFC 9460 §8).
	if key, ok := svcParamKeysByName[strings.ToLower(keyName)]; ok && key != SvcParamKeyMandatory {
		return key, true
	}
	return parseGenericSvcParamKey(keyName)
}

func unquoteSvcParamValue(value string) string {
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

// RDataPacksText reports whether rd serializes successfully to wire format.
// Parsers use it to reject presentation-form values that produce unpackable
// records (e.g. oversized fields).
func RDataPacksText(rd RData) bool {
	if rd == nil {
		return false
	}
	buf := make([]byte, rd.Len())
	_, err := rd.Pack(buf, 0)
	return err == nil
}

func parseUintField(s string, bitSize int) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, bitSize)
	if err != nil {
		return 0, false
	}
	return v, true
}
