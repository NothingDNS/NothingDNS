package doh

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ContentTypeDNSJSON is the MIME type for DNS JSON API responses.
const ContentTypeDNSJSON = "application/dns-json"

// JSONResponse represents a DNS-over-HTTPS JSON API response,
// matching the Google/Cloudflare JSON API format.
type JSONResponse struct {
	Status     int            `json:"Status"`
	TC         bool           `json:"TC"`
	RD         bool           `json:"RD"`
	RA         bool           `json:"RA"`
	AD         bool           `json:"AD"`
	CD         bool           `json:"CD"`
	Question   []JSONQuestion `json:"Question,omitempty"`
	Answer     []JSONRecord   `json:"Answer,omitempty"`
	Authority  []JSONRecord   `json:"Authority,omitempty"`
	Additional []JSONRecord   `json:"Additional,omitempty"`
}

// JSONQuestion represents a question entry in the JSON API format.
type JSONQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// JSONRecord represents a resource record in the JSON API format.
type JSONRecord struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// EncodeJSON converts a DNS message to the JSON API format.
func EncodeJSON(msg *protocol.Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message")
	}

	resp := JSONResponse{
		Status: int(msg.Header.Flags.RCODE),
		TC:     msg.Header.Flags.TC,
		RD:     msg.Header.Flags.RD,
		RA:     msg.Header.Flags.RA,
		AD:     msg.Header.Flags.AD,
		CD:     msg.Header.Flags.CD,
	}

	// Encode questions
	for _, q := range msg.Questions {
		if q == nil || q.Name == nil {
			continue
		}
		resp.Question = append(resp.Question, JSONQuestion{
			Name: q.Name.String(),
			Type: q.QType,
		})
	}

	// Encode answers
	resp.Answer = encodeRecords(msg.Answers)

	// Encode authority
	resp.Authority = encodeRecords(msg.Authorities)

	// Encode additional, skipping OPT records (EDNS0 pseudo-records)
	resp.Additional = encodeRecords(filterOPT(msg.Additionals))

	return json.Marshal(resp)
}

// encodeRecords converts a slice of ResourceRecords to JSONRecord entries.
func encodeRecords(records []*protocol.ResourceRecord) []JSONRecord {
	if len(records) == 0 {
		return nil
	}

	result := make([]JSONRecord, 0, len(records))
	for _, rr := range records {
		if rr == nil || rr.Name == nil {
			continue
		}
		data := ""
		if rr.Data != nil {
			data = rr.Data.String()
		}
		result = append(result, JSONRecord{
			Name: rr.Name.String(),
			Type: rr.Type,
			TTL:  rr.TTL,
			Data: data,
		})
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// filterOPT returns records with OPT pseudo-records removed.
func filterOPT(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	if len(records) == 0 {
		return nil
	}

	result := make([]*protocol.ResourceRecord, 0, len(records))
	for _, rr := range records {
		if rr != nil && rr.Type != protocol.TypeOPT {
			result = append(result, rr)
		}
	}
	return result
}

// DecodeJSONQuery decodes a JSON query body into a DNS message.
// The expected JSON format contains "name" and "type" fields.
func DecodeJSONQuery(data []byte) (*protocol.Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty JSON query")
	}

	var query struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &query); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return ParseJSONQueryParams(query.Name, query.Type)
}

// ParseJSONQueryParams builds a DNS query message from URL query parameters.
// The name parameter is the domain name to query.
// The qtype parameter is the query type as a string (e.g., "A", "AAAA") or
// a numeric type value (e.g., "1", "28").
func ParseJSONQueryParams(name string, qtype string) (*protocol.Message, error) {
	if name == "" {
		return nil, fmt.Errorf("missing query name")
	}

	// Ensure the name is fully qualified
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	// Resolve the query type
	var typeVal uint16
	if qtype == "" {
		// Default to A record
		typeVal = protocol.TypeA
	} else {
		// Try as a string type first (e.g., "A", "AAAA", "MX")
		if t, ok := protocol.StringToType[strings.ToUpper(qtype)]; ok {
			typeVal = t
		} else {
			// Try as a numeric type
			n, err := strconv.ParseUint(qtype, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("unknown query type: %s", qtype)
			}
			typeVal = uint16(n)
		}
	}

	msg, err := protocol.NewQuery(0, name, typeVal)
	if err != nil {
		return nil, fmt.Errorf("building query: %w", err)
	}

	return msg, nil
}
