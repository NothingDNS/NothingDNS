package nothingdns

import (
	"context"
	"strings"
)

// ZonesService handles zones, records, export and bulk PTR generation
// (the /api/v1/zones endpoints).
type ZonesService struct {
	t *Transport
}

// CreateZoneOptions carries the optional fields of POST /api/v1/zones. A nil
// field is omitted from the request, so the server applies its own default.
type CreateZoneOptions struct {
	// AdminEmail is the zone admin e-mail; the server derives the SOA rname
	// from it.
	AdminEmail *string
	// TTL is the default TTL for records in the new zone, in seconds.
	TTL *int
}

// AddRecordOptions carries the optional fields of a record create or replace.
type AddRecordOptions struct {
	// TTL is the record TTL, in seconds; the zone default is used when nil.
	TTL *int
}

// PTRBulkOptions tunes Zones.PTRBulk. A nil field is omitted; Preview defaults
// to true on the server, so set it explicitly to apply changes.
type PTRBulkOptions struct {
	// Override replaces records that already exist instead of skipping them.
	Override *bool
	// AddA also creates the matching A records (forward-confirmed PTR).
	AddA *bool
	// Preview, when true, writes nothing and returns the planned changes.
	Preview *bool
}

// createZoneRequest is the JSON body of POST /api/v1/zones.
type createZoneRequest struct {
	Name        string   `json:"name"`
	NameServers []string `json:"nameservers"`
	AdminEmail  *string  `json:"admin_email,omitempty"`
	TTL         *int     `json:"ttl,omitempty"`
}

// addRecordRequest is the JSON body of POST /api/v1/zones/{zone}/records.
type addRecordRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  *int   `json:"ttl,omitempty"`
}

// replaceRecordRequest is the JSON body of PUT /api/v1/zones/{zone}/records.
type replaceRecordRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	OldData string `json:"old_data"`
	Data    string `json:"data"`
	TTL     *int   `json:"ttl,omitempty"`
}

// deleteRecordRequest is the JSON body of DELETE /api/v1/zones/{zone}/records.
type deleteRecordRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Data, when set, limits the delete to the one record with this RDATA.
	Data string `json:"data,omitempty"`
}

// ptrBulkRequest is the JSON body of POST /api/v1/zones/{zone}/ptr-bulk. Note
// the camelCase addA key on the wire.
type ptrBulkRequest struct {
	CIDR    string `json:"cidr"`
	Pattern string `json:"pattern"`
	Overide *bool  `json:"override,omitempty"`
	AddA    *bool  `json:"addA,omitempty"`
	Preview *bool  `json:"preview,omitempty"`
}

// List lists every zone served by this node. It requires the operator role or
// higher.
//
// When the returned ZoneList has Truncated set, the server capped the response
// and Total may be larger than len(Zones).
func (s *ZonesService) List(ctx context.Context) (*ZoneList, error) {
	var out ZoneList
	if err := s.t.doJSON(ctx, "GET", "/api/v1/zones", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Create creates a new authoritative zone. It requires the operator role or
// higher.
//
// name is the zone name, e.g. "example.com"; a trailing dot is added when
// missing, so both forms work. nameServers are the NS hostnames written into
// the zone's SOA record. opts carries the optional admin e-mail and default
// TTL. It returns the server's confirmation message.
//
// It fails with an *ErrValidationError when nameServers is empty, or an
// *ErrAPIError carrying status 409 when the zone already exists or 421 when
// the name cannot become its own zone (for example because it is a subdomain
// of an existing zone).
func (s *ZonesService) Create(ctx context.Context, name string, nameServers []string, opts *CreateZoneOptions) (string, error) {
	if len(nameServers) == 0 {
		return "", &ErrValidationError{Message: "nameServers must contain at least one hostname"}
	}
	var body createZoneRequest
	body.Name = name
	body.NameServers = nameServers
	if opts != nil {
		body.AdminEmail = opts.AdminEmail
		body.TTL = opts.TTL
	}
	return s.t.doMessage(ctx, "POST", "/api/v1/zones", nil, body)
}

// Get returns one zone with its SOA record and NS set. It requires the
// operator role or higher. zone is the zone name; a trailing dot is optional.
//
// It fails with an *ErrAPIError carrying status 404 when the zone does not
// exist.
func (s *ZonesService) Get(ctx context.Context, zone string) (*ZoneDetail, error) {
	var out ZoneDetail
	if err := s.t.doJSON(ctx, "GET", "/api/v1/zones/"+s.t.escape(zone), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete deletes a zone together with all of its records. It requires the
// operator role or higher. It returns the server's confirmation message.
func (s *ZonesService) Delete(ctx context.Context, zone string) (string, error) {
	return s.t.doMessage(ctx, "DELETE", "/api/v1/zones/"+s.t.escape(zone), nil, nil)
}

// Reload re-reads one zone from its on-disk zone file. It requires the admin
// role. Call it after editing a zone file by hand; a full config reload
// (Config.Reload) also re-reads every zone. It returns the server's
// confirmation message.
func (s *ZonesService) Reload(ctx context.Context, zone string) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/zones/reload", map[string]any{"zone": zone}, nil)
}

// Transfers lists secondary (slave) zones and their transfer state. It
// requires the operator role or higher.
//
// It returns one entry per zone this node serves as a secondary, with the
// master address, serial, status and record count.
func (s *ZonesService) Transfers(ctx context.Context) ([]SlaveZone, error) {
	var out struct {
		SlaveZones []SlaveZone `json:"slave_zones"`
	}
	if err := s.t.doJSON(ctx, "GET", "/api/v1/zones/transfers", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.SlaveZones, nil
}

// ListRecords lists records in a zone. It requires the operator role or
// higher.
//
// zone is the zone name. nameFilter optionally restricts the result to one
// owner name — "www" or "www.example.com". Check the returned RecordList's
// Truncated before relying on Total for large zones.
func (s *ZonesService) ListRecords(ctx context.Context, zone, nameFilter string) (*RecordList, error) {
	query := map[string]any{}
	if nameFilter != "" {
		query["name"] = nameFilter
	}
	var out RecordList
	if err := s.t.doJSON(ctx, "GET", "/api/v1/zones/"+s.t.escape(zone)+"/records", query, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddRecord adds a record to a zone. It requires the operator role or higher.
//
// zone is the zone name; name is the owner name relative to the zone, where
// "@" is the apex; rtype is the record type (e.g. "A", "AAAA", "CNAME", "MX",
// "TXT", "SRV", "CAA", "PTR"); data is the record data in zone-file
// presentation format (a bare address for A, the target hostname for MX/SRV,
// quoted text for TXT); opts optionally sets a TTL. It returns the server's
// confirmation message.
//
// It fails with an *ErrAPIError carrying status 400 for invalid record data
// or 421 when the record conflicts with one that already exists.
func (s *ZonesService) AddRecord(ctx context.Context, zone, name, rtype, data string, opts *AddRecordOptions) (string, error) {
	var body addRecordRequest
	body.Name = name
	body.Type = rtype
	body.Data = data
	if opts != nil {
		body.TTL = opts.TTL
	}
	return s.t.doMessage(ctx, "POST", "/api/v1/zones/"+s.t.escape(zone)+"/records", nil, body)
}

// ReplaceRecord replaces the data of an existing record. It requires the
// operator role or higher.
//
// The server identifies the record by (name, type, oldData), so pass the
// record's current data as oldData and the new value as data. It returns the
// server's confirmation message.
func (s *ZonesService) ReplaceRecord(ctx context.Context, zone, name, rtype, oldData, data string, opts *AddRecordOptions) (string, error) {
	var body replaceRecordRequest
	body.Name = name
	body.Type = rtype
	body.OldData = oldData
	body.Data = data
	if opts != nil {
		body.TTL = opts.TTL
	}
	return s.t.doMessage(ctx, "PUT", "/api/v1/zones/"+s.t.escape(zone)+"/records", nil, body)
}

// DeleteRecords deletes every record of rtype owned by name. It requires the
// operator role or higher.
//
// All records of this type for the owner are removed, so pass "A" to clear
// every address of a host. It returns the server's confirmation message.
func (s *ZonesService) DeleteRecords(ctx context.Context, zone, name, rtype string) (string, error) {
	body := deleteRecordRequest{Name: name, Type: rtype}
	return s.t.doMessage(ctx, "DELETE", "/api/v1/zones/"+s.t.escape(zone)+"/records", nil, body)
}

// DeleteRecord deletes the single record of rtype owned by name whose RDATA
// equals data, leaving the other records of the RRset in place. It requires
// the operator role or higher. The server compares RDATA in canonical form
// (domain names case-insensitively, TXT exactly). It returns the server's
// confirmation message.
//
// It fails with an *ErrAPIError carrying status 404 (see IsNotFound) when no
// record matches, and with an *ErrValidationError, without sending a request,
// when data is blank — an empty data field would delete the whole RRset; use
// DeleteRecords for that. SOA records and the zone apex NS RRset are refused
// with 400 (see IsBadRequest).
func (s *ZonesService) DeleteRecord(ctx context.Context, zone, name, rtype, data string) (string, error) {
	if strings.TrimSpace(data) == "" {
		return "", &ErrValidationError{Message: "data is required to delete a single record; use DeleteRecords to delete the whole RRset"}
	}
	body := deleteRecordRequest{Name: name, Type: rtype, Data: data}
	return s.t.doMessage(ctx, "DELETE", "/api/v1/zones/"+s.t.escape(zone)+"/records", nil, body)
}

// Export exports a zone in BIND zone-file format. It requires the operator
// role or higher. It returns the raw zone-file text, ready to write to disk or
// feed to named-checkzone.
func (s *ZonesService) Export(ctx context.Context, zone string) (string, error) {
	return s.t.doText(ctx, "GET", "/api/v1/zones/"+s.t.escape(zone)+"/export", nil)
}

// PTRBulk generates PTR (and optionally forward-confirmed A) records for an
// IPv4 range. It requires the operator role or higher.
//
// zone is the reverse zone, e.g. "2.0.192.in-addr.arpa". cidr is the IPv4
// CIDR to cover, e.g. "192.0.2.0/24"; ranges larger than a /16 are rejected by
// the server. pattern is the target hostname template, where "{ip}" is
// replaced with the address, e.g. "host-{ip}.example.com". opts tunes
// override/addA/preview (see PTRBulkOptions).
//
// The returned PTRBulkResponse carries the planned counters and Changes when
// opts.Preview is true, or the applied Added/Exists/Skipped counters when it
// is false.
//
// It fails with an *ErrAPIError carrying status 400 for an invalid CIDR, a
// non-IPv4 range or an oversized range.
func (s *ZonesService) PTRBulk(ctx context.Context, zone, cidr, pattern string, opts *PTRBulkOptions) (*PTRBulkResponse, error) {
	var body ptrBulkRequest
	body.CIDR = cidr
	body.Pattern = pattern
	if opts != nil {
		body.Overide = opts.Override
		body.AddA = opts.AddA
		body.Preview = opts.Preview
	}
	var out PTRBulkResponse
	if err := s.t.doJSON(ctx, "POST", "/api/v1/zones/"+s.t.escape(zone)+"/ptr-bulk", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PTR6Lookup looks up the PTR record for an IPv6 address in a zone. It
// requires the operator role or higher.
//
// zone is the IPv6 reverse zone, e.g. "8.b.d.0.1.0.0.2.ip6.arpa"; ip is the
// IPv6 address to resolve. Check the returned PTRLookup's Found before reading
// its PTR/Target fields.
func (s *ZonesService) PTR6Lookup(ctx context.Context, zone, ip string) (*PTRLookup, error) {
	var out PTRLookup
	if err := s.t.doJSON(ctx, "GET", "/api/v1/zones/"+s.t.escape(zone)+"/ptr6-lookup", map[string]any{"ip": ip}, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
