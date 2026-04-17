package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func (s *Server) handleZones(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleListZones(w, r)
	case http.MethodPost:
		s.handleCreateZone(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleListZones returns list of zones with serial and record count.
func (s *Server) handleListZones(w http.ResponseWriter, _ *http.Request) {
	resp := &ZoneListResponse{Zones: []ZoneSummary{}}
	if s.zoneManager != nil {
		for name, z := range s.zoneManager.List() {
			z.RLock()
			recordCount := 0
			for _, records := range z.Records {
				recordCount += len(records)
			}
			serial := uint32(0)
			if z.SOA != nil {
				serial = z.SOA.Serial
			}
			z.RUnlock()
			resp.Zones = append(resp.Zones, ZoneSummary{
				Name:    name,
				Serial:  serial,
				Records: recordCount,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleZoneActions dispatches zone-specific operations based on path and method.
// Routes: DELETE /api/v1/zones/{name}
//
//	GET    /api/v1/zones/{name}/records
//	POST   /api/v1/zones/{name}/records
//	PUT    /api/v1/zones/{name}/records
//	DELETE /api/v1/zones/{name}/records
//	GET    /api/v1/zones/{name}/export
//
// SECURITY: All authenticated operators have global access to all zones.
// There is no per-zone or multi-tenant isolation. This is by design.
func (s *Server) handleZoneActions(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/zones/")

	// Decode URL-encoded zone name (e.g., "example.com." from "example.com.")
	zoneName, err := url.PathUnescape(path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid zone name")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	// Check if there's a sub-path after the zone name
	parts := strings.SplitN(zoneName, "/", 2)
	if len(parts) == 1 || parts[1] == "" {
		// /api/v1/zones/{name}
		switch r.Method {
		case http.MethodGet:
			s.handleGetZone(w, r, parts[0])
		case http.MethodDelete:
			s.handleDeleteZone(w, r, parts[0])
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	zoneName = parts[0]
	subPath := parts[1]

	switch subPath {
	case "records":
		switch r.Method {
		case http.MethodGet:
			s.handleGetRecords(w, r, zoneName)
		case http.MethodPost:
			s.handleAddRecord(w, r, zoneName)
		case http.MethodPut:
			s.handleUpdateRecord(w, r, zoneName)
		case http.MethodDelete:
			s.handleDeleteRecord(w, r, zoneName)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "export":
		if r.Method == http.MethodGet {
			s.handleExportZone(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "ptr-bulk":
		if r.Method == http.MethodPost {
			s.handleBulkPTR(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "ptr6-lookup":
		if r.Method == http.MethodGet {
			s.handlePtr6Lookup(w, r, zoneName)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		s.writeError(w, http.StatusNotFound, "Not found")
	}
}

// handleGetZone returns details of a single zone.
func (s *Server) handleGetZone(w http.ResponseWriter, _ *http.Request, name string) {
	z, ok := s.zoneManager.Get(name)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", name))
		return
	}

	z.RLock()
	defer z.RUnlock()

	recordCount := 0
	for _, records := range z.Records {
		recordCount += len(records)
	}

	result := &ZoneDetailResponse{
		Name:    z.Origin,
		Records: recordCount,
	}

	if z.SOA != nil {
		result.Serial = z.SOA.Serial
		result.SOA = &SOADetail{
			MName:   z.SOA.MName,
			RName:   z.SOA.RName,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		}
	}

	var nsList []string
	for _, ns := range z.NS {
		nsList = append(nsList, ns.NSDName)
	}
	result.Nameservers = nsList

	s.writeJSON(w, http.StatusOK, result)
}

// handleCreateZone creates a new zone.
func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	if s.requireOperator(w, r) {
		return
	}
	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	// VULN-071: use MaxBytesReader to prevent unbounded body reading
	var req struct {
		Name        string   `json:"name"`
		TTL         uint32   `json:"ttl"`
		AdminEmail  string   `json:"admin_email"`
		Nameservers []string `json:"nameservers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Zone name is required")
		return
	}
	if len(req.Nameservers) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one nameserver is required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = 3600
	}

	soa := &zone.SOARecord{
		TTL:     ttl,
		MName:   req.Nameservers[0],
		RName:   req.AdminEmail,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	var nsRecords []zone.NSRecord
	for _, ns := range req.Nameservers {
		nsRecords = append(nsRecords, zone.NSRecord{
			TTL:     ttl,
			NSDName: ns,
		})
	}

	if err := s.zoneManager.CreateZone(req.Name, ttl, soa, nsRecords); err != nil {
		s.writeError(w, http.StatusConflict, sanitizeError(err, "Failed to create zone"))
		return
	}

	s.writeJSON(w, http.StatusCreated, &MessageNameResponse{
		Message: fmt.Sprintf("Zone %s created", req.Name),
		Name:    req.Name,
	})
}

// handleDeleteZone deletes a zone.
func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request, name string) {
	if s.requireOperator(w, r) {
		return
	}
	if err := s.zoneManager.DeleteZone(name); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Failed to delete zone"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: fmt.Sprintf("Zone %s deleted", name),
	})
}

// handleGetRecords returns records for a zone.
func (s *Server) handleGetRecords(w http.ResponseWriter, r *http.Request, zoneName string) {
	name := r.URL.Query().Get("name")

	records, err := s.zoneManager.GetRecords(zoneName, name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	// Convert to API response
	resp := &RecordListResponse{Records: make([]RecordItem, 0, len(records))}
	for _, r := range records {
		resp.Records = append(resp.Records, RecordItem{
			Name:  r.Name,
			Type:  r.Type,
			TTL:   r.TTL,
			Class: r.Class,
			Data:  r.RData,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleAddRecord adds a record to a zone.
func (s *Server) handleAddRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	if s.requireOperator(w, r) {
		return
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading
	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
		TTL  uint32 `json:"ttl"`
		Data string `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" || req.Data == "" {
		s.writeError(w, http.StatusBadRequest, "name, type, and data are required")
		return
	}

	ttl := req.TTL
	if ttl == 0 {
		// Use zone's default TTL
		if z, ok := s.zoneManager.Get(zoneName); ok {
			z.RLock()
			ttl = z.DefaultTTL
			z.RUnlock()
		}
		if ttl == 0 {
			ttl = 3600
		}
	}

	record := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   ttl,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.AddRecord(zoneName, record); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	s.writeJSON(w, http.StatusCreated, &MessageResponse{
		Message: "Record added",
	})
}

// handleUpdateRecord updates a record in a zone.
func (s *Server) handleUpdateRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	if s.requireOperator(w, r) {
		return
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		OldData string `json:"old_data"`
		TTL     uint32 `json:"ttl"`
		Data    string `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	newRecord := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   req.TTL,
		Class: "IN",
		RData: req.Data,
	}

	if err := s.zoneManager.UpdateRecord(zoneName, req.Name, req.Type, req.OldData, newRecord); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Record updated",
	})
}

// handleDeleteRecord deletes a record from a zone.
func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request, zoneName string) {
	if s.requireOperator(w, r) {
		return
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading
	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	if err := s.zoneManager.DeleteRecord(zoneName, req.Name, req.Type); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Record deleted",
	})
}

// handleExportZone returns a zone in BIND format.
func (s *Server) handleExportZone(w http.ResponseWriter, _ *http.Request, zoneName string) {
	content, err := s.zoneManager.ExportZone(zoneName)
	if err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	safeName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, strings.TrimSuffix(zoneName, "."))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zone\"", safeName))
	if _, err := w.Write([]byte(content)); err != nil {
		util.Warnf("api: failed to write zone export: %v", err)
	}
}

// handleBulkPTR handles bulk PTR record creation with CIDR pattern.
func (s *Server) handleBulkPTR(w http.ResponseWriter, r *http.Request, zoneName string) {
	if s.requireOperator(w, r) {
		return
	}
	// VULN-071: use MaxBytesReader to prevent unbounded body reading
	var req struct {
		CIDR     string `json:"cidr"`
		Pattern  string `json:"pattern"`
		Override bool   `json:"override"`
		AddA     bool   `json:"addA"`
		Preview  bool   `json:"preview"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.CIDR == "" || req.Pattern == "" {
		s.writeError(w, http.StatusBadRequest, "cidr and pattern are required")
		return
	}

	_, ipNet, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid CIDR: %v", err))
		return
	}

	// Check that it's IPv4
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		s.writeError(w, http.StatusBadRequest, "Only IPv4 CIDR is supported")
		return
	}

	// Generate all IPs in range
	ones, _ := ipNet.Mask.Size()
	numIPs := 1 << (32 - ones)
	if numIPs > 65536 {
		s.writeError(w, http.StatusBadRequest, "CIDR too large (max /16)")
		return
	}

	// Validate pattern has required placeholders [A], [B], [C], [D]
	if !strings.Contains(req.Pattern, "[A]") || !strings.Contains(req.Pattern, "[B]") ||
		!strings.Contains(req.Pattern, "[C]") || !strings.Contains(req.Pattern, "[D]") {
		s.writeError(w, http.StatusBadRequest, "Pattern must contain [A], [B], [C], [D] placeholders")
		return
	}

	z, ok := s.zoneManager.Get(zoneName)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", zoneName))
		return
	}

	// Validate zone/CIDR compatibility
	zoneOrigin := z.Origin
	if _, err := validateZoneCIDR(zoneOrigin, ones); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
		return
	}

	// Analyze all records in one lock
	z.RLock()
	existingPTR := z.Records["PTR"]
	existingA := z.Records["A"]
	z.RUnlock()

	type change struct {
		IP        string `json:"ip"`
		PTRName   string `json:"ptrName"`
		AName     string `json:"aName,omitempty"`
		Action    string `json:"action"` // add, override, skip
		PTRExist  bool   `json:"ptrExist"`
		AExist    bool   `json:"aExist,omitempty"`
		OldPTR    string `json:"oldPtr,omitempty"`
		OldA      string `json:"oldA,omitempty"`
		RevRecord string `json:"revRecord"` // the relative PTR record name
	}

	changes := make([]change, 0, numIPs)
	add, addA, skip, override, overrideA := 0, 0, 0, 0, 0

	for i := 0; i < numIPs; i++ {
		ip := make(net.IP, 4)
		copy(ip, ip4)
		n := binary.BigEndian.Uint32(ip)
		binary.BigEndian.PutUint32(ip, n+uint32(i))

		a, b, c, d := ip[0], ip[1], ip[2], ip[3]
		ptrName := strings.ReplaceAll(strings.ReplaceAll(
			strings.ReplaceAll(strings.ReplaceAll(req.Pattern,
				"[A]", fmt.Sprintf("%d", a)),
				"[B]", fmt.Sprintf("%d", b)),
			"[C]", fmt.Sprintf("%d", c)),
			"[D]", fmt.Sprintf("%d", d))

		// Compute relative PTR record name within the zone
		revRecord := reverseIPv4Relative(ip.String(), zoneOrigin, ones)

		// Check existing PTR using relative name
		var oldPTR string
		ptrExist := false
		for _, rec := range existingPTR {
			if rec.Name == revRecord || rec.Name == revRecord+"." {
				ptrExist = true
				oldPTR = rec.RData
				break
			}
		}

		// Check existing A
		var oldA string
		aExist := false
		if req.AddA {
			for _, rec := range existingA {
				if rec.Name == ptrName || rec.Name == ptrName+"." {
					aExist = true
					oldA = rec.RData
					break
				}
			}
		}

		ch := change{
			IP:        ip.String(),
			PTRName:   ptrName,
			Action:    "add",
			PTRExist:  ptrExist,
			RevRecord: revRecord,
		}

		if ptrExist && !req.Override {
			ch.Action = "skip"
			skip++
		} else if ptrExist && req.Override {
			ch.Action = "override"
			ch.OldPTR = oldPTR
			override++
		} else {
			add++
		}

		if req.AddA {
			ch.AName = ptrName
			ch.AExist = aExist
			if aExist && !req.Override {
				ch.Action = "skip"
				skip++
			} else if aExist && req.Override {
				if ch.Action == "add" {
					ch.Action = "override"
				}
				ch.OldA = oldA
				overrideA++
			} else if !aExist {
				addA++
			}
		}

		changes = append(changes, ch)
	}

	// If preview, return just the analysis
	if req.Preview {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"preview":      true,
			"total":        numIPs,
			"willAdd":      add,
			"willAddA":     addA,
			"willSkip":     skip,
			"willOverride": override + overrideA,
			"changes":      changes,
		})
		return
	}

	// Actually apply changes
	added, addedA, exists, existsA, skipped := 0, 0, 0, 0, 0
	for _, ch := range changes {
		if ch.Action == "skip" {
			skipped++
			continue
		}

		if ch.Action == "override" || ch.Action == "add" {
			if ch.PTRExist {
				s.zoneManager.DeleteRecord(zoneName, ch.RevRecord, "PTR")
			}
			rec := zone.Record{
				Name:  ch.RevRecord,
				Type:  "PTR",
				Class: "IN",
				TTL:   3600,
				RData: ch.PTRName,
			}
			err := s.zoneManager.AddRecord(zoneName, rec)
			if err == nil {
				added++
			} else {
				exists++
			}
		}

		if req.AddA && ch.AName != "" {
			if ch.AExist {
				s.zoneManager.DeleteRecord(zoneName, ch.AName, "A")
			}
			aRec := zone.Record{
				Name:  ch.AName,
				Type:  "A",
				Class: "IN",
				TTL:   3600,
				RData: ch.IP,
			}
			err := s.zoneManager.AddRecord(zoneName, aRec)
			if err == nil {
				addedA++
			} else {
				existsA++
			}
		}
	}

	// Audit log
	util.Infof("bulk-ptr: zone=%s cidr=%s pattern=%s override=%v addA=%v added=%d addedA=%d skipped=%d exists=%d",
		zoneName, req.CIDR, req.Pattern, req.Override, req.AddA, added, addedA, skipped, exists)

	s.writeJSON(w, http.StatusOK, map[string]int{
		"added":   added,
		"addedA":  addedA,
		"exists":  exists,
		"existsA": existsA,
		"skipped": skipped,
	})
}

// handlePtr6Lookup performs a reverse lookup for an IPv6 address.
// This is a query-only operation - it does not create records.
// Query: GET /api/v1/zones/{zone}/ptr6-lookup?ip=<ipv6-address>
func (s *Server) handlePtr6Lookup(w http.ResponseWriter, r *http.Request, zoneName string) {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		s.writeError(w, http.StatusBadRequest, "IP parameter is required")
		return
	}

	// Parse IPv6 address
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid IPv6 address")
		return
	}

	// Verify zone exists and is an IPv6 reverse zone
	z, ok := s.zoneManager.Get(zoneName)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", zoneName))
		return
	}

	// Check if zone is an ip6.arpa zone
	if !strings.HasSuffix(z.Origin, "ip6.arpa.") {
		s.writeError(w, http.StatusBadRequest, "Zone is not an IPv6 reverse zone (must end with ip6.arpa.)")
		return
	}

	// Compute the IPv6 reverse name (nibble-based)
	// 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	ptrName := reverseIPv6(ip)

	// Lock zone for reading
	z.RLock()
	defer z.RUnlock()

	// Search for PTR record
	for _, rec := range z.Records["PTR"] {
		fqdn := rec.Name
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		target := ptrName + "."
		if fqdn == target || rec.Name == ptrName {
			s.writeJSON(w, http.StatusOK, map[string]interface{}{
				"ip":      ipStr,
				"ptr":     ptrName,
				"ptrFQDN": target,
				"target":  rec.RData,
				"ttl":     rec.TTL,
				"found":   true,
			})
			return
		}
	}

	// Not found
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":      ipStr,
		"ptr":     ptrName,
		"ptrFQDN": ptrName + ".",
		"found":   false,
	})
}

// reverseIPv6 computes the ip6.arpa reverse lookup name for an IPv6 address.
// Each nibble (4 bits) of the IPv6 address becomes a label in the reverse tree.
func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireAdmin(w, r) {
		return
	}

	zoneName := r.URL.Query().Get("zone")
	if zoneName == "" {
		s.writeError(w, http.StatusBadRequest, "Missing zone parameter")
		return
	}

	if s.zoneManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Zone manager not available")
		return
	}

	if err := s.zoneManager.Reload(zoneName); err != nil {
		s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to reload zone"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: fmt.Sprintf("Zone %s reloaded", zoneName),
	})
}

// handleCacheStats returns cache statistics.
