package api

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const maxBulkPTRPatternLength = 255

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
	zs := NewZoneService(s.zoneManager)
	resp := zs.ListZones()
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
	zs := NewZoneService(s.zoneManager)
	result, ok := zs.GetZone(name)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Zone %s not found", name))
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

// handleCreateZone creates a new zone.
// proposeZoneWrite routes a zone mutation through Raft consensus when the
// cluster runs in Raft mode, so the write replicates to every node before
// the API reports success. Returns:
//
//	routed=false → cluster is not in Raft mode; the caller performs its
//	               normal direct zoneManager write.
//	routed=true  → Raft handled it; ok=true means the change committed and
//	               applied locally (caller should emit its success response),
//	               ok=false means an HTTP error was already written (e.g. 421
//	               when this node is not the leader).
func (s *Server) proposeZoneWrite(w http.ResponseWriter, propose func() error) (routed, ok bool) {
	if s.cluster == nil || !s.cluster.IsRaftMode() {
		return false, false
	}
	if err := propose(); err != nil {
		if leader, isNL := s.cluster.IsNotLeaderError(err); isNL {
			msg := "not the Raft leader; retry the write against the current leader"
			if leader != "" {
				msg = "not the Raft leader; retry against " + leader
			}
			s.writeError(w, http.StatusMisdirectedRequest, msg)
			return true, false
		}
		s.writeError(w, http.StatusServiceUnavailable, sanitizeError(err, "Failed to replicate change"))
		return true, false
	}
	return true, true
}

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
	if !s.decode(w, r, &req) {
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

	if _, err := zone.SOAMailbox(req.AdminEmail, req.Name); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid admin email"))
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

	if routed, ok := s.proposeZoneWrite(w, func() error {
		return s.cluster.ProposeCreateZone(req.Name, ttl, req.AdminEmail, req.Nameservers)
	}); routed {
		if !ok {
			return
		}
	} else if err := s.zoneManager.CreateZone(req.Name, ttl, soa, nsRecords); err != nil {
		s.writeError(w, http.StatusConflict, sanitizeError(err, "Failed to create zone"))
		return
	}

	// KV durability is handled by the zone.Manager mutation hook (installed
	// by KVPersistence.Enable), so every mutation path — REST, Raft
	// apply — persists automatically. Persistence is best-effort (logged,
	// not surfaced): previously these handlers returned 500 on a KV persist
	// failure even though the mutation had already succeeded in memory.

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
	if routed, ok := s.proposeZoneWrite(w, func() error {
		return s.cluster.ProposeDeleteZone(name)
	}); routed {
		if !ok {
			return
		}
	} else if err := s.zoneManager.DeleteZone(name); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Failed to delete zone"))
		return
	}
	// KV removal handled by the zone.Manager mutation hook (deleted=true).

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

	// L-10: cap the response at RecordListMaxResults. Total reflects
	// the unfiltered record count; Truncated tells the client more
	// exist. A million-record reverse zone would otherwise build a
	// proportional JSON document and lock up the operator's browser.
	total := len(records)
	limit := total
	truncated := false
	if limit > RecordListMaxResults {
		limit = RecordListMaxResults
		truncated = true
	}
	resp := &RecordListResponse{
		Records:   make([]RecordItem, 0, limit),
		Total:     total,
		Truncated: truncated,
	}
	for _, r := range records[:limit] {
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
	if !s.decode(w, r, &req) {
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
			ttl = z.GetDefaultTTL()
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

	if routed, ok := s.proposeZoneWrite(w, func() error {
		return s.cluster.ProposeAddRecord(zoneName, record.Name, record.Type, record.Class, record.TTL, record.RData)
	}); routed {
		if !ok {
			return
		}
	} else if err := s.zoneManager.AddRecord(zoneName, record); err != nil {
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
		// TTL is optional: omitted keeps the record's current TTL, while an
		// explicit 0 (no caching) is honoured.
		TTL  *uint32 `json:"ttl"`
		Data string  `json:"data"`
	}
	if !s.decode(w, r, &req) {
		return
	}

	if req.Name == "" || req.Type == "" || req.OldData == "" || req.Data == "" {
		s.writeError(w, http.StatusBadRequest, "name, type, old_data, and data are required")
		return
	}

	var ttl uint32
	if req.TTL != nil {
		ttl = *req.TTL
	} else if current, ok := s.currentRecordTTL(zoneName, req.Name, req.Type, req.OldData); ok {
		ttl = current
	} else {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("record not found: %s %s %s", req.Name, req.Type, req.OldData))
		return
	}

	newRecord := zone.Record{
		Name:  req.Name,
		Type:  req.Type,
		TTL:   ttl,
		Class: "IN",
		RData: req.Data,
	}

	if routed, ok := s.proposeZoneWrite(w, func() error {
		return s.cluster.ProposeUpdateRecord(zoneName, newRecord.Name, newRecord.Type, req.OldData, newRecord.Class, newRecord.TTL, newRecord.RData)
	}); routed {
		if !ok {
			return
		}
	} else if err := s.zoneManager.UpdateRecord(zoneName, req.Name, req.Type, req.OldData, newRecord); err != nil {
		s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
		return
	}

	s.writeJSON(w, http.StatusOK, &MessageResponse{
		Message: "Record updated",
	})
}

// currentRecordTTL returns the TTL of the record an update targets, so an
// update that omits ttl keeps it instead of resetting it to 0.
func (s *Server) currentRecordTTL(zoneName, name, rtype, oldData string) (uint32, bool) {
	if s.zoneManager == nil {
		return 0, false
	}
	records, err := s.zoneManager.GetRecords(zoneName, name)
	if err != nil {
		return 0, false
	}
	for _, rec := range records {
		if strings.EqualFold(rec.Type, rtype) && strings.EqualFold(rec.RData, oldData) {
			return rec.TTL, true
		}
	}
	return 0, false
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
	if !s.decode(w, r, &req) {
		return
	}

	if req.Name == "" || req.Type == "" {
		s.writeError(w, http.StatusBadRequest, "name and type are required")
		return
	}

	if routed, ok := s.proposeZoneWrite(w, func() error {
		return s.cluster.ProposeDeleteRecord(zoneName, req.Name, req.Type)
	}); routed {
		if !ok {
			return
		}
	} else if err := s.zoneManager.DeleteRecord(zoneName, req.Name, req.Type); err != nil {
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
	if !s.decode(w, r, &req) {
		return
	}

	if req.CIDR == "" || req.Pattern == "" {
		s.writeError(w, http.StatusBadRequest, "cidr and pattern are required")
		return
	}
	if len(req.Pattern) > maxBulkPTRPatternLength {
		s.writeError(w, http.StatusBadRequest, "pattern too long")
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
	zoneOrigin := z.GetOrigin()
	if _, err := validateZoneCIDRNetwork(zoneOrigin, ip4, ones); err != nil {
		s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid request"))
		return
	}

	// Analyze existing records (thread-safe, no explicit lock needed)
	existingPTR := z.RecordsByType("PTR")
	existingA := z.RecordsByType("A")

	changes := make([]ReverseDNSChange, 0, numIPs)
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
			if bulkPTROwnerMatches(rec.Name, revRecord, zoneOrigin) {
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
				if bulkPTROwnerMatches(rec.Name, ptrName, zoneOrigin) {
					aExist = true
					oldA = rec.RData
					break
				}
			}
		}

		ch := ReverseDNSChange{
			IP:        ip.String(),
			PTRName:   ptrName,
			Action:    "add",
			PTRExist:  ptrExist,
			RevRecord: revRecord,
		}

		if ptrExist && !req.Override {
			ch.Action = "skip"
			ch.OldPTR = oldPTR
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
				ch.OldA = oldA
			} else if aExist && req.Override {
				ch.OldA = oldA
				overrideA++
			} else if !aExist && ch.Action != "skip" {
				// Skip entries are not applied at all (no PTR, no A),
				// so they must not be counted as pending A additions.
				addA++
			}
		}

		changes = append(changes, ch)
	}

	// If preview, return just the analysis
	if req.Preview {
		s.writeJSON(w, http.StatusOK, ReverseDNSPreviewResponse{
			Preview:      true,
			Total:        numIPs,
			WillAdd:      add,
			WillAddA:     addA,
			WillSkip:     skip,
			WillOverride: override + overrideA,
			Changes:      changes,
		})
		return
	}

	// Actually apply changes
	added, addedA, exists, existsA, skipped := 0, 0, 0, 0, 0
	for _, ch := range changes {
		if ch.Action == "skip" {
			// Non-override mode with an existing PTR: do not mutate anything
			// for this entry — neither the PTR nor a forward A record.
			skipped++
			continue
		}
		if ch.Action == "override" || ch.Action == "add" {
			if ch.PTRExist {
				if err := s.zoneManager.DeleteRecord(zoneName, ch.RevRecord, "PTR"); err != nil {
					s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete existing PTR record: %v", err))
					return
				}
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
				if !req.Override {
					existsA++
					continue
				}
				if err := s.zoneManager.DeleteRecord(zoneName, ch.AName, "A"); err != nil {
					s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete existing A record: %v", err))
					return
				}
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

	s.writeJSON(w, http.StatusOK, BulkPTRResultResponse{
		Added:   added,
		AddedA:  addedA,
		Exists:  exists,
		ExistsA: existsA,
		Skipped: skipped,
	})
}

func bulkPTROwnerMatches(recordName, owner, zoneOrigin string) bool {
	recordName = strings.TrimSuffix(strings.ToLower(recordName), ".")
	owner = strings.TrimSuffix(strings.ToLower(owner), ".")
	if recordName == owner {
		return true
	}

	zoneOrigin = strings.TrimSuffix(strings.ToLower(zoneOrigin), ".")
	if zoneOrigin == "" || owner == zoneOrigin || strings.HasSuffix(owner, "."+zoneOrigin) {
		return false
	}
	return recordName == owner+"."+zoneOrigin
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
	if !strings.HasSuffix(z.GetOrigin(), "ip6.arpa.") {
		s.writeError(w, http.StatusBadRequest, "Zone is not an IPv6 reverse zone (must end with ip6.arpa.)")
		return
	}

	// Compute the IPv6 reverse name (nibble-based)
	// 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	ptrName := reverseIPv6(ip)

	// Search for PTR record (thread-safe via RecordsByType)
	zoneOrigin := z.GetOrigin()
	for _, rec := range z.RecordsByType("PTR") {
		target := ptrName + "."
		if bulkPTROwnerMatches(rec.Name, ptrName, zoneOrigin) {
			s.writeJSON(w, http.StatusOK, PTRLookupResponse{
				IP:      ipStr,
				PTR:     ptrName,
				PTRFQDN: target,
				Target:  rec.RData,
				TTL:     rec.TTL,
				Found:   true,
			})
			return
		}
	}

	// Not found
	s.writeJSON(w, http.StatusOK, PTRLookupResponse{
		IP:      ipStr,
		PTR:     ptrName,
		PTRFQDN: ptrName + ".",
		Found:   false,
	})
}

// reverseIPv6 computes the ip6.arpa reverse lookup name for an IPv6 address.
// Each nibble (4 bits) of the IPv6 address becomes a label in the reverse tree.
func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodPost) {
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
