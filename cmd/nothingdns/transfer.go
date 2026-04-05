// NothingDNS - Zone transfers and dynamic updates

package main

import (
	"errors"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// handleAXFR handles zone transfer (AXFR) requests.
// AXFR must use TCP (RFC 5936 Section 4.1).
func (h *integratedHandler) handleAXFR(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()

	// AXFR requires TCP per RFC 5936
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("AXFR request over UDP from %s - refusing", clientInfo.String())
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	qname := q.Name.String()
	h.logger.Infof("AXFR request for %s from %s", qname, clientInfo.String())

	// Get client IP for access control
	clientIP := clientInfo.IP()

	// Handle AXFR using the AXFR server
	records, tsigKey, err := h.axfrServer.HandleAXFR(r, clientIP)
	if err != nil {
		h.logger.Warnf("AXFR failed for %s: %v", qname, err)
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	// Send AXFR response as multiple messages
	// Per RFC 5936: SOA + all zone records + SOA
	// Each message is sent separately over TCP
	// Per RFC 2845: sign the first and last messages with TSIG if key was used

	for i, rr := range records {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers:   []*protocol.ResourceRecord{rr},
		}

		// Sign first and last messages per RFC 2845
		if tsigKey != nil && (i == 0 || i == len(records)-1) {
			tsigRR, signErr := transfer.SignMessage(resp, tsigKey, 300)
			if signErr != nil {
				h.logger.Warnf("Failed to sign AXFR response: %v", signErr)
			} else {
				resp.Additionals = append(resp.Additionals, tsigRR)
			}
		}

		if _, err := w.Write(resp); err != nil {
			h.logger.Warnf("Failed to write AXFR response: %v", err)
			return
		}
	}

	h.logger.Infof("AXFR completed for %s - sent %d records", qname, len(records))

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
}

// handleIXFR handles incremental zone transfer (IXFR) requests.
// IXFR must use TCP (RFC 1995).
func (h *integratedHandler) handleIXFR(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()

	// IXFR requires TCP per RFC 1995
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("IXFR request over UDP from %s - refusing", clientInfo.String())
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	qname := q.Name.String()
	h.logger.Infof("IXFR request for %s from %s", qname, clientInfo.String())

	// Get client IP for access control
	clientIP := clientInfo.IP()

	// Handle IXFR using the IXFR server
	records, err := h.ixfrServer.HandleIXFR(r, clientIP)
	if err != nil {
		h.logger.Warnf("IXFR failed for %s: %v", qname, err)
		// Check if the error indicates AXFR fallback is needed
		if errors.Is(err, transfer.ErrNoJournal) || errors.Is(err, transfer.ErrSerialNotInRange) {
			h.logger.Infof("Falling back to AXFR for %s", qname)
			h.handleAXFR(w, r, q)
			return
		}
		sendError(w, r, protocol.RcodeRefused)
		return
	}

	// Send IXFR response as multiple messages
	// Per RFC 1995: The response format varies based on whether it's incremental or full AXFR
	for _, rr := range records {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers:   []*protocol.ResourceRecord{rr},
		}

		if _, err := w.Write(resp); err != nil {
			h.logger.Warnf("Failed to write IXFR response: %v", err)
			return
		}
	}

	h.logger.Infof("IXFR completed for %s - sent %d records", qname, len(records))

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
}

// handleNOTIFY handles NOTIFY requests from master servers (RFC 1996).
// NOTIFY informs slave servers that a zone has changed and should be refreshed.
func (h *integratedHandler) handleNOTIFY(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()

	h.logger.Infof("NOTIFY request for %s from %s", q.Name.String(), clientInfo.String())

	// Handle NOTIFY using the NOTIFY handler
	resp, err := h.notifyHandler.HandleNOTIFY(r, clientIP)
	if err != nil {
		h.logger.Warnf("NOTIFY handling failed for %s: %v", q.Name.String(), err)
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send NOTIFY response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write NOTIFY response: %v", err)
		return
	}

	h.logger.Infof("NOTIFY response sent for %s", q.Name.String())

	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}

	// Start a goroutine to listen for NOTIFY events and trigger zone transfers (once)
	h.notifyOnce.Do(func() { go h.processNotifyEvents() })
}

// processNotifyEvents listens for NOTIFY events and triggers zone transfers.
func (h *integratedHandler) processNotifyEvents() {
	notifyChan := h.notifyHandler.GetNotifyChannel()
	for req := range notifyChan {
		h.logger.Infof("Processing NOTIFY for zone %s (serial %d)", req.ZoneName, req.Serial)

		// Forward to slave manager if we have one
		if h.slaveManager != nil {
			select {
			case h.slaveManager.GetNotifyChannel() <- req:
				h.logger.Debugf("Forwarded NOTIFY for %s to slave manager", req.ZoneName)
			default:
				h.logger.Warnf("Slave manager notify channel full, dropping NOTIFY for %s", req.ZoneName)
			}
		}
	}
}

// handleUPDATE handles Dynamic DNS UPDATE requests (RFC 2136).
// UPDATE allows authenticated clients to dynamically modify DNS records.
func (h *integratedHandler) handleUPDATE(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()

	h.logger.Infof("UPDATE request for %s from %s", q.Name.String(), clientInfo.String())

	// Handle UPDATE using the Dynamic DNS handler
	resp, err := h.ddnsHandler.HandleUpdate(r, clientIP)
	if err != nil {
		h.logger.Warnf("UPDATE handling failed for %s: %v", q.Name.String(), err)
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send UPDATE response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write UPDATE response: %v", err)
		return
	}

	if resp.Header.Flags.RCODE == protocol.RcodeSuccess {
		h.logger.Infof("UPDATE successful for %s", q.Name.String())
	} else {
		h.logger.Warnf("UPDATE failed for %s with rcode %d", q.Name.String(), resp.Header.Flags.RCODE)
	}

	if h.metrics != nil {
		h.metrics.RecordResponse(resp.Header.Flags.RCODE)
	}

	// Start a goroutine to listen for update events and apply changes (once)
	h.updateOnce.Do(func() { go h.processUpdateEvents() })
}

// processUpdateEvents listens for update events and applies changes to zones.
func (h *integratedHandler) processUpdateEvents() {
	updateChan := h.ddnsHandler.GetUpdateChannel()
	for req := range updateChan {
		h.logger.Infof("Processing UPDATE for zone %s", req.ZoneName)

		// Get the zone
		h.zonesMu.RLock()
		z, ok := h.zones[req.ZoneName]
		h.zonesMu.RUnlock()
		if !ok {
			h.logger.Warnf("Zone %s not found for UPDATE", req.ZoneName)
			continue
		}

		// Record old serial for IXFR journal
		var oldSerial uint32
		if z.SOA != nil {
			oldSerial = z.SOA.Serial
		}

		// Apply the update
		if err := transfer.ApplyUpdate(z, req); err != nil {
			h.logger.Warnf("Failed to apply UPDATE to zone %s: %v", req.ZoneName, err)
			continue
		}

		// Record the change in the IXFR journal
		if h.ixfrServer != nil && z.SOA != nil {
			newSerial := z.SOA.Serial
			var added, deleted []zone.RecordChange
			for _, op := range req.Updates {
				change := zone.RecordChange{
					Name:  op.Name,
					Type:  op.Type,
					TTL:   op.TTL,
					RData: op.RData,
				}
				switch op.Operation {
				case transfer.UpdateOpAdd:
					added = append(added, change)
				case transfer.UpdateOpDelete, transfer.UpdateOpDeleteRRSet, transfer.UpdateOpDeleteName:
					deleted = append(deleted, change)
				}
			}
			h.recordZoneChange(req.ZoneName, oldSerial, newSerial, added, deleted)
		}

		h.logger.Infof("UPDATE applied to zone %s", req.ZoneName)

		// Persist zone file to disk if zoneDir is configured
		if err := h.zoneManager.PersistZone(req.ZoneName); err != nil {
			h.logger.Warnf("Failed to persist zone %s to disk: %v", req.ZoneName, err)
		}
	}
}

// recordZoneChange records a zone modification to the IXFR journal.
// This should be called whenever a zone is modified via dynamic updates.
func (h *integratedHandler) recordZoneChange(zoneName string, oldSerial, newSerial uint32, added, deleted []zone.RecordChange) {
	if h.ixfrServer == nil {
		return
	}

	h.ixfrServer.RecordChange(zoneName, oldSerial, newSerial, added, deleted)
	h.logger.Debugf("Recorded zone change for %s: serial %d -> %d (added: %d, deleted: %d)",
		zoneName, oldSerial, newSerial, len(added), len(deleted))
}
