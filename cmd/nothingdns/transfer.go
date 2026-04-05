// NothingDNS - Zone transfers and dynamic updates

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
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

	start := time.Now()
	qname := q.Name.String()
	clientIP := clientInfo.IP()
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}

	h.logger.Infof("AXFR request for %s from %s", qname, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
			Timestamp: start.UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      qname,
			Action:    "request",
		})
	}

	// Get client IP for access control
	// Handle AXFR using the AXFR server
	records, tsigKey, err := h.axfrServer.HandleAXFR(r, clientIP)
	if err != nil {
		h.logger.Warnf("AXFR failed for %s: %v", qname, err)
		if h.auditLogger != nil {
			h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  cipStr,
				Zone:      qname,
				Action:    "failed",
				Latency:   time.Since(start),
			})
		}
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
				if h.auditLogger != nil {
					h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
						Timestamp: time.Now().UTC().Format(time.RFC3339),
						ClientIP:  cipStr,
						Zone:      qname,
						Action:    "failed",
						Latency:   time.Since(start),
					})
				}
				sendError(w, r, protocol.RcodeServerFailure)
				return
			}
			resp.Additionals = append(resp.Additionals, tsigRR)
		}

		if _, err := w.Write(resp); err != nil {
			h.logger.Warnf("Failed to write AXFR response: %v", err)
			if h.auditLogger != nil {
				h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					ClientIP:  cipStr,
					Zone:      qname,
					Action:    "failed",
					Latency:   time.Since(start),
				})
			}
			return
		}
	}

	h.logger.Infof("AXFR completed for %s - sent %d records", qname, len(records))
	if h.auditLogger != nil {
		h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ClientIP:    cipStr,
			Zone:        qname,
			Action:      "completed",
			RecordCount: len(records),
			Latency:     time.Since(start),
		})
	}

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

	start := time.Now()
	qname := q.Name.String()
	clientIP := clientInfo.IP()
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}

	h.logger.Infof("IXFR request for %s from %s", qname, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
			Timestamp: start.UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      qname,
			Action:    "request",
		})
	}

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
		if h.auditLogger != nil {
			h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  cipStr,
				Zone:      qname,
				Action:    "failed",
				Latency:   time.Since(start),
			})
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
			if h.auditLogger != nil {
				h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					ClientIP:  cipStr,
					Zone:      qname,
					Action:    "failed",
					Latency:   time.Since(start),
				})
			}
			return
		}
	}

	h.logger.Infof("IXFR completed for %s - sent %d records", qname, len(records))
	if h.auditLogger != nil {
		h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ClientIP:    cipStr,
			Zone:        qname,
			Action:      "completed",
			RecordCount: len(records),
			Latency:     time.Since(start),
		})
	}

	if h.metrics != nil {
		h.metrics.RecordResponse(protocol.RcodeSuccess)
	}
}

// handleNOTIFY handles NOTIFY requests from master servers (RFC 1996).
// NOTIFY informs slave servers that a zone has changed and should be refreshed.
func (h *integratedHandler) handleNOTIFY(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}
	zoneName := q.Name.String()
	now := time.Now().UTC().Format(time.RFC3339)

	h.logger.Infof("NOTIFY request for %s from %s", zoneName, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
			Timestamp: now,
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "received",
		})
	}

	// Handle NOTIFY using the NOTIFY handler
	resp, err := h.notifyHandler.HandleNOTIFY(r, clientIP)
	if err != nil {
		h.logger.Warnf("NOTIFY handling failed for %s: %v", zoneName, err)
		if h.auditLogger != nil {
			h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
				Timestamp: now,
				ClientIP:  cipStr,
				Zone:      zoneName,
				Action:    "rejected",
			})
		}
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send NOTIFY response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write NOTIFY response: %v", err)
		return
	}

	h.logger.Infof("NOTIFY response sent for %s", zoneName)
	if h.auditLogger != nil {
		h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "accepted",
		})
	}

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
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}
	zoneName := q.Name.String()
	now := time.Now().UTC().Format(time.RFC3339)

	h.logger.Infof("UPDATE request for %s from %s", zoneName, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
			Timestamp: now,
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "request",
		})
	}

	// Handle UPDATE using the Dynamic DNS handler
	resp, err := h.ddnsHandler.HandleUpdate(r, clientIP)
	if err != nil {
		h.logger.Warnf("UPDATE handling failed for %s: %v", zoneName, err)
		if h.auditLogger != nil {
			h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
				Timestamp: now,
				ClientIP:  cipStr,
				Zone:      zoneName,
				Action:    "failure",
				Rcode:     fmt.Sprintf("%d", protocol.RcodeServerFailure),
			})
		}
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}

	// Send UPDATE response
	if _, err := w.Write(resp); err != nil {
		h.logger.Warnf("Failed to write UPDATE response: %v", err)
		return
	}

	action := "failure"
	if resp.Header.Flags.RCODE == protocol.RcodeSuccess {
		h.logger.Infof("UPDATE successful for %s", zoneName)
		action = "success"
	} else {
		h.logger.Warnf("UPDATE failed for %s with rcode %d", zoneName, resp.Header.Flags.RCODE)
		action = "failure"
	}
	if h.auditLogger != nil {
		h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    action,
			Rcode:     fmt.Sprintf("%d", resp.Header.Flags.RCODE),
		})
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

		// Count added/deleted records
		var addedCount, deletedCount int
		for _, op := range req.Updates {
			switch op.Operation {
			case transfer.UpdateOpAdd:
				addedCount++
			case transfer.UpdateOpDelete, transfer.UpdateOpDeleteRRSet, transfer.UpdateOpDeleteName:
				deletedCount++
			}
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
		if h.auditLogger != nil {
			h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  "-",
				Zone:      req.ZoneName,
				Action:    "applied",
				Added:     addedCount,
				Deleted:   deletedCount,
			})
		}

		// Persist zone to KV store if KVPersistence is available
		if h.kvPersistence != nil {
			if err := h.kvPersistence.PersistZone(req.ZoneName); err != nil {
				h.logger.Warnf("Failed to persist zone %s to KV store: %v", req.ZoneName, err)
			}
		}

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
