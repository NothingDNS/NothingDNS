// NothingDNS - Zone transfers and dynamic updates

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// handleAXFR handles zone transfer (AXFR) requests.
// AXFR must use TCP (RFC 5936 Section 4.1).
func (h *integratedHandler) handleAXFR(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	clientInfo := w.ClientInfo()
	reqID := util.GenerateRequestID()

	// AXFR requires TCP per RFC 5936
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("[%s] AXFR request over UDP from %s - refusing", reqID, clientInfo.String())
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

	h.logger.Infof("[%s] AXFR request for %s from %s", reqID, qname, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
			RequestID: reqID,
			Timestamp: start.UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      qname,
			Action:    "request",
		})
	}

	// Get client IP for access control
	// Handle AXFR using the AXFR server
	// Authenticate against one consistent TSIG key set (F583).
	h.xferKeysMu.RLock()
	records, tsigKey, err := h.transfer.AXFRServer.HandleAXFR(r, clientIP)
	h.xferKeysMu.RUnlock()
	if err != nil {
		h.logger.Warnf("[%s] AXFR failed for %s: %v", reqID, qname, err)
		if h.auditLogger != nil {
			h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
				RequestID: reqID,
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
	// Each message is sent separately over TCP, TSIG-signed as one
	// RFC 8945 §5.3.1 chain when the request was signed (F312).
	if err := writeTransferStream(w, r, records, tsigKey); err != nil {
		h.logger.Warnf("[%s] Failed to send AXFR response: %v", reqID, err)
		if h.auditLogger != nil {
			h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
				RequestID: reqID,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  cipStr,
				Zone:      qname,
				Action:    "failed",
				Latency:   time.Since(start),
			})
		}
		if errors.Is(err, errTransferSign) {
			sendError(w, r, protocol.RcodeServerFailure)
		}
		return
	}

	h.logger.Infof("[%s] AXFR completed for %s - sent %d records", reqID, qname, len(records))
	if h.auditLogger != nil {
		h.auditLogger.LogAXFR(audit.AXFRAuditEntry{
			RequestID:   reqID,
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
	reqID := util.GenerateRequestID()

	// IXFR requires TCP per RFC 1995
	if clientInfo.Protocol != "tcp" {
		h.logger.Warnf("[%s] IXFR request over UDP from %s - refusing", reqID, clientInfo.String())
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

	h.logger.Infof("[%s] IXFR request for %s from %s", reqID, qname, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
			RequestID: reqID,
			Timestamp: start.UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      qname,
			Action:    "request",
		})
	}

	// Handle IXFR using the IXFR server
	// Authenticate against one consistent TSIG key set (F583).
	h.xferKeysMu.RLock()
	records, tsigKey, err := h.transfer.IXFRServer.HandleIXFRWithKey(r, clientIP)
	h.xferKeysMu.RUnlock()
	if err != nil {
		h.logger.Warnf("[%s] IXFR failed for %s: %v", reqID, qname, err)
		// Check if the error indicates AXFR fallback is needed
		if errors.Is(err, transfer.ErrNoJournal) || errors.Is(err, transfer.ErrSerialNotInRange) {
			h.logger.Infof("[%s] Falling back to AXFR for %s", reqID, qname)
			h.handleAXFR(w, r, q)
			return
		}
		if h.auditLogger != nil {
			h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
				RequestID: reqID,
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
	// A signed request gets a TSIG-signed response stream (RFC 8945 §5.3.1, F313).
	if err := writeTransferStream(w, r, records, tsigKey); err != nil {
		h.logger.Warnf("[%s] Failed to send IXFR response: %v", reqID, err)
		if h.auditLogger != nil {
			h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
				RequestID: reqID,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  cipStr,
				Zone:      qname,
				Action:    "failed",
				Latency:   time.Since(start),
			})
		}
		if errors.Is(err, errTransferSign) {
			sendError(w, r, protocol.RcodeServerFailure)
		}
		return
	}

	h.logger.Infof("[%s] IXFR completed for %s - sent %d records", reqID, qname, len(records))
	if h.auditLogger != nil {
		h.auditLogger.LogIXFR(audit.IXFRAuditEntry{
			RequestID:   reqID,
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

// errTransferSign marks a transfer stream that failed because a message could
// not be TSIG-signed; the handler then answers SERVFAIL.
var errTransferSign = errors.New("signing transfer response")

// writeTransferStream writes records as an AXFR/IXFR response, one record per
// message. When tsigKey is set (the request was TSIG-verified with it), every
// message is signed as one RFC 8945 §5.3.1 chain bound to the request MAC
// (F312, F313). Each message is first given the header and EDNS rewrites the
// pipeline's response writers apply, so the bytes on the wire are the bytes
// that were signed (F315).
func writeTransferStream(w server.ResponseWriter, r *protocol.Message, records []*protocol.ResourceRecord, tsigKey *transfer.TSIGKey) error {
	var signer *transfer.TSIGStreamSigner
	if tsigKey != nil {
		requestMAC, err := transfer.TSIGRequestMAC(r)
		if err != nil {
			return fmt.Errorf("%w: %w", errTransferSign, err)
		}
		signer = transfer.NewTSIGStreamSigner(tsigKey, requestMAC, 300)
	}
	for i, rr := range records {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers:   []*protocol.ResourceRecord{rr},
		}
		resp.Header.Flags.AA = true // transfer responses are authoritative (RFC 5936, RFC 1995)

		if signer != nil {
			applyResponseWriterRewrites(w, resp)
			tsigRR, err := signer.Sign(resp)
			if err != nil {
				return fmt.Errorf("%w %d: %w", errTransferSign, i, err)
			}
			resp.Additionals = append(resp.Additionals, tsigRR)
		}

		if _, err := w.Write(resp); err != nil {
			return fmt.Errorf("writing message %d: %w", i, err)
		}
	}
	return nil
}

// applyResponseWriterRewrites applies to msg, ahead of TSIG signing, the
// rewrites the response writers wrapping w make in Write: the cookie writer's
// COOKIE option and the header policy writer's OPCODE/RD/CD/RA and OPT
// normalization. Both are idempotent, so the writers' second pass in Write
// leaves the signed message unchanged and the TSIG RR last (F315).
func applyResponseWriterRewrites(w server.ResponseWriter, msg *protocol.Message) {
	for w != nil {
		switch cw := w.(type) {
		case *cookieResponseWriter:
			if cw.cookieData != nil {
				opt := msg.GetOPT()
				if opt == nil {
					msg.SetEDNS0(4096, false)
					opt = msg.GetOPT()
				}
				if opt != nil {
					if optData, ok := opt.Data.(*protocol.RDataOPT); ok && optData != nil {
						optData.RemoveOption(protocol.OptionCodeCookie)
						optData.AddOption(protocol.OptionCodeCookie, cw.cookieData)
					}
				}
			}
		case *headerPolicyResponseWriter:
			msg.Header.Flags.Opcode = cw.opcode
			msg.Header.Flags.RD = cw.rd
			msg.Header.Flags.CD = cw.cd
			if !cw.RecursionAllowed() {
				msg.Header.Flags.RA = false
			}
			cw.normalizeOPT(msg)
		}
		u, ok := w.(interface{ Unwrap() server.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// handleNOTIFY handles NOTIFY requests from master servers (RFC 1996).
// NOTIFY informs slave servers that a zone has changed and should be refreshed.
func (h *integratedHandler) handleNOTIFY(w server.ResponseWriter, r *protocol.Message, q *protocol.Question) {
	reqID := util.GenerateRequestID()
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}
	zoneName := q.Name.String()
	now := time.Now().UTC().Format(time.RFC3339)

	h.logger.Infof("[%s] NOTIFY request for %s from %s", reqID, zoneName, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
			RequestID: reqID,
			Timestamp: now,
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "received",
		})
	}

	// Handle NOTIFY using the NOTIFY handler. A NOTIFY for a configured
	// slave zone is authorized by that zone's masters (F387/F388).
	resp, handled, err := h.handleSlaveNOTIFY(r, clientIP)
	if !handled {
		resp, err = h.transfer.NotifyHandler.HandleNOTIFY(r, clientIP)
	}
	if err != nil {
		h.logger.Warnf("[%s] NOTIFY handling failed for %s: %v", reqID, zoneName, err)
		if h.auditLogger != nil {
			h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
				RequestID: reqID,
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
		h.logger.Warnf("[%s] Failed to write NOTIFY response: %v", reqID, err)
		return
	}

	h.logger.Infof("[%s] NOTIFY response sent for %s", reqID, zoneName)
	if h.auditLogger != nil {
		h.auditLogger.LogNOTIFY(audit.NOTIFYAuditEntry{
			RequestID: reqID,
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

// handleSlaveNOTIFY processes a NOTIFY whose zone is a configured slave zone;
// handled is false for any other zone. Slave zones live only in the
// SlaveManager, not in the authoritative zones map the shared NOTIFY handler
// consults, so before F387 their NOTIFYs were answered NOTAUTH and never
// refreshed the zone. RFC 1996 §3.10: only a known master of the zone may
// NOTIFY it, so the source is checked against the zone's masters rather than
// transfer.allow_list, which lists the hosts allowed to transfer from us
// (F388). The request itself is processed by a per-request NOTIFY handler
// whose only zone is the slave zone and whose only allowed source is the
// verified master; its event is forwarded to the SlaveManager.
func (h *integratedHandler) handleSlaveNOTIFY(r *protocol.Message, clientIP net.IP) (*protocol.Message, bool, error) {
	sm := h.transfer.SlaveManager
	if sm == nil || len(r.Questions) != 1 || r.Questions[0] == nil || r.Questions[0].Name == nil {
		return nil, false, nil
	}
	zoneName := strings.ToLower(r.Questions[0].Name.String())
	sz := sm.GetSlaveZone(zoneName)
	if sz == nil {
		return nil, false, nil
	}

	nh := transfer.NewNOTIFYSlaveHandler(map[string]*zone.Zone{zoneName: zone.NewZone(zoneName)})
	if clientIP != nil && isSlaveZoneMaster(sz.Config.Masters, clientIP) {
		if err := nh.AddNotifyAllowed(clientIP.String()); err != nil {
			return nil, true, err
		}
	} else {
		h.logger.Warnf("NOTIFY for slave zone %s from %v refused: not a configured master", zoneName, clientIP)
	}
	resp, err := nh.HandleNOTIFY(r, clientIP)
	select {
	case req := <-nh.GetNotifyChannel():
		select {
		case sm.GetNotifyChannel() <- req:
		default:
			h.logger.Warnf("Slave manager notify channel full, dropping NOTIFY for %s", zoneName)
		}
	default:
	}
	return resp, true, err
}

// isSlaveZoneMaster reports whether ip is one of the configured masters
// (host:port, or a bare host). Host names are resolved.
func isSlaveZoneMaster(masters []string, ip net.IP) bool {
	for _, m := range masters {
		host, _, err := net.SplitHostPort(m)
		if err != nil {
			host = m
		}
		if mip := net.ParseIP(host); mip != nil {
			if mip.Equal(ip) {
				return true
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// processNotifyEvents listens for NOTIFY events and triggers zone transfers.
func (h *integratedHandler) processNotifyEvents() {
	notifyChan := h.transfer.NotifyHandler.GetNotifyChannel()
	for req := range notifyChan {
		h.logger.Infof("Processing NOTIFY for zone %s (serial %d)", req.ZoneName, req.Serial)

		// Forward to slave manager if we have one
		if h.transfer.SlaveManager != nil {
			select {
			case h.transfer.SlaveManager.GetNotifyChannel() <- req:
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
	reqID := util.GenerateRequestID()
	clientInfo := w.ClientInfo()
	clientIP := clientInfo.IP()
	cipStr := "-"
	if clientIP != nil {
		cipStr = clientIP.String()
	}
	zoneName := q.Name.String()
	now := time.Now().UTC().Format(time.RFC3339)

	h.logger.Infof("[%s] UPDATE request for %s from %s", reqID, zoneName, clientInfo.String())
	if h.auditLogger != nil {
		h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
			RequestID: reqID,
			Timestamp: now,
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "request",
		})
	}

	// Handle UPDATE using the Dynamic DNS handler. In Raft cluster mode an
	// accepted update is replicated through the Raft log so every node
	// converges (F452); otherwise it is applied to the local zone. A Raft
	// follower with cluster.forward_updates (F569) forwards a signed UPDATE
	// for a local zone to the leader (RFC 2136 §6, F562) instead of
	// handling it; without it the follower answers REFUSED.
	var commit transfer.UpdateCommitFunc
	raftMode := h.cluster != nil && h.cluster.IsRaftMode()
	if raftMode {
		if h.updateNeedsForward(r, zoneName) {
			h.forwardUpdateToLeader(w, r, reqID, zoneName, cipStr)
			return
		}
	}
	// Authenticate and authorize against one consistent key set and grant
	// table (F583): the DDNS handler is read and used under xferKeysMu, so a
	// SIGHUP that swaps it waits for this request. The Raft commit, which can
	// wait for a Raft apply, runs after the read lock is released: the
	// request was already authorized with the snapshot it started with, and
	// after commit the old handler only builds the response (no update
	// event in commit mode), so it may be closed meanwhile.
	h.xferKeysMu.RLock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			h.xferKeysMu.RUnlock()
		}
	}
	ddns := h.transfer.DDNSHandler
	if raftMode {
		commit = func(z *zone.Zone, req *transfer.UpdateRequest) error {
			unlock()
			return h.commitUpdateViaRaft(z, req)
		}
	}
	resp, tsigKey, err := ddns.HandleUpdateRequest(r, clientIP, commit)
	unlock()
	if err == nil && tsigKey != nil {
		// RFC 8945 §5.3: the response to a TSIG-verified request is signed
		// with the same key, bound to the request MAC. Apply the response
		// writers' rewrites first so the signed bytes are the sent bytes.
		err = signUpdateResponse(w, r, resp, tsigKey)
	}
	if err != nil {
		h.logger.Warnf("[%s] UPDATE handling failed for %s: %v", reqID, zoneName, err)
		if h.auditLogger != nil {
			h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
				RequestID: reqID,
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
		h.logger.Warnf("[%s] Failed to write UPDATE response: %v", reqID, err)
		return
	}

	var action string
	if resp.Header.Flags.RCODE == protocol.RcodeSuccess {
		h.logger.Infof("[%s] UPDATE successful for %s", reqID, zoneName)
		action = "success"
	} else {
		h.logger.Warnf("[%s] UPDATE failed for %s with rcode %d", reqID, zoneName, resp.Header.Flags.RCODE)
		action = "failure"
	}
	if h.auditLogger != nil {
		h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
			RequestID: reqID,
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

	// Start a goroutine to listen for this DDNS handler's update events
	// (once per handler; a reload replaces the handler, F583).
	if !raftMode {
		h.ensureUpdateConsumer(ddns)
	}
}

// currentDDNSHandler returns the DDNS handler in use (swapped by SIGHUP,
// F583).
func (h *integratedHandler) currentDDNSHandler() *transfer.DynamicDNSHandler {
	h.xferKeysMu.RLock()
	defer h.xferKeysMu.RUnlock()
	return h.transfer.DDNSHandler
}

// ensureUpdateConsumer starts processUpdateEvents for ddns unless it is the
// handler already being drained. The consumer of a handler replaced by a
// reload drains its remaining events and exits when the reload closes it.
func (h *integratedHandler) ensureUpdateConsumer(ddns *transfer.DynamicDNSHandler) {
	if ddns == nil {
		return
	}
	h.ddnsConsumerMu.Lock()
	defer h.ddnsConsumerMu.Unlock()
	if h.ddnsConsumer == ddns {
		return
	}
	h.ddnsConsumer = ddns
	go h.processUpdateEventsFrom(ddns.GetUpdateChannel())
}

// signUpdateResponse appends the TSIG RR for resp, the single-message
// response to the TSIG-verified UPDATE r (RFC 8945 §5.3).
func signUpdateResponse(w server.ResponseWriter, r, resp *protocol.Message, key *transfer.TSIGKey) error {
	requestMAC, err := transfer.TSIGRequestMAC(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errTransferSign, err)
	}
	applyResponseWriterRewrites(w, resp)
	tsigRR, err := transfer.NewTSIGStreamSigner(key, requestMAC, 300).Sign(resp)
	if err != nil {
		return fmt.Errorf("%w: %w", errTransferSign, err)
	}
	resp.Additionals = append(resp.Additionals, tsigRR)
	return nil
}

// commitUpdateViaRaft replicates an authorized UPDATE through the Raft log
// (F452). Only the leader commits updates: a follower forwards signed
// UPDATEs to the leader before reaching here (F562, forwardUpdateToLeader),
// so a non-leader reaching this point (unsigned request, or leadership lost
// mid-request) answers REFUSED. DDNS updates are serialized here; the
// commit itself is commitUpdateBatch.
func (h *integratedHandler) commitUpdateViaRaft(z *zone.Zone, req *transfer.UpdateRequest) error {
	c := h.cluster
	if c == nil || !c.IsRaftMode() {
		return fmt.Errorf("%w: cluster is not in Raft mode", transfer.ErrUpdateRefused)
	}
	if !c.IsLeader() {
		return fmt.Errorf("%w: this node is not the Raft leader", transfer.ErrUpdateRefused)
	}
	h.ddnsRaftMu.Lock()
	defer h.ddnsRaftMu.Unlock()
	return commitUpdateBatch(c, z, req)
}

// ddnsForwardTimeout bounds one RFC 2136 §6 forward to the leader: dial,
// request write and response read together (F562).
const ddnsForwardTimeout = 5 * time.Second

// ddnsForwardSlots caps concurrent forwards per process; a forward that
// finds no free slot is answered SERVFAIL instead of queuing (F562).
var ddnsForwardSlots = make(chan struct{}, 64)

// ddnsForwardCluster is the part of *cluster.Cluster UPDATE forwarding uses.
type ddnsForwardCluster interface {
	IsLeader() bool
	GetNodeID() string
	AdvertisedDNSAddr() string
	LeaderDNSAddr() (leaderID, addr string, ok bool)
}

// updateNeedsForward reports whether this node, a Raft follower, must
// forward UPDATE r to the leader (RFC 2136 §6, F562): cluster.forward_updates
// is on (opt-in, F569), r carries a TSIG RR and names a zone this node
// serves. The follower does NOT authorize the request: the leader verifies
// TSIG and applies the allow_update policy.
// Unsigned UPDATEs are never forwarded — the leader would see this node's
// address, not the client's, so forwarding them could only launder
// address-based policy; they are handled locally (and refused).
func (h *integratedHandler) updateNeedsForward(r *protocol.Message, zoneName string) bool {
	if h.cluster == nil || !h.forwardUpdatesEnabled() || h.cluster.IsLeader() || !messageHasTSIG(r) {
		return false
	}
	h.zonesMu.RLock()
	_, ok := h.zones[strings.ToLower(zoneName)]
	h.zonesMu.RUnlock()
	return ok
}

// forwardUpdatesEnabled reports cluster.forward_updates (F569): follower
// UPDATE forwarding is opt-in; when off a follower answers REFUSED.
func (h *integratedHandler) forwardUpdatesEnabled() bool {
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()
	return h.config != nil && h.config.Cluster.ForwardUpdates
}

func messageHasTSIG(m *protocol.Message) bool {
	for _, rr := range m.Additionals {
		if rr != nil && rr.Type == protocol.TypeTSIG {
			return true
		}
	}
	return false
}

// forwardUpdateToLeader relays UPDATE r to the Raft leader's advertised DNS
// TCP address and writes the leader's response back unchanged (F562). The
// request is re-packed from the parsed message with its original ID and
// TSIG RR (the server keeps no raw request bytes; TSIG verification here is
// defined over the same re-packed form), and the response is written past
// the response-rewriting wrappers so its TSIG MAC still verifies.
//
// Loop protection: a node forwards only while it is not the leader, only to
// the leader it currently follows (learned from that leader's current
// AppendEntries) and never to its own advertised address. A node that
// receives a forwarded UPDATE after losing leadership has moved to a newer
// term, so every further hop goes to a leader of a strictly newer term — a
// cycle is impossible, and the in-flight cap bounds fan-out. No leader, no
// address, a timeout or a bad reply → SERVFAIL.
func (h *integratedHandler) forwardUpdateToLeader(w server.ResponseWriter, r *protocol.Message, reqID, zoneName, cipStr string) {
	resp, leaderID, err := forwardUpdate(h.cluster, r, ddnsForwardTimeout)
	if err != nil {
		h.logger.Warnf("[%s] UPDATE for %s from %s not forwarded to Raft leader %q: %v", reqID, zoneName, cipStr, leaderID, err)
		if h.auditLogger != nil {
			h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
				RequestID: reqID,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				ClientIP:  cipStr,
				Zone:      zoneName,
				Action:    "failure",
				Rcode:     fmt.Sprintf("%d", protocol.RcodeServerFailure),
			})
		}
		sendError(w, r, protocol.RcodeServerFailure)
		return
	}
	rcode := resp.Header.Flags.RCODE
	h.logger.Infof("[%s] UPDATE for %s forwarded to Raft leader %s: rcode %d", reqID, zoneName, leaderID, rcode)
	if h.auditLogger != nil {
		h.auditLogger.LogUpdate(audit.UpdateAuditEntry{
			RequestID: reqID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  cipStr,
			Zone:      zoneName,
			Action:    "forwarded",
			Rcode:     fmt.Sprintf("%d", rcode),
		})
	}
	if h.metrics != nil {
		h.metrics.RecordResponse(rcode)
	}
	if _, err := writeRelayedResponse(w, resp); err != nil {
		h.logger.Warnf("[%s] Failed to write forwarded UPDATE response: %v", reqID, err)
	}
}

// forwardUpdate sends r to the leader c follows and returns its response.
func forwardUpdate(c ddnsForwardCluster, r *protocol.Message, timeout time.Duration) (*protocol.Message, string, error) {
	leaderID, addr, ok := c.LeaderDNSAddr()
	switch {
	case !ok || leaderID == "":
		return nil, "", errors.New("no Raft leader known")
	case leaderID == c.GetNodeID() || c.IsLeader():
		return nil, leaderID, errors.New("this node is the leader; not forwarding")
	case addr == "":
		return nil, leaderID, errors.New("leader advertises no DNS address (cluster.dns_advertise_addr)")
	case addr == c.AdvertisedDNSAddr():
		return nil, leaderID, fmt.Errorf("leader DNS address %s is this node's own address", addr)
	}
	select {
	case ddnsForwardSlots <- struct{}{}:
		defer func() { <-ddnsForwardSlots }()
	default:
		return nil, leaderID, errors.New("too many UPDATE forwards in flight")
	}
	buf := make([]byte, 65535)
	n, err := r.Pack(buf)
	if err != nil {
		return nil, leaderID, fmt.Errorf("re-packing request: %w", err)
	}
	resp, err := exchangeUpdateTCP(addr, buf[:n], timeout)
	if err != nil {
		return nil, leaderID, fmt.Errorf("leader %s: %w", addr, err)
	}
	if resp.Header.ID != r.Header.ID || !resp.Header.Flags.QR || resp.Header.Flags.Opcode != protocol.OpcodeUpdate {
		return nil, leaderID, fmt.Errorf("leader %s: reply does not answer the UPDATE (id %d qr %v opcode %d)", addr, resp.Header.ID, resp.Header.Flags.QR, resp.Header.Flags.Opcode)
	}
	return resp, leaderID, nil
}

// exchangeUpdateTCP sends one length-prefixed DNS message to addr and reads
// one reply, all within timeout.
func exchangeUpdateTCP(addr string, req []byte, timeout time.Duration) (*protocol.Message, error) {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(req))
	out[0], out[1] = byte(len(req)>>8), byte(len(req))
	copy(out[2:], req)
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	rb := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return protocol.UnpackMessage(rb)
}

// writeRelayedResponse writes a response produced (and possibly TSIG-signed)
// by another server: it bypasses the cookie and header-policy rewrites,
// which would change the signed bytes, and records the rcode on the header
// policy writer for query logging.
func writeRelayedResponse(w server.ResponseWriter, msg *protocol.Message) (int, error) {
	for {
		switch cw := w.(type) {
		case *headerPolicyResponseWriter:
			cw.rcode, cw.wrote = msg.Header.Flags.RCODE, true
			cw.answers = summarizeAnswers(msg)
			w = cw.inner
			continue
		case *cookieResponseWriter:
			w = cw.inner
			continue
		}
		return w.Write(msg)
	}
}

// ddnsBatchCluster is the part of *cluster.Cluster an UPDATE commit uses.
type ddnsBatchCluster interface {
	ZoneFingerprint(zoneName string, names []string) (string, error)
	ZoneContentFingerprint(zoneName string) (string, error)
	ProposeZoneBatch(zoneName string, ops []cluster.ZoneOp, pre cluster.ZoneBatchPrecondition) error
}

// ddnsRaftMaxAttempts bounds how often an UPDATE is re-planned after its
// batch lost an optimistic-concurrency race (cluster.ErrZoneBatchConflict).
const ddnsRaftMaxAttempts = 3

// commitUpdateBatch commits one UPDATE as ONE atomic Raft zone batch
// (F532/F533). Each attempt fingerprints the RRs at every prerequisite and
// update owner name, then evaluates the update with full RFC 2136 semantics
// against a private copy of the zone (transfer.PlanUpdate) and proposes the
// resulting record changes as a single batch guarded by that fingerprint.
// Every replica applies the batch all-or-nothing and only if none of those
// RRs changed since the fingerprint, so the prerequisites hold for the state
// the update is applied to (RFC 2136 §3.2/§3.4) even when an API write races
// the UPDATE; the fingerprint is taken BEFORE planning, so a write between the
// two is caught as a conflict too. Prerequisites and updates only read and
// write RRs at their own owner names, so these names cover everything the
// plan depends on — except the SOA, which the per-name fingerprint excludes.
// A prerequisite on the SOA RRset (F582) depends on the zone as a whole
// (every write bumps the serial), so such an UPDATE is guarded by the
// whole-zone content fingerprint instead (cluster.ZoneBatchPrecondition.
// Zone): any write to the zone between planning and apply is a conflict and
// the re-plan re-checks the SOA (NXRRSET / YXRRSET then). Only UPDATEs that
// reference the SOA pay for it — guarding every UPDATE that way would turn
// every concurrent write anywhere in the zone into a re-plan (and, under
// sustained writes, SERVFAIL after ddnsRaftMaxAttempts).
//
// Outcome → error (RCODE via transfer's mapping):
//   - conflict: re-plan, at most ddnsRaftMaxAttempts times; the re-plan
//     re-checks the prerequisites (e.g. NXRRSET now). Still conflicting →
//     SERVFAIL (transient: the zone kept changing; the client may retry).
//   - more than cluster.MaxZoneBatchOps record changes → REFUSED: a local
//     policy limit on the size of one update (RFC 2136 §2.2 REFUSED), the same
//     update would fail again, so not SERVFAIL.
//   - SOA replacement → REFUSED (the batch owns the serial).
//   - *cluster.ZoneBatchOpError, leadership loss, apply-wait timeout →
//     SERVFAIL. Nothing was applied, except after an apply-wait timeout, where
//     the batch may still commit later — atomically either way.
func commitUpdateBatch(c ddnsBatchCluster, z *zone.Zone, req *transfer.UpdateRequest) error {
	names := ddnsUpdateOwnerNames(req)
	var err error
	for attempt := 0; attempt < ddnsRaftMaxAttempts; attempt++ {
		err = commitUpdateBatchOnce(c, z, req, names)
		if !errors.Is(err, cluster.ErrZoneBatchConflict) {
			return err
		}
	}
	return fmt.Errorf("ddns: zone %s kept changing during %d attempts: %w", z.Origin, ddnsRaftMaxAttempts, err)
}

func commitUpdateBatchOnce(c ddnsBatchCluster, z *zone.Zone, req *transfer.UpdateRequest, names []string) error {
	wholeZone := ddnsPrereqReferencesSOA(req)
	var fingerprint string
	var err error
	if wholeZone {
		fingerprint, err = c.ZoneContentFingerprint(z.Origin)
	} else {
		fingerprint, err = c.ZoneFingerprint(z.Origin, names)
	}
	if err != nil {
		return fmt.Errorf("ddns: zone fingerprint: %w", err)
	}
	removed, added, soaChanged, err := transfer.PlanUpdate(z, req)
	if err != nil {
		return err
	}
	if soaChanged {
		return fmt.Errorf("%w: SOA replacement is not supported in Raft cluster mode", transfer.ErrUpdateRefused)
	}
	if n := len(removed) + len(added); n > cluster.MaxZoneBatchOps {
		return fmt.Errorf("%w: update changes %d records, limit is %d", transfer.ErrUpdateRefused, n, cluster.MaxZoneBatchOps)
	}
	ops := make([]cluster.ZoneOp, 0, len(removed)+len(added))
	for _, rec := range removed {
		ops = append(ops, cluster.ZoneOp{Op: cluster.ZoneOpDeleteRData, Name: rec.Name, Type: rec.Type, RData: rec.RData})
	}
	for _, rec := range added {
		class := rec.Class
		if class == "" {
			class = "IN"
		}
		ops = append(ops, cluster.ZoneOp{Op: cluster.ZoneOpAdd, Name: rec.Name, Type: rec.Type, Class: class, TTL: rec.TTL, RData: rec.RData})
	}
	if len(ops) == 0 {
		// Prerequisites held and the update is a no-op (e.g. replayed add).
		return nil
	}
	return c.ProposeZoneBatch(z.Origin, ops, cluster.ZoneBatchPrecondition{Names: names, Fingerprint: fingerprint, Zone: wholeZone})
}

// ddnsPrereqReferencesSOA reports whether req has a prerequisite on an SOA
// RRset (F582). Updates never need it: an SOA add is refused in Raft mode and
// SOA deletes are ignored (RFC 2136 §3.4.2.3/§3.4.2.4).
func ddnsPrereqReferencesSOA(req *transfer.UpdateRequest) bool {
	for _, p := range req.Prerequisites {
		if p.Type == protocol.TypeSOA {
			return true
		}
	}
	return false
}

// ddnsUpdateOwnerNames returns the distinct owner names of req's
// prerequisites and updates (lower-cased).
func ddnsUpdateOwnerNames(req *transfer.UpdateRequest) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, p := range req.Prerequisites {
		add(p.Name)
	}
	for _, u := range req.Updates {
		add(u.Name)
	}
	return names
}

// processUpdateEvents listens for update events and applies changes to zones.
func (h *integratedHandler) processUpdateEvents() {
	h.processUpdateEventsFrom(h.currentDDNSHandler().GetUpdateChannel())
}

// processUpdateEventsFrom drains one DDNS handler's update events until the
// handler is closed.
func (h *integratedHandler) processUpdateEventsFrom(updateChan <-chan *transfer.UpdateRequest) {
	for req := range updateChan {
		h.logger.Infof("Processing UPDATE for zone %s", req.ZoneName)

		// The update was already applied synchronously by
		// DynamicDNSHandler.HandleUpdate under the zone lock (with
		// prerequisite re-checks). Re-applying it here would bump the
		// SOA serial a second time and duplicate added records — this
		// loop only performs post-apply side effects: IXFR journal,
		// audit log, and persistence. Serials travel in the request.

		// Skip side effects if the zone has been removed since the
		// update was applied (zone deletion racing this consumer).
		h.zonesMu.RLock()
		_, ok := h.zones[req.ZoneName]
		h.zonesMu.RUnlock()
		if !ok {
			h.logger.Warnf("Zone %s not found for UPDATE side effects", req.ZoneName)
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
		if h.transfer.IXFRServer != nil && req.NewSerial != req.OldSerial {
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
			h.recordZoneChange(req.ZoneName, req.OldSerial, req.NewSerial, added, deleted)
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

		// DDNS mutates the *zone.Zone directly (transfer.ApplyUpdate in
		// HandleUpdate), bypassing the Manager's mutation methods — fire the
		// mutation hook manually so KV persistence (and any future hook
		// consumer) sees the change. All other mutation paths persist
		// automatically via the hook.
		h.zoneManager.NotifyMutated(req.ZoneName)

		// Persist zone file to disk if zoneDir is configured
		if err := h.zoneManager.PersistZone(req.ZoneName); err != nil {
			h.logger.Warnf("Failed to persist zone %s to disk: %v", req.ZoneName, err)
		}
	}
}

// recordZoneChange records a zone modification to the IXFR journal.
// This should be called whenever a zone is modified via dynamic updates.
func (h *integratedHandler) recordZoneChange(zoneName string, oldSerial, newSerial uint32, added, deleted []zone.RecordChange) {
	if h.transfer.IXFRServer == nil {
		return
	}

	h.transfer.IXFRServer.RecordChange(zoneName, oldSerial, newSerial, added, deleted)
	h.logger.Debugf("Recorded zone change for %s: serial %d -> %d (added: %d, deleted: %d)",
		zoneName, oldSerial, newSerial, len(added), len(deleted))
}
