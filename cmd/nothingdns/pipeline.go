// NothingDNS - DNS query pipeline
// Decomposed ServeDNS into individually-testable Stage funcs.

package main

import (
	"context"
	"time"

	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
)

// query holds all derived state for a DNS request.
// Created once at the top of ServeDNS and passed through every stage.
type query struct {
	reqID string
	start time.Time

	// Parsed from the incoming message
	msg   *protocol.Message
	q     *protocol.Question // first question; never nil after validation stage
	qname string
	qtype uint16

	// DO bit for cache key (RFC 8914 §4.6)
	doBit bool

	// Cache key including DO bit
	cacheKey string

	// Audit/tracing fields (written by stages)
	qtypeStr   string // human qtype for metrics/tracing
	qnameAudit string // qname for audit log (set once)
	cacheHit   bool   // set by cache stage
	blocked    bool   // set by blocklist/RPZ stages (for the dashboard query log)

	// Response state (written by final stages)
	rcode    uint8 // written by stages that send a response
	rcodeSet bool  // true once rcode has been set

	// Tracing (setup by setupStage, ended in defer)
	span *otel.Span

	// Pipeline context and cancel (setup by Pipeline.ServeDNS)
	ctx    context.Context
	cancel context.CancelFunc

	// currentWriter is the active response writer; stages may wrap it
	currentWriter server.ResponseWriter
}

// Stage is a single processing step in the DNS pipeline.
// Return handled=true to stop pipeline and return immediately.
// Return handled=false to continue to next stage.
type Stage func(ctx context.Context, q *query, w server.ResponseWriter) (handled bool, err error)

// Pipeline runs a sequence of stages until one signals handled or all complete.
type Pipeline struct {
	stages []Stage
}

// ServeDNS runs all stages in order with full context/tracing/defer support.
// This is the entry point wired into integratedHandler.ServeDNS.
func (p *Pipeline) ServeDNS(h *integratedHandler, w server.ResponseWriter, r *protocol.Message) {
	reqID := util.GenerateRequestID()
	start := time.Now()

	// q is declared at function scope so the panic-recovery defer (above)
	// can reference it. It is populated below after tracing setup.
	var q *query

	// Panic recovery — prevents handler crashes from crashing the server.
	// w may be nil if the panic occurs before q.currentWriter is assigned
	// (line 185 below). Use q.currentWriter instead when available, as it
	// survives stage-level writer wrapping (e.g. cookieStage).
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Errorf("Panic in ServeDNS: internal error (req_id=%s)", reqID)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeServerFailure)
			}
			wr := w
			if q != nil && q.currentWriter != nil {
				wr = q.currentWriter
			}
			sendErrorWithEDE(wr, r, protocol.RcodeServerFailure, protocol.EDEOtherError, "internal server error")
		}
	}()

	// OpenTelemetry tracing: derive from serverCtx so it is cancelled on shutdown.
	var span *otel.Span
	var reqCtx context.Context
	var reqCancel context.CancelFunc
	if h.serverCtx != nil {
		reqCtx, reqCancel = context.WithCancel(h.serverCtx)
	} else {
		// serverCtx is nil during early startup or test misconfiguration.
		// context.TODO flags this as a placeholder — the derived context will
		// NOT be cancelled on server shutdown, so outstanding requests may
		// block graceful termination.
		reqCtx, reqCancel = context.WithCancel(context.TODO())
	}
	defer reqCancel()

	if h.tracer != nil {
		_, span = h.tracer.StartSpan(reqCtx, "dns.query",
			otel.WithAttr("req.id", reqID),
		)
	}

	q = &query{
		msg:    r,
		start:  start,
		reqID:  reqID,
		span:   span,
		ctx:    reqCtx,
		cancel: reqCancel,
	}

	// Defer latency recording and audit logging
	defer func() {
		latency := time.Since(start)
		if h.metrics != nil && q.qtypeStr != "" {
			h.metrics.RecordQueryLatency(q.qtypeStr, latency)
		}
		if h.auditLogger != nil && q.qtypeStr != "" {
			clientIP := "-"
			if ci := q.currentWriter.ClientInfo(); ci != nil && ci.IP() != nil {
				clientIP = ci.IP().String()
			}
			h.auditLogger.LogQuery(audit.QueryAuditEntry{
				RequestID: reqID,
				Timestamp: start.UTC().Format(time.RFC3339),
				ClientIP:  clientIP,
				QueryName: q.qnameAudit,
				QueryType: q.qtypeStr,
				Latency:   latency,
				CacheHit:  q.cacheHit,
			})
		}
		// Feed the dashboard Query Log page + live WebSocket stream (one event
		// per query). dashboard.RecordQuery was defined but never called from
		// the request pipeline, so both were always empty.
		if h.dashboardServer != nil && q.qtypeStr != "" {
			clientIP, proto := "-", ""
			if ci := q.currentWriter.ClientInfo(); ci != nil {
				if ip := ci.IP(); ip != nil {
					clientIP = ip.String()
				}
				proto = ci.Protocol
			}
			var rcode uint8
			if q.rcodeSet {
				rcode = q.rcode
			}
			domain := q.qnameAudit
			if domain == "" {
				domain = q.qname
			}
			h.dashboardServer.RecordQuery(&dashboard.QueryEvent{
				Timestamp:    start,
				ClientIP:     clientIP,
				Domain:       domain,
				QueryType:    q.qtypeStr,
				ResponseCode: rcodeToString(rcode),
				Duration:     latency.Milliseconds(),
				Cached:       q.cacheHit,
				Blocked:      q.blocked,
				Protocol:     proto,
			})
		}
		// End tracing span with DNS attributes
		if span != nil {
			if q.qtypeStr != "" {
				span.Attrs = append(span.Attrs,
					otel.Attr{Key: "dns.qname", Value: q.qnameAudit},
					otel.Attr{Key: "dns.qtype", Value: q.qtypeStr},
					otel.Attr{Key: "dns.cache_hit", Value: q.cacheHit},
				)
				if q.rcodeSet {
					span.Attrs = append(span.Attrs,
						otel.Attr{Key: "dns.rcode", Value: rcodeToString(q.rcode)},
					)
				}
				if ci := w.ClientInfo(); ci != nil && ci.IP() != nil {
					span.Attrs = append(span.Attrs,
						otel.Attr{Key: "dns.client_ip", Value: ci.IP().String()},
					)
				}
			}
			h.tracer.EndSpan(span, nil)
		}
	}()

	// Wrap the writer before any stage can respond, so that every response —
	// including the panic-recovery SERVFAIL and the errors written by the
	// admission stages below — carries the request's OPCODE/RD/CD back to the
	// client (RFC 1035 §4.1.1, RFC 4035 §3.1.6) and an accurate RA bit.
	q.currentWriter = newHeaderPolicyWriter(h, w, r)

	for _, stage := range p.stages {
		handled, err := stage(q.ctx, q, q.currentWriter)
		if handled || err != nil {
			return
		}
	}
}

// AppendStage adds a stage to the pipeline.
func (p *Pipeline) AppendStage(s Stage) {
	p.stages = append(p.stages, s)
}

// NewPipeline builds a fully configured DNS query pipeline for h.
// Stages are registered in the order they execute in ServeDNS.
func NewPipeline(h *integratedHandler) *Pipeline {
	p := &Pipeline{}
	p.AppendStage(setupStage(h))
	p.AppendStage(queryDirectionStage(h))
	p.AppendStage(validationStage(h))
	p.AppendStage(metricsStage(h))
	p.AppendStage(aclStage(h))
	p.AppendStage(rpzClientStage(h))
	p.AppendStage(rateLimitStage(h))
	p.AppendStage(requestPolicyStage(h))
	p.AppendStage(cookieStage(h))
	p.AppendStage(anyStage(h))
	p.AppendStage(transferStage(h))
	// Filtering MUST run BEFORE the cache: a domain resolved and cached before
	// it was added to the blocklist/RPZ (e.g. via hot-reload, or simply added
	// after first resolution) would otherwise be served straight from cache,
	// bypassing the filter until its TTL expires. This matches the documented
	// pipeline order (blocklist → RPZ-QNAME → cache → NSEC cache).
	p.AppendStage(blocklistStage(h))
	p.AppendStage(rpzQnameStage(h))
	p.AppendStage(doBitStage(h))
	p.AppendStage(cacheStage(h))
	p.AppendStage(nsecCacheStage(h))
	p.AppendStage(splitHorizonStage(h))
	p.AppendStage(authoritativeStage(h))
	p.AppendStage(cnameStage(h))
	p.AppendStage(authoritativeOnlyStage(h))
	p.AppendStage(resolverStage(h))
	p.AppendStage(upstreamStage(h))
	p.AppendStage(noUpstreamStage(h))
	return p
}
