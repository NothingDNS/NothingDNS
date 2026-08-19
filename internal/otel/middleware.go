package otel

import (
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
	gootel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Middleware returns an HTTP middleware that adds tracing. Incoming
// traceparent/tracestate headers are extracted via the global W3C
// TraceContext propagator, so requests carrying an upstream trace context
// join that trace instead of starting a new one. The response carries the
// current span's context back out so callers can continue the trace.
func Middleware(tracer *Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tracer == nil || !tracer.cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Extract W3C trace context from inbound headers.
			ctx := otelPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Start span — spanPath bounds cardinality: raw request paths
			// (zone names, record IDs, arbitrary probes) would otherwise
			// mint an unbounded set of span names.
			ctx, span := tracer.StartSpan(ctx, r.Method+" "+spanPath(r.URL.Path))
			if span == nil {
				next.ServeHTTP(w, r)
				return
			}
			defer tracer.EndSpan(span, nil)

			// Inject the server span's context so downstream HTTP calls
			// made with this request's context propagate the trace.
			otelPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))

			// Update request context
			r = r.WithContext(ctx)

			// Wrap response writer to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			start := time.Now()
			next.ServeHTTP(wrapped, r)
			duration := time.Since(start)

			// Add span attributes
			span.Attrs = append(span.Attrs,
				Attr{Key: "http.status_code", Value: wrapped.statusCode},
				Attr{Key: "http.method", Value: r.Method},
				Attr{Key: "http.url", Value: r.URL.String()},
				Attr{Key: "http.host", Value: r.Host},
				Attr{Key: "http.duration_ms", Value: duration.Milliseconds()},
			)
		})
	}
}

// otelPropagator returns the global propagator (W3C TraceContext, set by
// NewTracer).
func otelPropagator() propagation.TextMapPropagator {
	return gootel.GetTextMapPropagator()
}

var spanPath = func(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "/"
	}
	segs := strings.Split(trimmed, "/")
	truncated := false
	if len(segs) > 3 {
		segs = segs[:3]
		truncated = true
	}
	if len(segs) == 3 && looksDynamicSegment(segs[2]) {
		segs[2] = ":id"
	}
	out := "/" + strings.Join(segs, "/")
	if truncated {
		out += "/*"
	}
	return out
}

// looksDynamicSegment reports whether a path segment looks like a per-entity
// value rather than a fixed route word: all-numeric, a UUID (dashed 36-char
// form exceeds the length cap; the dashless 32-hex form is matched here), or
// simply longer than 32 characters.
func looksDynamicSegment(seg string) bool {
	if len(seg) > 32 {
		return true
	}
	if seg == "" {
		return false
	}
	numeric := true
	hex := len(seg) == 32
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c < '0' || c > '9' {
			numeric = false
		}
		if hex && !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			hex = false
		}
	}
	return numeric || hex
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// TraceHandler wraps an HTTP handler with tracing, extracting the W3C
// trace context from the inbound request like Middleware does.
func TraceHandler(tracer *Tracer, name string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tracer == nil || !tracer.cfg.Enabled {
			handler(w, r)
			return
		}

		ctx := otelPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.StartSpan(ctx, name)
		if span == nil {
			handler(w, r)
			return
		}
		defer tracer.EndSpan(span, nil)

		r = r.WithContext(ctx)

		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		handler(wrapped, r)

		span.Attrs = append(span.Attrs,
			Attr{Key: "http.status_code", Value: wrapped.statusCode},
		)
	}
}

// DNSTraceAttrs returns standard attributes for DNS operations.
func DNSTraceAttrs(queryType string, server string, cacheHit bool) []Attr {
	return []Attr{
		{Key: "dns.query_type", Value: queryType},
		{Key: "dns.server", Value: server},
		{Key: "dns.cache_hit", Value: cacheHit},
	}
}

// RecordError records an error on a span.
func RecordError(span *Span, err error) {
	if span == nil {
		return
	}
	span.Err = err
	span.Attrs = append(span.Attrs, Attr{Key: "error", Value: true})
}

// LogSpans logs all recorded spans (for debugging).
func LogSpans(spans []*Span) {
	for _, span := range spans {
		duration := span.EndTime.Sub(span.StartTime)
		util.Debugf("span: name=%s trace=%x span=%x duration=%v attrs=%v",
			span.Name, span.TraceID, span.SpanID, duration, span.Attrs)
	}
}
