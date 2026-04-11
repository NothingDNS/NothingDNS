package otel

import (
	"log"
	"net/http"
	"time"
)

// Middleware returns an HTTP middleware that adds tracing.
func Middleware(tracer *Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !tracer.cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Start span
			ctx, span := tracer.StartSpan(r.Context(), r.Method+" "+r.URL.Path)
			if span == nil {
				next.ServeHTTP(w, r)
				return
			}
			defer tracer.EndSpan(span, nil)

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

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// TraceHandler wraps an HTTP handler with tracing.
func TraceHandler(tracer *Tracer, name string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tracer.cfg.Enabled {
			handler(w, r)
			return
		}

		ctx, span := tracer.StartSpan(r.Context(), name)
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
		Attr{Key: "dns.query_type", Value: queryType},
		Attr{Key: "dns.server", Value: server},
		Attr{Key: "dns.cache_hit", Value: cacheHit},
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
		log.Printf("span: name=%s trace=%x span=%x duration=%v attrs=%v",
			span.Name, span.TraceID, span.SpanID, duration, span.Attrs)
	}
}
