package otel

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// applyAttrs converts facade attributes onto an SDK span. Attribute types
// are mapped by an explicit type switch: the facade's Attr.Value is
// interface{}, and the removed attribute.Any behaved unpredictably on
// unknown types.
func applyAttrs(span sdkRecordingSpan, attrs []Attr) {
	if len(attrs) == 0 {
		return
	}
	kvs := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		kvs = append(kvs, toKeyValue(a))
	}
	span.SetAttributes(kvs...)
}

// toKeyValue maps a facade Attr onto a typed SDK attribute. Unknown value
// types fall back to their fmt representation as a string.
func toKeyValue(a Attr) attribute.KeyValue {
	switch v := a.Value.(type) {
	case string:
		return attribute.String(a.Key, v)
	case bool:
		return attribute.Bool(a.Key, v)
	case int:
		return attribute.Int(a.Key, v)
	case int32:
		return attribute.Int(a.Key, int(v))
	case int64:
		return attribute.Int64(a.Key, v)
	case uint16:
		return attribute.Int(a.Key, int(v))
	case float64:
		return attribute.Float64(a.Key, v)
	case []byte:
		return attribute.ByteSlice(a.Key, v)
	case fmt.Stringer:
		return attribute.String(a.Key, v.String())
	case error:
		return attribute.String(a.Key, v.Error())
	default:
		return attribute.String(a.Key, fmt.Sprintf("%v", v))
	}
}

// sdkRecordingSpan is the subset of the SDK span interface the facade
// needs (trace.Span satisfies it).
type sdkRecordingSpan interface {
	SetAttributes(...attribute.KeyValue)
}

// attributeBool builds a boolean attribute.
func attributeBool(key string, v bool) attribute.KeyValue {
	return attribute.Bool(key, v)
}

// memoryRecorder is an sdktrace.SpanProcessor that retains finished spans
// in memory for Tracer.Export(), used when no OTLP endpoint is configured
// (tests, local debugging). Retention is bounded: when the cap is reached
// the oldest spans are dropped and counted, mirroring the OOM guard the
// hand-rolled tracer had.
type memoryRecorder struct {
	mu      sync.Mutex
	spans   []*Span
	dropped uint64
}

func newMemoryRecorder() *memoryRecorder { return &memoryRecorder{} }

// processor returns the recorder as a SpanProcessor for the provider.
func (r *memoryRecorder) processor() sdktrace.SpanProcessor { return r }

// OnStart implements sdktrace.SpanProcessor.
func (r *memoryRecorder) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {}

// OnEnd converts the finished SDK span into a facade Span and retains it.
func (r *memoryRecorder) OnEnd(s sdktrace.ReadOnlySpan) {
	sc := s.SpanContext()
	span := &Span{
		Name:      s.Name(),
		TraceID:   sc.TraceID(),
		SpanID:    sc.SpanID(),
		StartTime: s.StartTime(),
		EndTime:   s.EndTime(),
	}
	if parent := s.Parent(); parent.IsValid() {
		span.ParentID = parent.SpanID()
	}
	attrs := s.Attributes()
	if len(attrs) > 0 {
		span.Attrs = make([]Attr, 0, len(attrs))
		for _, kv := range attrs {
			span.Attrs = append(span.Attrs, Attr{Key: string(kv.Key), Value: kv.Value.AsInterface()})
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, span)
	if len(r.spans) > maxRetainedSpans {
		drop := len(r.spans) - maxRetainedSpans
		r.spans = append(r.spans[:0], r.spans[drop:]...)
		r.dropped += uint64(drop)
	}
}

// Shutdown implements sdktrace.SpanProcessor.
func (r *memoryRecorder) Shutdown(_ context.Context) error { return nil }

// ForceFlush implements sdktrace.SpanProcessor.
func (r *memoryRecorder) ForceFlush(_ context.Context) error { return nil }

// drain returns all retained spans and clears the buffer. Caller holds
// Tracer.recMu.
func (r *memoryRecorder) drain() []*Span {
	spans := r.spans
	r.spans = nil
	return spans
}

// takeDropped returns and resets the dropped-span counter.
func (r *memoryRecorder) takeDropped() uint64 {
	d := r.dropped
	r.dropped = 0
	return d
}
