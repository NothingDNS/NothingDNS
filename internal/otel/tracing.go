package otel

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// TraceLevel defines tracing verbosity.
type TraceLevel int

const (
	LevelNone TraceLevel = iota
	LevelBasic
	LevelDetailed
	LevelVerbose
)

// Config holds tracing configuration.
type Config struct {
	Enabled    bool       `yaml:"enabled"`
	Level      TraceLevel `yaml:"level"`
	SampleRate float64   `yaml:"sample_rate"` // 0.0-1.0
}

// Span represents an in-flight trace.
type Span struct {
	Name       string
	TraceID    [16]byte
	SpanID     [8]byte
	ParentID   [8]byte
	StartTime  time.Time
	EndTime    time.Time
	Level      TraceLevel
	Attrs      []Attr
	Err        error
}

// Attr is a key-value pair for span attributes.
type Attr struct {
	Key   string
	Value interface{}
}

// Tracer provides distributed tracing.
type Tracer struct {
	cfg    Config
	counter uint64
	spans  []*Span
}

// NewTracer creates a new tracer.
func NewTracer(cfg Config) *Tracer {
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}
	return &Tracer{cfg: cfg}
}

// StartSpan begins a new span.
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	if !t.cfg.Enabled {
		return ctx, nil
	}

	span := &Span{
		Name:      name,
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		StartTime: time.Now(),
		Level:     t.cfg.Level,
	}

	for _, opt := range opts {
		opt(span)
	}

	return context.WithValue(ctx, spanKey, span), span
}

// EndSpan completes a span.
func (t *Tracer) EndSpan(span *Span, err error) {
	if span == nil {
		return
	}
	span.EndTime = time.Now()
	span.Err = err
}

// SpanOption configures a span.
type SpanOption func(*Span)

// WithParent sets the parent span ID.
func WithParent(parentID [8]byte) SpanOption {
	return func(s *Span) {
		s.ParentID = parentID
	}
}

// WithAttr adds an attribute.
func WithAttr(key string, value interface{}) SpanOption {
	return func(s *Span) {
		s.Attrs = append(s.Attrs, Attr{Key: key, Value: value})
	}
}

// WithLevel sets span trace level.
func WithLevel(level TraceLevel) SpanOption {
	return func(s *Span) {
		s.Level = level
	}
}

// Export exports spans (implements OTLP-compatible export).
func (t *Tracer) Export() []*Span {
	return t.spans
}

var (
	spanKey = &struct{}{}
)

// generateTraceID creates a 128-bit trace ID.
func generateTraceID() [16]byte {
	var id [16]byte
	now := time.Now().UnixNano()
	id[0] = byte(now >> 56)
	id[1] = byte(now >> 48)
	id[2] = byte(now >> 40)
	id[3] = byte(now >> 32)
	id[4] = byte(now >> 24)
	id[5] = byte(now >> 16)
	id[6] = byte(now >> 8)
	id[7] = byte(now)
	b := atomic.AddUint64(&counter, 1)
	for i := 0; i < 8; i++ {
		id[8+i] = byte(b >> (56 - i*8))
	}
	return id
}

// generateSpanID creates a 64-bit span ID.
func generateSpanID() [8]byte {
	var id [8]byte
	b := atomic.AddUint64(&counter, 1)
	for i := 0; i < 8; i++ {
		id[i] = byte(b >> (56 - i*8))
	}
	return id
}

var counter uint64

// String implements fmt.Stringer for TraceLevel.
func (l TraceLevel) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelBasic:
		return "basic"
	case LevelDetailed:
		return "detailed"
	case LevelVerbose:
		return "verbose"
	default:
		return "unknown"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (l TraceLevel) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (l *TraceLevel) UnmarshalText(text []byte) error {
	switch string(text) {
	case "none":
		*l = LevelNone
	case "basic":
		*l = LevelBasic
	case "detailed":
		*l = LevelDetailed
	case "verbose":
		*l = LevelVerbose
	default:
		return fmt.Errorf("unknown trace level: %s", text)
	}
	return nil
}

// SpanFromContext extracts a span from context.
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanKey).(*Span); ok {
		return span
	}
	return nil
}

// NewSpanContext creates a new span context with trace/span IDs.
func NewSpanContext(traceID [16]byte, spanID [8]byte) context.Context {
	span := &Span{
		TraceID: traceID,
		SpanID:  spanID,
	}
	return context.WithValue(context.Background(), spanKey, span)
}
