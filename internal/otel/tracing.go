// Package otel is NothingDNS's tracing facade over the official
// OpenTelemetry SDK. It preserves the package's original consumer-facing
// API (Tracer/Span/Attr/StartSpan/EndSpan/Middleware) while replacing the
// former hand-rolled tracer, OTLP JSON exporter, and Jaeger exporter with:
//
//   - sdktrace.TracerProvider with ParentBased(TraceIDRatioBased) sampling
//   - BatchSpanProcessor + otlptracehttp exporter when an OTLP endpoint is
//     configured (OTLP/HTTP+protobuf, the modern collector default)
//   - an in-memory span recorder when no endpoint is configured, keeping
//     Tracer.Export() meaningful for tests and local debugging
//   - W3C Trace Context propagation (traceparent/tracestate), set as the
//     global propagator and applied by the HTTP middleware
package otel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// maxRetainedSpans bounds the in-memory recorder so a tracer without an
// OTLP endpoint (tests, local runs) cannot grow without bound when spans
// are never drained via Export().
const maxRetainedSpans = 4096

// TraceLevel defines tracing verbosity. Retained for configuration and
// attribute-tagging compatibility; the SDK itself has no per-span level.
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
	SampleRate float64    `yaml:"sample_rate"` // 0.0-1.0
	// Endpoint is the OTLP collector endpoint (e.g. "http://localhost:4318").
	// When empty, NewTracer falls back to the standard OTLP environment
	// variables (OTEL_EXPORTER_OTLP_TRACES_ENDPOINT / OTEL_EXPORTER_OTLP_ENDPOINT);
	// if those are unset too, spans go to the in-memory recorder only.
	Endpoint string `yaml:"endpoint"`
}

// Attr is a key-value pair for span attributes. Values are applied to the
// underlying SDK span at EndSpan time via attribute.Any.
type Attr struct {
	Key   string
	Value interface{}
}

// Span is the facade's handle on an in-flight trace span. Consumer code
// appends to Attrs between StartSpan and EndSpan; EndSpan transfers them
// onto the SDK span before ending it. A nil *Span is the "not recording"
// state, exactly like the previous implementation — callers already
// nil-check.
type Span struct {
	Name      string
	TraceID   [16]byte
	SpanID    [8]byte
	ParentID  [8]byte
	StartTime time.Time
	EndTime   time.Time
	Level     TraceLevel
	Attrs     []Attr
	Err       error

	sdk trace.Span
}

// Tracer provides distributed tracing over the official SDK.
type Tracer struct {
	cfg Config

	provider *sdktrace.TracerProvider
	tracer   trace.Tracer

	recMu       sync.Mutex
	recorder    *memoryRecorder
	droppedSpns uint64
}

// NewTracer creates a tracer backed by a fresh TracerProvider. Sampling is
// ParentBased(TraceIDRatioBased(SampleRate)) — consistent probabilistic
// sampling per trace ID, the same semantics the hand-rolled tracer had.
// When an endpoint is configured (Config.Endpoint or the standard OTLP env
// vars), spans are batch-exported over OTLP/HTTP; otherwise they are
// retained in memory (bounded, Export()-drainable).
func NewTracer(cfg Config) *Tracer {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = otlpEndpointFromEnv()
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1.0
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
	}

	t := &Tracer{cfg: cfg}

	if endpoint != "" {
		if !strings.Contains(endpoint, "://") {
			// tolerate scheme-less endpoints by defaulting to http
			endpoint = "http://" + endpoint
		}
		exp, err := otlptracehttp.New(context.Background(),
			otlptracehttp.WithEndpointURL(endpoint),
		)
		if err == nil {
			opts = append(opts, sdktrace.WithBatcher(exp))
		}
	} else {
		t.recorder = newMemoryRecorder()
		opts = append(opts, sdktrace.WithSpanProcessor(t.recorder.processor()))
	}

	t.provider = sdktrace.NewTracerProvider(opts...)
	t.tracer = t.provider.Tracer("github.com/nothingdns/nothingdns")

	// W3C Trace Context is the wire format for distributed propagation.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return t
}

// otlpEndpointFromEnv reads the standard OTLP endpoint environment
// variables, preferring the traces-specific form.
func otlpEndpointFromEnv() string {
	if v := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); v != "" {
		return v
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
}

// StartSpan begins a new span. The returned context carries both the SDK
// span (so child spans and propagation work) and this facade's handle (so
// SpanFromContext works). When tracing is disabled the span is nil, and
// the context is returned unchanged.
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	if t == nil || !t.cfg.Enabled {
		return ctx, nil
	}

	sdkCtx, sdkSpan := t.tracer.Start(ctx, name)
	if !sdkSpan.SpanContext().IsSampled() {
		// Unsampled: end the SDK span immediately and behave like the
		// disabled path so no memory is retained and callers skip it.
		sdkSpan.End()
		return ctx, nil
	}

	sc := sdkSpan.SpanContext()
	span := &Span{
		Name:      name,
		TraceID:   sc.TraceID(),
		SpanID:    sc.SpanID(),
		StartTime: time.Now(),
		Level:     t.cfg.Level,
		sdk:       sdkSpan,
	}
	// The parent must be read from the INPUT context: the context returned
	// by tracer.Start carries the new child span itself, so reading there
	// would set ParentID to the span's own ID.
	if psc := trace.SpanContextFromContext(ctx); psc.IsValid() {
		span.ParentID = psc.SpanID()
	}

	for _, opt := range opts {
		opt(span)
	}
	if len(span.Attrs) > 0 {
		applyAttrs(sdkSpan, span.Attrs)
	}

	ctx = context.WithValue(sdkCtx, spanKey, span)
	return ctx, span
}

// EndSpan completes a span: it applies any attributes the consumer added
// since StartSpan, records the error (if any) on the SDK span, and ends
// it. Idempotent per span.
func (t *Tracer) EndSpan(span *Span, err error) {
	if span == nil || span.sdk == nil {
		return
	}
	if !span.EndTime.IsZero() {
		return
	}
	span.EndTime = time.Now()
	span.Err = err

	if len(span.Attrs) > 0 {
		applyAttrs(span.sdk, span.Attrs)
	}
	if err != nil {
		span.sdk.RecordError(err)
		span.sdk.SetAttributes(attributeBool("error", true))
	}
	span.sdk.End()
}

// Shutdown flushes and shuts down the underlying TracerProvider. Call
// once during graceful server shutdown; afterwards the tracer must not be
// used for new spans.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// DroppedSpans reports spans discarded by the in-memory recorder's cap.
// Always 0 when an OTLP endpoint is configured (the SDK's batch processor
// owns retention then).
func (t *Tracer) DroppedSpans() uint64 {
	t.recMu.Lock()
	defer t.recMu.Unlock()
	return t.droppedSpns
}

// Export drains and returns finished spans held by the in-memory recorder
// (no-endpoint configuration only — tests and local debugging).
func (t *Tracer) Export() []*Span {
	t.recMu.Lock()
	defer t.recMu.Unlock()
	if t.recorder == nil {
		return nil
	}
	spans := t.recorder.drain()
	t.droppedSpns += t.recorder.takeDropped()
	return spans
}

// SpanOption configures a span.
type SpanOption func(*Span)

// WithAttr adds an attribute (applied to the SDK span immediately).
func WithAttr(key string, value interface{}) SpanOption {
	return func(s *Span) {
		s.Attrs = append(s.Attrs, Attr{Key: key, Value: value})
	}
}

// WithLevel sets the span's level tag.
func WithLevel(level TraceLevel) SpanOption {
	return func(s *Span) {
		s.Level = level
	}
}

// WithParent records a parent span ID on the facade span. Parent linkage
// itself is derived from the context by the SDK; this option exists for
// compatibility with callers that tag the parent explicitly.
func WithParent(parentID [8]byte) SpanOption {
	return func(s *Span) {
		s.ParentID = parentID
	}
}

var (
	spanKey = &struct{}{}
)

// SpanFromContext extracts this facade's span handle from the context.
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanKey).(*Span); ok {
		return span
	}
	return nil
}

// NewSpanContext creates a context carrying the given trace/span IDs as a
// remote (W3C-propagated) parent, so a subsequent StartSpan becomes its
// child.
func NewSpanContext(traceID [16]byte, spanID [8]byte) context.Context {
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return trace.ContextWithRemoteSpanContext(context.Background(), sc)
}

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
