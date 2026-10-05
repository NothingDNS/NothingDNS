package otel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type flushFailureWriter struct {
	header http.Header
	code   int
}

func (w *flushFailureWriter) Header() http.Header { return w.header }
func (w *flushFailureWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *flushFailureWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return len(b), nil
}

type flushErrorWriter struct{ *flushFailureWriter }

func (w *flushErrorWriter) FlushError() error { return io.ErrClosedPipe }
func TestHTTPTraceFlushFailurePreservesStatus(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	for _, direct := range []bool{false, true} {
		for _, kind := range []string{"unsupported", "failed", "committed", "supported"} {
			tr := NewTracer(Config{Enabled: true, SampleRate: 1})
			t.Cleanup(func() {
				if err := tr.Shutdown(context.Background()); err != nil {
					t.Error(err)
				}
			})
			base := &flushFailureWriter{header: make(http.Header)}
			var target http.ResponseWriter = base
			want := 503
			var expectedError error = http.ErrNotSupported
			if kind == "failed" {
				target = &flushErrorWriter{base}
				expectedError = io.ErrClosedPipe
			}
			if kind == "committed" {
				want = 202
			}
			var recorder *httptest.ResponseRecorder
			if kind == "supported" {
				recorder = httptest.NewRecorder()
				target = recorder
				want = 200
				expectedError = nil
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "committed" {
					w.WriteHeader(202)
				}
				err := http.NewResponseController(w).Flush()
				if !errors.Is(err, expectedError) {
					t.Fatalf("flush error %v want %v", err, expectedError)
				}
				w.WriteHeader(503)
			})
			var h http.Handler = Middleware(tr)(handler)
			if direct {
				h = TraceHandler(tr, "stream", handler)
			}
			h.ServeHTTP(target, httptest.NewRequest("GET", "/stream", nil))
			actual := base.code
			if recorder != nil {
				actual = recorder.Code
				if !recorder.Flushed {
					t.Fatal("supported writer not flushed")
				}
			}
			if actual != want {
				t.Fatalf("%s: status %d want %d", kind, actual, want)
			}
			spans := tr.Export()
			if len(spans) != 1 {
				t.Fatal("missing span")
			}
			found := false
			for _, a := range spans[0].Attrs {
				if a.Key == "http.status_code" && a.Value == int64(want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: incorrect traced status", kind)
			}
		}
	}

}
