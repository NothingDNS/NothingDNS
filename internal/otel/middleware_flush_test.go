package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTracingMiddlewarePreservesFlush(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	for _, tracedHandler := range []bool{false, true} {
		for _, code := range []int{0, http.StatusAccepted} {
			tr := newTestTracer()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code != 0 {
					w.WriteHeader(code)
				}
				controller := http.NewResponseController(w)
				for i := 0; i < 2; i++ {
					if err := controller.Flush(); err != nil {
						t.Fatalf("Flush: %v", err)
					}
				}
				w.WriteHeader(http.StatusInternalServerError)
			})
			var h http.Handler = Middleware(tr)(handler)
			if tracedHandler {
				h = TraceHandler(tr, "stream", handler)
			}
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, httptest.NewRequest("GET", "/stream", nil))
			want := code
			if want == 0 {
				want = http.StatusOK
			}
			if recorder.Code != want || !recorder.Flushed {
				t.Fatalf("code=%d flushed=%v, want %d/true", recorder.Code, recorder.Flushed, want)
			}
			spans := tr.Export()
			if len(spans) != 1 {
				t.Fatalf("spans=%d, want 1", len(spans))
			}
			found := false
			for _, attr := range spans[0].Attrs {
				if attr.Key == "http.status_code" && attr.Value == int64(want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing status %d in %v", want, spans[0].Attrs)
			}
			if err := tr.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
}
