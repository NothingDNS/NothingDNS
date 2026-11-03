package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestConfigGetConcurrentRuntimeOverride(t *testing.T) {
	f := newOverridesFixture(t)
	f.server.WithRuntimeOverrides("")

	const iterations = 500
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			depth := 10 + i%2
			patch := &config.RuntimeOverrides{
				Resolution: &config.ResolutionOverride{MaxDepth: &depth},
			}
			if err := f.server.persistAndApplyOverrides(patch); err != nil {
				errs <- fmt.Errorf("apply override: %w", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
			req = req.WithContext(newAuthenticatedContext(f.admin))
			rec := httptest.NewRecorder()
			f.server.handleConfigGet(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("config GET status %d: %s", rec.Code, rec.Body.String())
				return
			}
		}
	}()

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
