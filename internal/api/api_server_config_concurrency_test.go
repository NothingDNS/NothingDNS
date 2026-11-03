package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/config"
)

func TestServerConfigConcurrentRuntimeOverride(t *testing.T) {
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
			enabled := i%2 == 0
			patch := &config.RuntimeOverrides{
				DNS64: &config.DNS64Override{Enabled: &enabled},
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
			req := httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil)
			req = req.WithContext(newAuthenticatedContext(f.admin))
			rec := httptest.NewRecorder()
			f.server.handleServerConfig(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("server-config GET status %d: %s", rec.Code, rec.Body.String())
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
