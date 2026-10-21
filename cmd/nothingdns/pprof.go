package main

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// startPprof serves the Go pprof handlers on addr (validated as loopback by
// config validation) until ctx is cancelled. It serves from a private mux (the net/http/pprof
// import also registers on http.DefaultServeMux, which nothing here serves). The bind happens synchronously so a port
// conflict is reported to the caller.
func startPprof(ctx context.Context, addr string, logger *util.Logger) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && logger != nil {
			logger.Warnf("pprof listener stopped: %v", err)
		}
	}()
	return ln.Addr(), nil
}
