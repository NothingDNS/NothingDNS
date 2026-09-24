// NothingDNS — DNS transport server lifecycle.
//
// Extracts the transport-start and transport-shutdown sequences out of
// run() so the main function reads as three clear phases: init managers,
// start transports, handle signals.

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/quic"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// servers holds all DNS transport server instances.
type servers struct {
	udp *server.UDPServer
	tcp *server.TCPServer
	// Listeners for additional server.bind / udp_bind / tcp_bind addresses
	// beyond the first (udp/tcp above).
	extraUDP []*server.UDPServer
	extraTCP []*server.TCPServer
	tls      *server.TLSServer
	doq      *quic.DoQServer
	xot      *transfer.XoTServer
}

// startServers creates and starts the UDP, TCP, TLS (DoT), DoQ, and XoT
// transport servers based on the config. Returns the created servers or
// the partially-started set on error (so callers can shut them down).
func startServers(cfg *config.Config, handler *integratedHandler, transferMgr *TransferManager, logger *util.Logger) (*servers, error) {
	s := &servers{}

	udpAddrs := dnsListenAddrs(cfg.Server.UDPBind, cfg.Server.Bind, cfg.Server.Port)
	tcpAddrs := dnsListenAddrs(cfg.Server.TCPBind, cfg.Server.Bind, cfg.Server.Port)

	// UDP
	for i, addr := range udpAddrs {
		udp := server.NewUDPServerWithWorkers(addr, handler, cfg.Server.UDPWorkers)
		if err := udp.Listen(); err != nil {
			return s, fmt.Errorf("starting UDP server on %s: %w", addr, err)
		}
		if i == 0 {
			s.udp = udp
		} else {
			s.extraUDP = append(s.extraUDP, udp)
		}
		go func() {
			if err := udp.Serve(); err != nil {
				logger.Errorf("UDP server error on %s: %v", addr, err)
			}
		}()
		logger.Infof("UDP server listening on %s", addr)
	}

	// DSO (RFC 8490): one shared adapter serves both TCP and DoT — conn
	// keys are unique across listeners. Installed before Serve starts.
	var dsoAdapter *dsoConnAdapter
	if handler.dsoManager != nil {
		dsoAdapter = newDSOConnAdapter(handler.dsoManager, logger)
	}

	// TCP
	for i, addr := range tcpAddrs {
		tcp := server.NewTCPServerWithWorkers(addr, handler, cfg.Server.TCPWorkers)
		if dsoAdapter != nil {
			// Session creation still refuses plain TCP unless the DSO manager
			// was configured with AllowPlainTCP (RFC 8490 §5.1).
			tcp.SetDSOHandler(dsoAdapter)
		}
		if err := tcp.Listen(); err != nil {
			return s, fmt.Errorf("starting TCP server on %s: %w", addr, err)
		}
		if i == 0 {
			s.tcp = tcp
		} else {
			s.extraTCP = append(s.extraTCP, tcp)
		}
		go func() {
			if err := tcp.Serve(); err != nil {
				logger.Errorf("TCP server error on %s: %v", addr, err)
			}
		}()
		logger.Infof("TCP server listening on %s", addr)
	}

	// TLS (DoT)
	if cfg.Server.TLS.Enabled {
		if err := s.startTLS(cfg, handler, dsoAdapter, logger); err != nil {
			return s, err
		}
	}

	// DoQ (RFC 9250)
	if cfg.Server.QUIC.Enabled {
		if err := s.startDoQ(cfg, handler, logger); err != nil {
			return s, err
		}
	}

	// XoT (RFC 9103)
	if cfg.Server.XoT.Enabled {
		if err := s.startXoT(cfg, handler.zones, transferMgr, logger); err != nil {
			return s, err
		}
	}

	return s, nil
}

// startTLS starts the DNS-over-TLS server.
func (s *servers) startTLS(cfg *config.Config, handler *integratedHandler, dsoAdapter *dsoConnAdapter, logger *util.Logger) error {
	tlsAddr := cfg.Server.TLS.Bind
	if tlsAddr == "" {
		tlsAddr = fmt.Sprintf(":%d", server.DefaultTLSPort)
	}

	tlsConfig, err := buildTLSConfig(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}

	s.tls = server.NewTLSServer(tlsAddr, handler, tlsConfig)
	if dsoAdapter != nil {
		s.tls.SetDSOHandler(dsoAdapter)
	}
	if err := s.tls.Listen(); err != nil {
		return fmt.Errorf("starting TLS server: %w", err)
	}
	go func() {
		if err := s.tls.Serve(); err != nil {
			logger.Errorf("TLS server error: %v", err)
		}
	}()
	logger.Infof("TLS server listening on %s (DoT)", tlsAddr)
	return nil
}

// startDoQ starts the DNS-over-QUIC server (RFC 9250).
func (s *servers) startDoQ(cfg *config.Config, handler *integratedHandler, logger *util.Logger) error {
	doqAddr := cfg.Server.QUIC.Bind
	if doqAddr == "" {
		doqAddr = fmt.Sprintf(":%d", quic.DefaultDoQPort)
	}

	certFile := cfg.Server.QUIC.CertFile
	keyFile := cfg.Server.QUIC.KeyFile
	// Fall back to TLS cert if QUIC-specific cert is not set
	if certFile == "" && cfg.Server.TLS.CertFile != "" {
		certFile = cfg.Server.TLS.CertFile
		keyFile = cfg.Server.TLS.KeyFile
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("QUIC enabled but cert_file/key_file not configured")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading QUIC certificate: %w", err)
	}

	quicTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	doqHandler := &doqHandlerAdapter{handler: handler}
	s.doq = quic.NewDoQServer(doqAddr, doqHandler, quicTLSConfig)
	if err := s.doq.Listen(); err != nil {
		return fmt.Errorf("starting DoQ server: %w", err)
	}
	go func() {
		if err := s.doq.Serve(); err != nil {
			logger.Errorf("DoQ server error: %v", err)
		}
	}()
	logger.Infof("DoQ server listening on %s (DNS over QUIC)", doqAddr)
	return nil
}

// startXoT starts the DNS Zone Transfer over TLS server (RFC 9103).
func (s *servers) startXoT(cfg *config.Config, zones map[string]*zone.Zone, transferMgr *TransferManager, logger *util.Logger) error {
	xotAddr := cfg.Server.XoT.Bind
	if xotAddr == "" {
		xotAddr = fmt.Sprintf(":%d", 853)
	}

	xotConfig := &transfer.XoTConfig{
		CertFile:        cfg.Server.XoT.CertFile,
		KeyFile:         cfg.Server.XoT.KeyFile,
		CAFile:          cfg.Server.XoT.CAFile,
		ListenPort:      853,
		MinTLSVersion:   cfg.Server.XoT.MinTLSVersion,
		AllowedNetworks: cfg.Server.XoT.AllowedNetworks,
	}

	// Reuse TLS cert if XoT cert not specifically configured
	if xotConfig.CertFile == "" && cfg.Server.TLS.CertFile != "" {
		xotConfig.CertFile = cfg.Server.TLS.CertFile
		xotConfig.KeyFile = cfg.Server.TLS.KeyFile
	}
	if xotConfig.CertFile == "" || xotConfig.KeyFile == "" {
		return fmt.Errorf("XoT enabled but cert_file/key_file not configured")
	}

	var err error
	s.xot, err = transfer.NewXoTServer(zones, xotConfig, logger)
	if err != nil {
		return fmt.Errorf("creating XoT server: %w", err)
	}
	s.xot.SetJournalStore(transferMgr.Result().JournalStore)

	if err := s.xot.Serve(xotAddr); err != nil {
		return fmt.Errorf("starting XoT server: %w", err)
	}
	go s.xot.AcceptLoop()
	logger.Infof("XoT server listening on %s (DNS Zone Transfer over TLS, RFC 9103)", s.xot.Addr())
	return nil
}

// stopAll shuts down all transport servers. Each is stopped independently;
// failures are logged but do not prevent the remaining servers from
// shutting down.
func (s *servers) stopAll(logger *util.Logger) {
	for _, udp := range s.udpServers() {
		if err := udp.Stop(); err != nil {
			logger.Warnf("Failed to stop UDP server cleanly: %v", err)
		}
	}
	for _, tcp := range s.tcpServers() {
		if err := tcp.Stop(); err != nil {
			logger.Warnf("Failed to stop TCP server cleanly: %v", err)
		}
	}
	if s.tls != nil {
		if err := s.tls.Stop(); err != nil {
			logger.Warnf("Failed to stop TLS server cleanly: %v", err)
		}
	}
	if s.doq != nil {
		if err := s.doq.Stop(); err != nil {
			logger.Warnf("Failed to stop DoQ server cleanly: %v", err)
		}
	}
	if s.xot != nil {
		if err := s.xot.Close(); err != nil {
			logger.Warnf("Failed to close XoT server cleanly: %v", err)
		}
	}
}

// udpServers returns every running UDP listener.
func (s *servers) udpServers() []*server.UDPServer {
	if s.udp == nil {
		return nil
	}
	return append([]*server.UDPServer{s.udp}, s.extraUDP...)
}

// tcpServers returns every running TCP listener.
func (s *servers) tcpServers() []*server.TCPServer {
	if s.tcp == nil {
		return nil
	}
	return append([]*server.TCPServer{s.tcp}, s.extraTCP...)
}

// dnsListenAddrs resolves the listen addresses for one DNS transport:
// the transport-specific list (udp_bind / tcp_bind) wins, then server.bind,
// then ":port". Every entry is used — previously only the first was, so
// additional bind addresses were silently ignored.
//
// A wildcard entry (0.0.0.0, ::, or an empty host) already accepts traffic
// on every local address — Go opens it dual-stack — so any other entry on
// the same port would fail with "address already in use". Such entries are
// folded into the first wildcard for that port.
//
// Multi-homed / secondary /32 alias UDP source sticky-ness is handled by
// Linux IP_PKTINFO on the wildcard socket (see internal/server/udp_pktinfo*),
// not by expanding wildcards into per-IP listeners.
func dnsListenAddrs(explicit, bind []string, port int) []string {
	entries := explicit
	if len(entries) == 0 {
		entries = bind
	}
	if len(entries) == 0 {
		return []string{fmt.Sprintf(":%d", port)}
	}

	addrs := make([]string, 0, len(entries))
	for _, e := range entries {
		addrs = append(addrs, bindEntryToAddr(e, port))
	}

	wildcardPorts := make(map[string]bool)
	for _, a := range addrs {
		if host, p, err := net.SplitHostPort(a); err == nil && isWildcardHost(host) {
			wildcardPorts[p] = true
		}
	}

	out := make([]string, 0, len(addrs))
	seen := make(map[string]bool)
	wildcardUsed := make(map[string]bool)
	for _, a := range addrs {
		host, p, err := net.SplitHostPort(a)
		key := a
		if err == nil && wildcardPorts[p] {
			if !isWildcardHost(host) || wildcardUsed[p] {
				continue
			}
			wildcardUsed[p] = true
			key = "*:" + p
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	return out
}

func isWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// buildTLSConfig creates a tls.Config for DoT with dynamic certificate
// reloading (supports Let's Encrypt auto-renewal without restart).
func buildTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		// Dynamic certificate loading — reloads on each handshake.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			updatedCert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}
			return &updatedCert, nil
		},
	}, nil
}

// startStatsCollector launches a background goroutine that periodically
// reads transport stats and reports them to the metrics collector.
// Stops when stopCh is closed.
func startStatsCollector(srvs *servers, metricsCollector metricsTransport, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if metricsCollector != nil && srvs.udp != nil && srvs.tcp != nil {
					var us server.UDPServerStats
					for _, udp := range srvs.udpServers() {
						st := udp.Stats()
						us.PacketsReceived += st.PacketsReceived
						us.PacketsSent += st.PacketsSent
						us.Errors += st.Errors
					}
					var ts server.TCPServerStats
					for _, tcp := range srvs.tcpServers() {
						st := tcp.Stats()
						ts.ConnectionsAccepted += st.ConnectionsAccepted
						ts.ConnectionsClosed += st.ConnectionsClosed
						ts.MessagesReceived += st.MessagesReceived
						ts.Errors += st.Errors
					}
					metricsCollector.SetTransportStats(
						us.PacketsReceived, us.PacketsSent, us.Errors,
						ts.ConnectionsAccepted, ts.ConnectionsClosed, ts.MessagesReceived, ts.Errors,
					)
				}
			}
		}
	}()
}

// metricsTransport is the narrow interface for the stats collector.
type metricsTransport interface {
	SetTransportStats(
		udpRx, udpTx, udpErrors uint64,
		tcpConnAccepted, tcpConnClosed, tcpMsgRx, tcpErrors uint64,
	)
}
