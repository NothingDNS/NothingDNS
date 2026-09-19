// NothingDNS - Handler Dependencies Reference
// This file documents the logical grouping of handler dependencies.
// Use as reference for future refactoring - the struct is not yet embedded.
//
// Groups: DNSResolver, ZoneStorage, SecurityComponents, DNSSECComponents,
//         TransferComponents, Observability, SpecialFeatures

package main

import (
	"github.com/nothingdns/nothingdns/internal/audit"
	"github.com/nothingdns/nothingdns/internal/blocklist"
	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dns64"
	"github.com/nothingdns/nothingdns/internal/dnscookie"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/dso"
	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/geodns"
	"github.com/nothingdns/nothingdns/internal/mdns"
	"github.com/nothingdns/nothingdns/internal/metrics"
	"github.com/nothingdns/nothingdns/internal/otel"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// DNSResolver groups recursive resolution dependencies.
type DNSResolver struct {
	Upstream     *upstream.Client
	LoadBalancer *upstream.LoadBalancer
	Resolver     *resolver.Resolver
}

// ZoneStorage groups zone data and persistence dependencies.
type ZoneStorage struct {
	Zones         map[string]*zone.Zone
	ZoneManager   *zone.Manager
	KVPersistence *zone.KVPersistence
	ZoneTree      *zone.RadixTree
}

// SecurityComponents groups DNS security filtering dependencies.
type SecurityComponents struct {
	Blocklist   *blocklist.Blocklist
	RPZEngine   *rpz.Engine
	GeoEngine   *geodns.Engine
	ACLChecker  *filter.ACLChecker
	RateLimiter *filter.RateLimiter
	RRL         *filter.RRL
	DNS64Synth  *dns64.Synthesizer
	// RecursionPolicy limits recursion and cached answers to allowed
	// clients; nil allows everyone.
	RecursionPolicy *filter.RecursionPolicy
}

// DNSSEC components for signature validation and zone signing.
type DNSSECComponents struct {
	Validator   *dnssec.Validator
	ZoneSigners map[string]*dnssec.Signer
}

// TransferComponents groups zone transfer dependencies.
type TransferComponents struct {
	AXFRServer    *transfer.AXFRServer
	IXFRServer    *transfer.IXFRServer
	NotifyHandler *transfer.NOTIFYSlaveHandler
	DDNSHandler   *transfer.DynamicDNSHandler
	SlaveManager  *transfer.SlaveManager
}

// Observability groups monitoring and tracing dependencies.
type Observability struct {
	Metrics     *metrics.MetricsCollector
	Tracer      *otel.Tracer
	AuditLogger *audit.AuditLogger
}

// SpecialFeatures groups optional features like DNS64, NSEC cache, etc.
type SpecialFeatures struct {
	DNS64Synth    *dns64.Synthesizer
	NSECCache     *cache.NSECCache
	CookieJar     *dnscookie.CookieJar
	MDNSResponder *mdns.Responder
	DSOManager    *dso.Manager
}

// HandlerDeps groups all handler dependencies into logical categories.
// This reduces the integratedHandler struct from 37 fields to 11 groups.
type HandlerDeps struct {
	Config  *config.Config
	Logger  *util.Logger
	Cluster *cluster.Cluster

	DNSResolver
	ZoneStorage
	SecurityComponents
	DNSSECComponents
	TransferComponents
	Observability
	SpecialFeatures

	SplitHorizon *filter.SplitHorizon
	ViewZones    map[string]map[string]*zone.Zone

	IDNAEnabled bool // RFC 5891 IDNA validation
}
