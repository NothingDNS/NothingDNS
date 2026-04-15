package rpz

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
)

func benchEngine() *Engine {
	logger := util.NewLogger(util.INFO, util.TextFormat, nil)
	e := NewEngine(Config{
		Enabled: true,
		Logger:  logger,
	})

	// Add QNAME rules
	patterns := []string{
		"ads.example.com",
		"tracker.example.com",
		"*.ad.example.com",
		"*.ads.example.net",
		"malware.test.com",
		"phishing.bad.com",
		"*.tracker.network",
		"block.example.org",
	}
	for _, p := range patterns {
		e.AddQNAMERule(p, ActionNXDOMAIN, "")
	}

	// Add client IP rules
	cidrs := []string{
		"10.0.0.0/8",
		"192.168.1.0/24",
		"172.16.0.0/12",
		"203.0.113.0/24",
	}
	for _, cidr := range cidrs {
		rule := &Rule{
			Trigger:  TriggerClientIP,
			Pattern:  cidr,
			Action:   ActionNXDOMAIN,
			Priority: 10,
		}
		e.addRule(rule)
	}

	return e
}

func BenchmarkQNAMEPolicy_ExactMatch(b *testing.B) {
	e := benchEngine()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.QNAMEPolicy("ads.example.com.")
	}
}

func BenchmarkQNAMEPolicy_SuffixMatch(b *testing.B) {
	e := benchEngine()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.QNAMEPolicy("sub.ad.example.com.")
	}
}

func BenchmarkQNAMEPolicy_Miss(b *testing.B) {
	e := benchEngine()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.QNAMEPolicy("clean.safe.example.com.")
	}
}

func BenchmarkClientIPPolicy_Hit(b *testing.B) {
	e := benchEngine()
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.ClientIPPolicy(ip)
	}
}

func BenchmarkClientIPPolicy_Miss(b *testing.B) {
	e := benchEngine()
	ip := net.ParseIP("8.8.8.8")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.ClientIPPolicy(ip)
	}
}
