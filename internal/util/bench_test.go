package util

import (
	"net"
	"testing"
)

func BenchmarkParseDomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDomain("www.example.com.")
	}
}

func BenchmarkParseDomain_Long(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDomain("very.long.subdomain.deep.nesting.host.example.co.uk.")
	}
}

func BenchmarkNormalizeDomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = NormalizeDomain("WWW.Example.COM")
	}
}

func BenchmarkIsValidDomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsValidDomain("www.example.com.")
	}
}

func BenchmarkIsSubdomain(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsSubdomain("sub.www.example.com.", "example.com.")
	}
}

func BenchmarkParseIP_v4(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseIP("192.168.1.1")
	}
}

func BenchmarkParseIP_v6(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseIP("2001:db8::1")
	}
}

func BenchmarkParseCIDR(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCIDR("192.168.0.0/16")
	}
}

func BenchmarkCIDRContains(b *testing.B) {
	cidr, _ := ParseCIDR("10.0.0.0/8")
	ip := net.ParseIP("10.1.2.3")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cidr.Contains(ip)
	}
}

func BenchmarkIsPrivateIP(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPrivateIP(ip)
	}
}

func BenchmarkReverseDNS_v4(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ReverseDNS(ip)
	}
}

func BenchmarkReverseDNS_v6(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ReverseDNS(ip)
	}
}
