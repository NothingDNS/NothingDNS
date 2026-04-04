package zone

import (
	"fmt"
	"testing"
)

func newBenchZone() *Zone {
	z := NewZone("example.com.")
	z.DefaultTTL = 300

	// Add SOA
	z.Records["example.com."] = []Record{
		{Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
	}

	// Add NS records
	z.Records["example.com."] = append(z.Records["example.com."],
		Record{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.example.com."},
		Record{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.example.com."},
	)

	// Add A records for various subdomains
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("host%d.example.com.", i)
		z.Records[name] = []Record{
			{Name: name, TTL: 300, Class: "IN", Type: "A", RData: fmt.Sprintf("10.0.%d.%d", i/256, i%256)},
		}
	}

	// Add www
	z.Records["www.example.com."] = []Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "93.184.216.34"},
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2606:2800:220:1:248:1893:25c8:1946"},
	}

	// Add MX
	z.Records["example.com."] = append(z.Records["example.com."],
		Record{Name: "example.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
	)

	return z
}

func BenchmarkZoneLookup_Hit(b *testing.B) {
	z := newBenchZone()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = z.Lookup("www.example.com.", "A")
	}
}

func BenchmarkZoneLookup_Miss(b *testing.B) {
	z := newBenchZone()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = z.Lookup("nonexistent.example.com.", "A")
	}
}

func BenchmarkZoneLookupAll(b *testing.B) {
	z := newBenchZone()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = z.LookupAll("www.example.com.")
	}
}

func BenchmarkZoneLookup_ManyRecords(b *testing.B) {
	z := newBenchZone()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("host%d.example.com.", i%100)
		_ = z.Lookup(name, "A")
	}
}

func BenchmarkZoneLookupParallel(b *testing.B) {
	z := newBenchZone()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i%100)
			_ = z.Lookup(name, "A")
			i++
		}
	})
}
