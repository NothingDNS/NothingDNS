package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func newBenchCache(capacity int) *Cache {
	return New(Config{
		Capacity:   capacity,
		MinTTL:     1 * time.Second,
		MaxTTL:     1 * time.Hour,
		DefaultTTL: 5 * time.Minute,
	})
}

func benchMessage(id uint16) *protocol.Message {
	name, _ := protocol.ParseName("www.example.com.")
	return &protocol.Message{
		Header: protocol.Header{ID: id, Flags: protocol.Flags{QR: true}, ANCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}
}

func BenchmarkCacheSet(b *testing.B) {
	c := newBenchCache(100000)
	msg := benchMessage(1)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Set(fmt.Sprintf("key-%d", i), msg, 300)
	}
}

func BenchmarkCacheGet_Hit(b *testing.B) {
	c := newBenchCache(100000)
	msg := benchMessage(1)

	for i := 0; i < 1000; i++ {
		c.Set(fmt.Sprintf("key-%d", i), msg, 300)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.Get(fmt.Sprintf("key-%d", i%1000))
	}
}

func BenchmarkCacheGet_Miss(b *testing.B) {
	c := newBenchCache(100000)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.Get(fmt.Sprintf("miss-%d", i))
	}
}

func BenchmarkCacheSetEviction(b *testing.B) {
	c := newBenchCache(1000) // small capacity to force eviction
	msg := benchMessage(1)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Set(fmt.Sprintf("evict-%d", i), msg, 300)
	}
}

func BenchmarkCacheGetParallel(b *testing.B) {
	c := newBenchCache(100000)
	msg := benchMessage(1)

	for i := 0; i < 10000; i++ {
		c.Set(fmt.Sprintf("key-%d", i), msg, 300)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = c.Get(fmt.Sprintf("key-%d", i%10000))
			i++
		}
	})
}

func BenchmarkCacheSetParallel(b *testing.B) {
	c := newBenchCache(100000)
	msg := benchMessage(1)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Set(fmt.Sprintf("par-%d", i), msg, 300)
			i++
		}
	})
}
