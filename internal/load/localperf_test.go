//go:build perf

package load

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Flood 127.0.0.1:15353 with authoritative A queries. Reports success QPS.
// Server must already be running. PERF_ADDR overrides the target.
func TestLocalUDPFlood(t *testing.T) {
	addr := "127.0.0.1:15353"
	if v := getenv("PERF_ADDR"); v != "" {
		addr = v
	}
	workers := runtime.NumCPU() * 2
	if v := getenv("PERF_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workers = n
		}
	}
	duration := 3 * time.Second

	// example.test A
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0,
		0x00, 0x01, 0x00, 0x01,
	}

	var ok, fail atomic.Int64
	var wg sync.WaitGroup
	stop := time.Now().Add(duration)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			query := append([]byte(nil), q...)
			buf := make([]byte, 512)
			id := uint16(1)
			for time.Now().Before(stop) {
				id++
				binary.BigEndian.PutUint16(query[:2], id)
				_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if _, err := conn.Write(query); err != nil {
					fail.Add(1)
					continue
				}
				n, err := conn.Read(buf)
				if err != nil || n < 12 || buf[0] != query[0] || buf[1] != query[1] {
					fail.Add(1)
					continue
				}
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	success := ok.Load()
	qps := float64(success) / duration.Seconds()
	fmt.Printf("workers=%d success=%d fail=%d qps=%.0f\n", workers, success, fail.Load(), qps)
}

func getenv(k string) string {
	return os.Getenv(k)
}
