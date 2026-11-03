package main

import (
	"context"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type dnssecAdapterConcurrencyUpstream struct{}

func (dnssecAdapterConcurrencyUpstream) Query(*protocol.Message) (*protocol.Message, error) {
	return &protocol.Message{}, nil
}

func TestDNSSECResolverAdapterConcurrentReloadAndQuery(t *testing.T) {
	a := &dnssecResolverAdapter{upstream: dnssecAdapterConcurrencyUpstream{}}
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(2)
	done.Add(2)
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		for i := 0; i < 2000; i++ {
			a.SetIterative(nil)
		}
	}()
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_, _ = a.Query(context.Background(), "example.com.", protocol.TypeA)
		}
	}()
	ready.Wait()
	close(start)
	done.Wait()
}
