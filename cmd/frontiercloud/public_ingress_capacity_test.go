package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type blockedIdentityControl struct {
	*edgeFixture
	entered chan struct{}
	release chan struct{}
}

func (c *blockedIdentityControl) IdentityState(ctx context.Context) (store.NodeIdentity, error) {
	select {
	case c.entered <- struct{}{}:
	case <-ctx.Done():
		return store.NodeIdentity{}, ctx.Err()
	}
	select {
	case <-c.release:
		return c.edgeFixture.IdentityState(ctx)
	case <-ctx.Done():
		return store.NodeIdentity{}, ctx.Err()
	}
}

func TestNativeKeyAdmissionSurvivesBusyBusinessSlots(t *testing.T) {
	fixture := &blockedIdentityControl{
		edgeFixture: &edgeFixture{master: "https://master.example", nonces: map[string]bool{}},
		entered:     make(chan struct{}, 17),
		release:     make(chan struct{}),
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := masterIngressEdge(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unsigned request reached business")
	}), fixture, resolver)
	var wg sync.WaitGroup
	defer func() { close(fixture.release); wg.Wait() }()
	call := func(method, path string, done chan<- int) {
		defer wg.Done()
		r := httptest.NewRequest(method, publicproxy.EdgePrefix+path, nil)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		edge.ServeHTTP(w, r)
		if done != nil {
			done <- w.Code
		}
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go call(http.MethodGet, "/api/v1/media/catalog/media", nil)
	}
	for i := 0; i < 16; i++ {
		select {
		case <-fixture.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("business requests did not occupy all business slots")
		}
	}
	done := make(chan int, 1)
	wg.Add(1)
	go call(http.MethodPost, "/api/v1/media/crypto/native/source", done)
	select {
	case <-fixture.entered:
		// Key work reached identity verification despite saturated business slots.
	case status := <-done:
		t.Fatalf("native key request was rejected before identity verification: %d", status)
	case <-time.After(5 * time.Second):
		t.Fatal("native key request did not reach its reserved slot")
	}
}
