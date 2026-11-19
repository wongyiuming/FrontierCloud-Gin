package main

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

type masterStartupRoute struct{ handler http.Handler }

// masterIngressBootstrap uses the final listener throughout startup. Until
// publication it serves only the existing authenticated candidate probe and
// returns 503 for every business request. No additional server or port exists.
type masterIngressBootstrap struct {
	current  atomic.Pointer[masterStartupRoute]
	server   *http.Server
	listener net.Listener
	errors   chan error
}

func startMasterIngressBootstrap(ctx context.Context, address string, runtime *maintenance.Runtime, control ingressEdgeControl, resolver *network.Resolver) (*masterIngressBootstrap, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	b := &masterIngressBootstrap{listener: listener, errors: make(chan error, 1)}
	b.current.Store(&masterStartupRoute{handler: masterIngressProbeOnly(control, resolver)})
	switcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.current.Load().handler.ServeHTTP(w, r) })
	b.server = &http.Server{Addr: address, Handler: runtime.Handler(switcher), BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { b.errors <- b.server.Serve(listener) }()
	return b, nil
}

func (b *masterIngressBootstrap) publish(handler http.Handler) {
	b.current.Store(&masterStartupRoute{handler: handler})
}
