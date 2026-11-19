package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type peerIngressHTTP struct {
	next                   http.Handler
	control                *node.Service
	trusted                []string
	lookups                chan struct{}
	mu                     sync.Mutex
	ingress                store.PublicIngress
	relationship           string
	master                 string
	proxy                  *publicproxy.Handler
	candidateVerify        func(context.Context, string, http.Header, []byte) (node.Envelope, error)
	recordingControlsReady bool
}

func newPeerIngressHTTP(next http.Handler, control *node.Service, settings config.Config) *peerIngressHTTP {
	value := &peerIngressHTTP{next: next, control: control, trusted: append([]string(nil), settings.PublicIngressTrustedProxyNetworks...), lookups: make(chan struct{}, 16)}
	if control != nil {
		value.candidateVerify = control.VerifyCandidatePublicProbe
	}
	return value
}

func (p *peerIngressHTTP) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proxy != nil {
		p.proxy.CloseIdleConnections()
	}
}

func (p *peerIngressHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == node.IngressCandidatePublicPath {
		p.serveCandidateProbe(w, r)
		return
	}
	if !publicproxy.Eligible(r) {
		p.next.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if p.control == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	proxy, err := p.prepare(r.Context())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(w, r)
}

func (p *peerIngressHTTP) serveCandidateProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	resolver, err := network.New(p.trusted)
	if err != nil || p.candidateVerify == nil || r.Method != http.MethodPost || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || (r.TLS == nil && (!resolver.Resolve(r).FromTrustedProxy || !resolver.SecureAdmin(r))) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	select {
	case p.lookups <- struct{}{}:
		defer func() { <-p.lookups }()
	default:
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || len(body) == 0 || len(body) > 1024 {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	signed, err := p.candidateVerify(r.Context(), r.Host, r.Header, body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signed)
}

func (p *peerIngressHTTP) prepare(ctx context.Context) (*publicproxy.Handler, error) {
	select {
	case p.lookups <- struct{}{}:
	default:
		return nil, errors.New("public ingress lookup busy")
	}
	defer func() { <-p.lookups }()
	ingress, relation, err := p.control.CurrentPeerIngress(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proxy == nil || p.ingress != ingress || p.relationship != relation.ID || p.master != relation.Endpoint {
		signer, e := p.control.NewPublicIngressSigner(relation.ID)
		var next *publicproxy.Handler
		if e == nil {
			next, e = publicproxy.New(publicproxy.Config{MasterOrigin: relation.Endpoint, PublicOrigin: ingress.PublicOrigin, MasterEdge: true, RecordingControlsReady: p.recordingControlsReady, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: signer, TrustedProxyNetworks: p.trusted}})
		}
		if e != nil {
			return nil, e
		}
		if p.proxy != nil {
			p.proxy.CloseIdleConnections()
		}
		p.proxy, p.ingress, p.relationship, p.master = next, ingress, relation.ID, relation.Endpoint
	}
	return p.proxy, nil
}
