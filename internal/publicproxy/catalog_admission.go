package publicproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This hook remains unset in production. Only a trusted, bounded read-only
// implementation may construct it; no public header can install a scope
// callback or mark a request admitted. Body ownership passes to the verifier.
type PreparedCatalog struct {
	Body       []byte
	CheckScope func(context.Context, store.IngressPrerequisite) error
	Release    func()
}
type CatalogPreparer interface {
	PrepareCatalog(*http.Request) (PreparedCatalog, error)
}
type catalogFinalIngress interface {
	AcquireCatalogIngress(context.Context, store.Relationship, store.PublicIngress, func(context.Context, store.IngressPrerequisite) error) (store.PublicIngress, store.PublicIngressLease, error)
}

var catalogPrepareSlot = make(chan struct{}, 1)

func catalogReadPath(path string) bool {
	return path == "/api/v1/media/catalog/categories" || path == "/api/v1/media/catalog/media" || path == "/api/v1/media/catalog/artwork"
}

// servePreparedCatalog never emits a private result until final tree-scope,
// relationship and ingress checks have committed. Authenticate consumes the
// node proof nonce once; the final fence re-reads its relationship instance
// without attempting to consume that nonce again.
func (v *Verifier) servePreparedCatalog(w http.ResponseWriter, r *http.Request, item route, proof []byte, id, public, ip string, gen int64, limit int) {
	ctx := r.Context()
	select {
	case catalogPrepareSlot <- struct{}{}:
		defer func() { <-catalogPrepareSlot }()
	case <-ctx.Done():
		fail(w, http.StatusServiceUnavailable)
		return
	}
	finalizer, ok := v.current.(catalogFinalIngress)
	if !ok || r.Method != http.MethodGet || !catalogReadPath(item.path) || v.catalogPreparer == nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	rel, err := v.auth.Authenticate(ctx, r.Header, http.MethodPost, ProofDomain, proof, false, false)
	if err != nil || rel.PeerID != id || rel.Direction != "downstream" || rel.State != "active" || rel.Protocol != protocol.Version {
		fail(w, http.StatusForbidden)
		return
	}
	expected := store.PublicIngress{NodeID: id, Generation: gen, PublicOrigin: public}
	current, initial, err := v.current.AcquireCurrentIngress(ctx)
	if err != nil || nilValue(initial) {
		if !nilValue(initial) {
			initial.Release()
		}
		fail(w, http.StatusForbidden)
		return
	}
	initial.Release()
	if current != expected || ctx.Err() != nil {
		fail(w, http.StatusForbidden)
		return
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: id, Generation: gen, PublicOrigin: public, ClientIP: ip})
	if err != nil {
		fail(w, http.StatusForbidden)
		return
	}
	clean := r.Clone(verified)
	clean.Header = make(http.Header)
	for _, name := range signedHeaders {
		for _, value := range r.Header.Values(name) {
			clean.Header.Add(name, value)
		}
	}
	prepared, err := v.catalogPreparer.PrepareCatalog(clean)
	defer clear(prepared.Body)
	var release func()
	if prepared.Release != nil {
		release = sync.OnceFunc(prepared.Release)
		defer release()
	}
	if err != nil || ctx.Err() != nil || prepared.CheckScope == nil || prepared.Release == nil || len(prepared.Body) == 0 || len(prepared.Body) > limit {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	privateBody := bytes.Clone(prepared.Body)
	defer clear(privateBody)
	if !json.Valid(privateBody) {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	current, lease, err := finalizer.AcquireCatalogIngress(ctx, rel, expected, prepared.CheckScope)
	if err != nil || nilValue(lease) {
		if !nilValue(lease) {
			lease.Release()
		}
		fail(w, http.StatusForbidden)
		return
	}
	defer lease.Release()
	if current != expected || ctx.Err() != nil || lease.Commit() != nil || ctx.Err() != nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	release()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(privateBody)
}
