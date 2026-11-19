package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaqueCatalogPreflightKey struct{}
type opaqueCatalogPreflight struct {
	resolve     media.CatalogOwnerResolver
	verifyFacts media.CatalogFactsVerifier
	check       func(context.Context, store.IngressPrerequisite) error
	release     func()
}

// serveLocalOpaqueCatalog performs the same private preparation on Master
// itself. Origin validation precedes precomputation; final admission acquires
// Owner, ingress, then tree and rechecks scope before exposing the buffered JSON.
func (p *Public) serveLocalOpaqueCatalog(c *gin.Context) {
	noStore(c)
	if p.control == nil || p.localCatalogPreparer == nil || c.Request.Method != http.MethodGet {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	select {
	case localCatalogAdmissions <- struct{}{}:
		defer func() { <-localCatalogAdmissions }()
	default:
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()
	resolver, err := network.New(p.settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	client := resolver.Resolve(c.Request)
	if c.Request.TLS == nil && !(client.FromTrustedProxy && resolver.SecureAdmin(c.Request)) {
		detail(c, http.StatusForbidden, "Forbidden")
		return
	}
	identity, err := p.media.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		detail(c, http.StatusForbidden, "Forbidden")
		return
	}
	initial, lease, err := p.control.AcquireCurrentIngress(ctx)
	if err != nil || lease == nil {
		if lease != nil {
			lease.Release()
		}
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	lease.Release()
	origin, err := url.Parse(initial.PublicOrigin)
	if err != nil || origin.Scheme != "https" || !strings.EqualFold(c.Request.Host, origin.Host) || initial.NodeID != identity.ID {
		detail(c, http.StatusForbidden, "Forbidden")
		return
	}
	local, err := network.WithLocalCatalogPreflight(ctx, network.LocalPublicIngress{NodeID: initial.NodeID, Generation: initial.Generation, PublicOrigin: initial.PublicOrigin})
	if err != nil {
		detail(c, http.StatusForbidden, "Forbidden")
		return
	}
	prepared, err := p.localCatalogPreparer.PrepareCatalog(c.Request.WithContext(local))
	defer clear(prepared.Body)
	var release func()
	if prepared.Release != nil {
		release = sync.OnceFunc(prepared.Release)
		defer release()
	}
	if err != nil || prepared.CheckScope == nil || prepared.Release == nil || len(prepared.Body) == 0 || len(prepared.Body) > maxLocalCatalogResponse || ctx.Err() != nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	body := bytes.Clone(prepared.Body)
	defer clear(body)
	if !json.Valid(body) {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	current, final, err := p.control.AcquireLocalCatalogIngress(ctx, initial, prepared.CheckScope)
	if err != nil || final == nil {
		if final != nil {
			final.Release()
		}
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	defer final.Release()
	if current != initial || ctx.Err() != nil || final.Commit() != nil || ctx.Err() != nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	release()
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}

type boundedCatalogWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
	failed bool
}

func (w *boundedCatalogWriter) Header() http.Header { return w.header }
func (w *boundedCatalogWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}
func (w *boundedCatalogWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(p) > (8<<20)-w.body.Len() {
		w.failed = true
		return 0, errors.New("catalog response exceeds limit")
	}
	return w.body.Write(p)
}

// OpaqueCatalogPreparer uses the real Gin catalog handler in a private,
// bounded pre-admission context. It must remain uninstalled until the complete
// encrypted tree, category/S3 paths, member fences and recovery are ready.
type OpaqueCatalogPreparer struct {
	Router      http.Handler
	Resolve     media.CatalogOwnerResolver
	VerifyFacts media.CatalogFactsVerifier
}

func (p *OpaqueCatalogPreparer) PrepareCatalog(req *http.Request) (publicproxy.PreparedCatalog, error) {
	if p == nil || p.Router == nil || p.Resolve == nil || p.VerifyFacts == nil || req == nil || req.Context().Err() != nil {
		return publicproxy.PreparedCatalog{}, errors.New("catalog unavailable")
	}
	preflight := &opaqueCatalogPreflight{resolve: p.Resolve, verifyFacts: p.VerifyFacts}
	transferred := false
	defer func() {
		if !transferred && preflight.release != nil {
			preflight.release()
		}
	}()
	ctx := context.WithValue(req.Context(), opaqueCatalogPreflightKey{}, preflight)
	w := &boundedCatalogWriter{header: make(http.Header)}
	p.Router.ServeHTTP(w, req.WithContext(ctx))
	if w.failed || w.status != http.StatusOK || preflight.check == nil || preflight.release == nil || req.Context().Err() != nil {
		return publicproxy.PreparedCatalog{}, errors.New("catalog unavailable")
	}
	transferred = true
	return publicproxy.PreparedCatalog{Body: w.body.Bytes(), CheckScope: preflight.check, Release: preflight.release}, nil
}

func (p *Public) prepareOpaqueCatalog(c *gin.Context, preflight *opaqueCatalogPreflight) {
	if p.opaqueTree == nil || preflight == nil || preflight.resolve == nil || preflight.check != nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	kind, ok := kindQuery(c)
	if !ok {
		return
	}
	name, ok := queryText(c, "path", 1024)
	if !ok {
		return
	}
	if _, ok := queryText(c, "playback_session_id", 64); !ok {
		return
	}
	include, ok := queryBool(c, "include_hidden")
	if !ok {
		return
	}
	items, fence, err := p.media.PrepareOpaqueTreeCatalog(c.Request.Context(), p.opaqueTree, kind, name, include, preflight.resolve, preflight.verifyFacts)
	if err != nil || fence == nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	preflight.check, preflight.release = fence.Check, fence.Release
	c.JSON(http.StatusOK, gin.H{"entries": items})
}

func (p *Public) prepareOpaqueCategories(c *gin.Context, preflight *opaqueCatalogPreflight) {
	if p.opaqueTree == nil || preflight == nil || preflight.check != nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	kind, ok := kindQuery(c)
	if !ok {
		return
	}
	include, ok := queryBool(c, "include_hidden")
	if !ok {
		return
	}
	var items []media.Category
	var fence *media.PreparedCatalogFence
	var err error
	if _, hasPath := c.GetQuery("path"); hasPath {
		name, ok := queryText(c, "path", 1024)
		if !ok {
			return
		}
		items, fence, err = p.media.PrepareOpaqueTreeSubcategories(c.Request.Context(), p.opaqueTree, kind, name, include, preflight.resolve)
	} else {
		items, fence, err = p.media.PrepareOpaqueTreeCategories(c.Request.Context(), p.opaqueTree, kind, include, preflight.resolve)
	}
	if err != nil || fence == nil {
		detail(c, http.StatusServiceUnavailable, "Media catalog temporarily unavailable")
		return
	}
	preflight.check, preflight.release = fence.Check, fence.Release
	c.JSON(http.StatusOK, gin.H{"entries": p.media.CategoryArtwork(c.Request.Context(), kind, items, include)})
}

// Nested selection mirrors the legacy seven-subdirectory/eight-track budget.
// The combined fence remains experimental until all configuration/source
// writers use a proven compatible lock order and source evidence is complete.
func (p *Public) prepareOpaqueArtwork(c *gin.Context, preflight *opaqueCatalogPreflight) {
	if p.opaqueTree == nil || preflight == nil || preflight.resolve == nil || preflight.verifyFacts == nil || preflight.check != nil {
		detail(c, http.StatusServiceUnavailable, "Music artwork temporarily unavailable")
		return
	}
	name, ok := queryText(c, "path", 1024)
	if !ok {
		return
	}
	include, ok := queryBool(c, "include_hidden")
	if !ok {
		return
	}
	var fences []*media.PreparedCatalogFence
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			for i := len(fences) - 1; i >= 0; i-- {
				fences[i].Release()
			}
		})
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	tracks := make([]media.Track, 0, 8)
	collect := func(directory string) (int, int, error) {
		items, fence, err := p.media.PrepareOpaqueArtworkDirectory(c.Request.Context(), p.opaqueTree, directory, include, preflight.resolve, preflight.verifyFacts)
		if err != nil || fence == nil {
			return 0, 0, errors.New("artwork unavailable")
		}
		fences = append(fences, fence)
		before := len(tracks)
		for _, item := range items {
			if strings.HasSuffix(strings.ToLower(item.MediaPath), ".mp3") {
				tracks = append(tracks, item)
				if len(tracks) == 8 {
					break
				}
			}
		}
		return len(items), len(tracks) - before, nil
	}
	direct, found, err := collect(name)
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Music artwork temporarily unavailable")
		return
	}
	subcount := 0
	if found == 0 && len(strings.Split(name, "/")) == 2 {
		children, fence, e := p.media.PrepareOpaqueTreeSubcategories(c.Request.Context(), p.opaqueTree, "music", name, include, preflight.resolve)
		if e != nil || fence == nil {
			detail(c, http.StatusServiceUnavailable, "Music artwork temporarily unavailable")
			return
		}
		fences = append(fences, fence)
		subcount = len(children)
		for _, child := range children[:min(len(children), 7)] {
			if len(tracks) == 8 {
				break
			}
			if _, _, e = collect(name + "/" + child.Name); e != nil {
				detail(c, http.StatusServiceUnavailable, "Music artwork temporarily unavailable")
				return
			}
		}
	}
	// An empty visible traversal does not yet prove the old global category
	// exists when it contains only hidden objects; never return a false empty.
	if direct == 0 && subcount == 0 && len(tracks) == 0 {
		detail(c, http.StatusServiceUnavailable, "Music artwork temporarily unavailable")
		return
	}
	preflight.check = func(ctx context.Context, lease store.IngressPrerequisite) error {
		for _, fence := range fences {
			if err := fence.Check(ctx, lease); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	preflight.release = release
	transferred = true
	c.JSON(http.StatusOK, media.CategoryArtwork{MetadataTracks: tracks})
}
