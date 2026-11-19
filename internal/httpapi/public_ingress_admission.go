package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

// Catalog responses can contain resource handles. Bound both the size and the
// number of responses awaiting an ingress lease commit, independently of key
// requests. A failed commit must never publish the buffered handles.
const maxLocalCatalogResponse = 8 << 20

var localCatalogAdmissions = make(chan struct{}, 4)

func (p *Public) catalogIngressAdmission() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, preflight := c.Request.Context().Value(opaqueCatalogPreflightKey{}).(*opaqueCatalogPreflight); preflight {
			if _, local := network.LocalCatalogPreflightFromContext(c.Request.Context()); local {
				c.Next()
				return
			}
		}
		if _, proxied := network.AuthenticatedIngressFromContext(c.Request.Context()); proxied {
			// The peer verifier owns the lease and admission. Inform it if Gin
			// recovers a panic inside the wrapped handler.
			defer func() {
				if recovered := recover(); recovered != nil {
					network.AbortPublicAdmission(c.Request.Context())
					panic(recovered)
				}
			}()
			c.Next()
			return
		}
		if p.localCatalogPreparer != nil && (c.Request.URL.Path == "/api/v1/media/catalog/media" || c.Request.URL.Path == "/api/v1/media/catalog/categories" || c.Request.URL.Path == "/api/v1/media/catalog/artwork") {
			p.serveLocalOpaqueCatalog(c)
			c.Abort()
			return
		}
		identity, err := p.media.IdentityState(c.Request.Context())
		if err != nil {
			internalError(c, err)
			c.Abort()
			return
		}
		if identity.Role != "Master" {
			c.Next()
			return
		}
		noStore(c)
		select {
		case localCatalogAdmissions <- struct{}{}:
			defer func() { <-localCatalogAdmissions }()
		case <-c.Request.Context().Done():
			detail(c, http.StatusServiceUnavailable, "入口授权不可用")
			c.Abort()
			return
		default:
			detail(c, http.StatusServiceUnavailable, "入口授权不可用")
			c.Abort()
			return
		}
		if p.control == nil {
			detail(c, http.StatusServiceUnavailable, "入口授权不可用")
			c.Abort()
			return
		}
		ingress, lease, err := p.control.AcquireCurrentIngress(c.Request.Context())
		if err != nil || ingress.NodeID != identity.ID {
			if lease != nil {
				lease.Release()
			}
			detail(c, http.StatusServiceUnavailable, "入口授权不可用")
			c.Abort()
			return
		}
		servePublicWithIngressLease(c, ingress, lease, false, maxLocalCatalogResponse)
	}
}
