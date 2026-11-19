package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type localFollowerRelayAdmissionKey struct{}
type localFollowerRelayAdmission struct {
	lease     store.PublicIngressLease
	admission *network.PublicAdmission
}

func (p *Public) localFollowerRelayReady(ctx context.Context) bool {
	local, ok := network.LocalPublicIngressFromContext(ctx)
	return ok && p != nil && p.localFollowerRelay != nil && p.localFollowerRelay.tree == p.opaqueTree && p.localFollowerRelay.media == p.media && p.localFollowerRelay.control == p.control && p.localFollowerRelay.origin == local.PublicOrigin
}

// RegisterOpaqueLocalFollowerRelay is fixture-only until tree, policies and
// lifecycle readiness are complete. The active ingress is the Master itself;
// its local admission is not represented as an authenticated peer.
func RegisterOpaqueLocalFollowerRelay(router *gin.Engine, settings config.Config, origin string, service *media.Service, control *node.Service, sessions *mediacrypto.Manager, tree *sealedtree.SQLStore) (*OpaqueFollowerRelay, error) {
	if router == nil || service == nil || control == nil || sessions == nil || tree == nil || !settings.TLSEnabled || node.ValidateMasterResourceOrigin(origin) != nil {
		return nil, errors.New("invalid Master-local follower relay configuration")
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	edge, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	h := &OpaqueFollowerRelay{origin: origin, media: service, control: control, sessions: sessions, tree: tree, reads: make(chan struct{}, 4)}
	serve := func(c *gin.Context) {
		noStore(c)
		identity := edge.Resolve(c.Request)
		if !strings.EqualFold(c.Request.Host, parsed.Host) || c.Request.TLS == nil && !(identity.FromTrustedProxy && edge.SecureAdmin(c.Request)) {
			detail(c, http.StatusForbidden, "Resource access unavailable")
			return
		}
		if _, peer := network.AuthenticatedIngressFromContext(c.Request.Context()); peer {
			detail(c, http.StatusForbidden, "Resource access unavailable")
			return
		}
		current, lease, err := control.AcquireCurrentIngress(c.Request.Context())
		if err != nil || lease == nil {
			if lease != nil {
				lease.Release()
			}
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		defer lease.Release()
		master, err := control.IdentityState(c.Request.Context())
		if err != nil || master.Role != "Master" || current.NodeID != master.ID || current.PublicOrigin != origin {
			detail(c, http.StatusForbidden, "Resource access unavailable")
			return
		}
		ctx, err := store.BindIngressPrerequisite(c.Request.Context(), lease)
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		ctx, admission := network.WithPublicAdmission(ctx)
		defer admission.Abort()
		ctx, err = network.WithLocalPublicIngress(ctx, network.LocalPublicIngress{NodeID: current.NodeID, Generation: current.Generation, PublicOrigin: current.PublicOrigin})
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		ctx = context.WithValue(ctx, localFollowerRelayAdmissionKey{}, &localFollowerRelayAdmission{lease: lease, admission: admission})
		c.Request = c.Request.WithContext(ctx)
		h.serve(c)
	}
	router.GET("/api/v1/media/opaque-local-follower-relay/:resource", serve)
	router.HEAD("/api/v1/media/opaque-local-follower-relay/:resource", serve)
	return h, nil
}
