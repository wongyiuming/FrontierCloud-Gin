package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var sealedPlaybackSlots = make(chan struct{}, 2)

func (p *Public) sealedPlayback(c *gin.Context, path, id, session string, played, duration float64) (store.PlaybackResult, error) {
	empty := store.PlaybackResult{}
	canonical, threshold, err := media.ValidatePlaybackReport(session, played, duration)
	if err != nil {
		return empty, err
	}
	select {
	case sealedPlaybackSlots <- struct{}{}:
		defer func() { <-sealedPlaybackSlots }()
	default:
		return empty, media.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	identity, err := p.media.IdentityState(ctx)
	if err != nil {
		return empty, err
	}
	if identity.Role != "Master" || p.control == nil {
		return empty, media.ErrUnavailable
	}
	// Signed requests have already committed ingress admission in the proxy.
	// Commit local admission at the same point and release its tree reader
	// before taking the mutation fence for the counter.
	if _, verified := network.AuthenticatedIngressFromContext(ctx); !verified {
		ingress, lease, err := p.control.AcquireCurrentIngress(ctx)
		if lease != nil {
			defer lease.Release()
		}
		if err != nil || lease == nil || ingress.NodeID != identity.ID || lease.Commit() != nil {
			return empty, media.ErrUnavailable
		}
	}
	result, err := p.opaqueTree.RecordNativePlayback(ctx, path, id, canonical)
	switch {
	case errors.Is(err, sql.ErrNoRows), errors.Is(err, sealedtree.ErrInvalid), errors.Is(err, sealedtree.ErrHidden), errors.Is(err, sealedtree.ErrRevocationPending):
		return empty, os.ErrNotExist
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, sealedtree.ErrFenceRequired):
		return empty, media.ErrUnavailable
	}
	result.Threshold = threshold
	return result, err
}
