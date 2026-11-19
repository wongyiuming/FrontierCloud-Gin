package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type recordingAudioDelete func(context.Context, *sealedtree.SQLStore, store.PublicIngress, store.KaraokeUser, string, string, selectedupload.ReadDeadline, store.KaraokeAudit, func(context.Context) error) (bool, error)

func (a *KaraokeAccounts) deleteRecordingAudio(c *gin.Context, user *store.KaraokeUser, audit store.KaraokeAudit, pending bool) {
	p := a.public
	if p.opaqueTree == nil || a.recordingAudioDirect == nil && (a.recordingAudioDelete == nil || pending) {
		detail(c, http.StatusServiceUnavailable, "录音清理暂不可用")
		return
	}
	ingress, ok := p.recordingAudioIngress(c)
	if !ok {
		return
	}
	id := c.Param("recording")
	if !node.ValidIdentifier(id) || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0 {
		invalid(c, "body", "recording_audio")
		return
	}
	sessions := c.Request.Header.Values("X-Fc-Recording-Session")
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil || len(sessions) != 1 || !node.ValidIdentifier(sessions[0]) {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, sessions[0])
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	checkAccount := a.recordingAccountCheck(c, user, true)
	if a.recordingAudioDirect != nil {
		send := func(ctx context.Context, ownerOrigin, capability string) (protocol.OpaqueCapacityReceipt, string, error) {
			return p.control.CleanupDirectRecording(ctx, ownerOrigin, ingress.Origin, capability)
		}
		if pending {
			_, err = a.recordingAudioDirect.CancelRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, id, audit, checkAccount, send)
		} else {
			_, err = a.recordingAudioDirect.DeleteRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, id, audit, checkAccount, send)
		}
		if pending || !errors.Is(err, business.ErrRecordingNotDirect) || a.recordingAudioDelete == nil {
			if err != nil {
				recordingError(c, err)
				return
			}
			status := "deleted"
			if pending {
				status = "cancelled"
			}
			c.JSON(http.StatusOK, gin.H{"recording_id": id, "status": status})
			return
		}
	}
	if _, err = a.recordingAudioDelete(ctx, p.opaqueTree, expected, *user, browser, id, http.NewResponseController(c.Writer), audit, checkAccount); err != nil {
		recordingError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recording_id": id, "status": "deleted"})
}
