//go:build linux

package httpapi

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ConfigureSealedRecordingDelete binds the already installed Local reader and
// selected upload runtime to the same actual Owner and media volume.
func (a *Admin) ConfigureSealedRecordingDelete(accounts *KaraokeAccounts, owner *node.SelectedLocalReceiver) error {
	if a == nil || a.identity == nil || accounts == nil || accounts.public != a.public || a.public == nil ||
		a.public.media == nil || a.selectedUpload == nil || accounts.recordingAudioOpen == nil || accounts.recordingAudioDelete != nil || owner == nil ||
		!a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin) {
		return store.ErrNodeState
	}
	accounts.recordingAudioDelete = func(ctx context.Context, tree *sealedtree.SQLStore, ingress store.PublicIngress, user store.KaraokeUser, browser, id string, deadline selectedupload.ReadDeadline, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
		if ingress.PublicOrigin != a.settings.PublicOrigin || ingress.NodeID != a.identity.ID {
			return false, store.ErrNodeState
		}
		return a.selectedUpload.DeleteRecordingAudioLocal(ctx, tree, ingress, user, browser, id, owner, a.public.media, deadline, audit, checkAccount)
	}
	return nil
}
