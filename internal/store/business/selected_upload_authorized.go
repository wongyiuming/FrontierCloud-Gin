package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// prepareAuthorizedSelected is the real preparation verifier for the private
// coordinator. Its caller must have authenticated the current Admin and passed
// that session's hash, and the tree must already have durably reserved the
// server-issued metadata under the authenticated runtime readiness gate.
// Recovery after process restart is a separate reauthentication flow; it must
// not reuse an expired or previous-manager preparation token.
func (r *Repository) prepareAuthorizedSelected(ctx context.Context, tree *sealedtree.SQLStore, key []byte, crypto *mediacrypto.Manager, sessionHash, preparation string, parentPath []string, entry sealedtree.Entry, placement sealedtree.Placement, facts sealedtree.Facts, free int64, commitments []string, guards ...func(context.Context, queryer, sealedtree.SelectedPending) error) (sealedtree.PreparedFile, bool, error) {
	if crypto == nil || !nodeHashPattern.MatchString(sessionHash) || preparation == "" || len(parentPath) == 0 || placement.Encryption == nil || facts.PendingSelectedUpload == nil || facts.PendingSelectedUpload.AdminBinding != sessionHash {
		return sealedtree.PreparedFile{}, false, store.ErrNodeState
	}
	if err := crypto.VerifyTransientPreparation("admin:"+sessionHash, preparation, *placement.Encryption); err != nil {
		return sealedtree.PreparedFile{}, false, store.ErrNodeState
	}
	parentPath = append([]string(nil), parentPath...)
	var s3Commitments [][]string
	if facts.PendingSelectedUpload.Policy == "S3" {
		s3Commitments = [][]string{append([]string(nil), commitments...)}
	}
	return r.prepareSelectedCoordinated(ctx, tree, key, entry, placement, facts, free, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation, pending sealedtree.SelectedPending) error {
		if err := m.CheckSelectedParentPathTx(c, q, pending.ParentID, parentPath); err != nil {
			return err
		}
		if pending.Admission.AdminBinding != sessionHash || pending.Placement.Encryption == nil || *pending.Placement.Encryption != *placement.Encryption || crypto.VerifyTransientPreparation("admin:"+sessionHash, preparation, *pending.Placement.Encryption) != nil {
			return store.ErrNodeState
		}
		for _, guard := range guards {
			if guard == nil || guard(c, q, pending) != nil {
				return store.ErrNodeState
			}
		}
		return m.ClaimSelectedMediaPreparationTx(c, q, pending.OperationID)
	}, s3Commitments...)
}
