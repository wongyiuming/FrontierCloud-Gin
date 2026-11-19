//go:build linux && ledger_fixture

package business

import (
	"context"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// FixtureRecordingAudioAdmission is available only in isolated ledger
// fixtures. It intentionally does not prove a real Karaoke session.
type FixtureRecordingAudioAdmission struct {
	UserID, RecordingID, MemberID string
	Digest, Binding, Title        string
	ContentType                   string
	Encryption                    mediacrypto.Metadata
}

// FixtureRecordingAudioBlob exposes the encrypted intent's blob identifier
// only to an isolated ledger fixture after admission.
func FixtureRecordingAudioBlob(ctx context.Context, repo *Repository, key []byte, recordingID string) (string, error) {
	intent, _, _, found, err := repo.readRecordingAudioIntentTx(ctx, repo.db, key, recordingID)
	if err != nil || !found {
		return "", store.ErrRecordingState
	}
	return intent.BlobID, nil
}

func FixtureStageRecordingAudioDeletion(ctx context.Context, runtime *SelectedUploadRuntime, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string) (bool, error) {
	return runtime.stageRecordingAudioDeletion(ctx, tree, expected, user, browser, recordingID, store.KaraokeAudit{}, func(context.Context) error { return nil })
}

func FixtureFinishRecordingAudioDeletion(ctx context.Context, runtime *SelectedUploadRuntime, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	return runtime.finishRecordingAudioDeletion(ctx, tree, expected, user, browser, recordingID, receipt, signature, store.KaraokeAudit{}, func(context.Context) error { return nil })
}

func FixtureRecordingAudioCleanupClaim(ctx context.Context, repo *Repository, tree *sealedtree.SQLStore, key []byte, recordingID string) (protocol.SelectedStorageUpload, error) {
	var claim protocol.SelectedStorageUpload
	err := repo.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		intent, _, _, found, e := repo.readRecordingAudioIntentTx(c, q, key, recordingID)
		if e != nil || !found || intent.State != "deleting" || mutation.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		claim, e = repo.recordingAudioCleanupClaimTx(c, q, key, intent)
		return e
	})
	return claim, err
}

// FixtureInterruptRecordingAudioLocal simulates loss of authorization after
// the Owner has published bytes but before Master finalization. It is not a
// process-crash test and cannot be included in normal builds.
func FixtureInterruptRecordingAudioLocal(ctx context.Context, repo *Repository, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, gate SelectedUploadRuntimeGate, owner SelectedLocalOwner, userID, recordingID string, deadline selectedupload.ReadDeadline, body io.ReadCloser) error {
	calls := 0
	_, err := repo.uploadRecordingAudioLocal(ctx, tree, key, nodeVault, gate, owner, userID, recordingID, "upload", deadline, body, store.KaraokeAudit{}, func(_ context.Context, _ queryer, intent recordingAudioIntent) error {
		calls++
		if intent.UserID != userID || calls >= 4 {
			return errors.New("fixture authorization interrupted")
		}
		return nil
	})
	if err == nil || calls != 4 {
		return store.ErrRecordingState
	}
	return nil
}

func FixtureReserveRecordingAudio(ctx context.Context, repo *Repository, tree *sealedtree.SQLStore, key []byte, in FixtureRecordingAudioAdmission, localFree int64) (string, error) {
	req := recordingAudioAdmission{UserID: in.UserID, RecordingID: in.RecordingID, MemberID: in.MemberID, Digest: in.Digest, Binding: in.Binding, Title: in.Title, ContentType: in.ContentType, Encryption: in.Encryption}
	intent, prior, err := repo.reserveRecordingAudioCoordinated(ctx, tree, key, req, localFree, store.KaraokeAudit{}, func(context.Context, queryer, recordingAudioAdmission) error { return nil })
	if err != nil || prior {
		return "", store.ErrRecordingState
	}
	return intent.BlobID, nil
}

func FixtureUploadRecordingAudioLocal(ctx context.Context, repo *Repository, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, gate SelectedUploadRuntimeGate, owner SelectedLocalOwner, userID, recordingID, action string, deadline selectedupload.ReadDeadline, body io.ReadCloser) (bool, error) {
	return repo.uploadRecordingAudioLocal(ctx, tree, key, nodeVault, gate, owner, userID, recordingID, action, deadline, body, store.KaraokeAudit{}, func(_ context.Context, _ queryer, intent recordingAudioIntent) error {
		if intent.UserID != userID {
			return store.ErrRecordingState
		}
		return nil
	})
}
