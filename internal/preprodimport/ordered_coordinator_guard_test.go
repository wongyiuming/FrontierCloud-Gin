package preprodimport

import (
	"context"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// These entry points have no production registration. They must reject
// immediately, before accessing a repository, until their locking is rebuilt.
func TestUnorderedImportCoordinatorsRemainClosed(t *testing.T) {
	ctx := context.Background()
	_, err := authorizeOwnerPublish(ctx, nil, nil, nil, nil, nil, nil, completeSnapshot{}, snapshotPlanTrust{}, signedSnapshotPlan{}, nil, nil, nil, nil, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "requires ordered lock") {
		t.Fatal("owner publisher must reject before acquiring ingress", err)
	}
	_, err = observePlainOrLyric(ctx, nil, nil, nil, nil, nil, nil, store.EncryptedMediaSourceSnapshot{}, store.EncryptedMediaSourceSnapshot{}, "", completeSnapshot{}, "", objectProofScope{})
	if err == nil || !strings.Contains(err.Error(), "requires ordered locks") {
		t.Fatal("plain observer must reject before acquiring ingress", err)
	}
	_, err = observeLegacyObject(ctx, nil, nil, nil, nil, nil, nil, store.EncryptedMediaSourceSnapshot{}, nil, "", completeSnapshot{}, keyScope{}, nil, "", "")
	if err == nil || !strings.Contains(err.Error(), "requires ordered locks") {
		t.Fatal("legacy observer must reject before acquiring ingress", err)
	}
}
