//go:build linux

package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestRecoveryOpaqueSessionExclusiveOwnerMediaAndRecording(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	owner := db.Nodes().(recoveryOwnerFixtureRepo)
	recoveryProofOwnerFence(t, root, svc, owner)
	media, mediaFile := recoveryProofPlacement(t, root, svc.identity.ID)
	recording := media
	recording.Kind = "recording"
	recording.ObjectID = strings.Repeat("d", 32)
	recording.BlobID = strings.Repeat("e", 64)
	recording.ReadAlias = strings.Repeat("f", 64)
	recording.AliasRevision, _ = protocol.OpaquePlacementRevisionFromDescriptor(recording.ReadAlias, recording.BlobID, recording.NativeSHA256, recording.Descriptor, recording.Bytes)
	name, err := sealedtree.BlobPath(recording.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(mediaFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	var releases int
	prepare := func(context.Context) (RecoveryOpaqueSessionPlan, error) {
		return RecoveryOpaqueSessionPlan{Items: []RecoveryOpaqueSessionItem{{Placement: recording}, {Placement: media}}, Check: func(context.Context) error { return nil }, Release: func() { releases++ }}, nil
	}
	err = svc.VisitRecoveryOpaqueSession(ctx, svc.identity.ID, prepare, func(result RecoveryOpaqueSessionResult) error {
		if result.Objects != 2 || len(result.CensusCommitment) != 64 || len(result.ProofCommitment) != 64 {
			t.Fatal("bad result", result)
		}
		wait, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		competing, e := owner.AcquireOwnerControlShared(wait)
		if e == nil {
			competing.Release()
			return errors.New("exclusive Owner fence absent")
		}
		return nil
	})
	if err != nil || releases != 1 {
		t.Fatal("valid session", err, releases)
	}
	stage := filepath.Join(root, "staging")
	if err = os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(stage, "pending.part"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueSession(ctx, svc.identity.ID, prepare, func(RecoveryOpaqueSessionResult) error { t.Fatal("pending stage admitted"); return nil }); err == nil {
		t.Fatal("staging not checked")
	}
	if err = os.Remove(filepath.Join(stage, "pending.part")); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueSession(ctx, svc.identity.ID, prepare, func(RecoveryOpaqueSessionResult) error {
		return os.WriteFile(filepath.Join(stage, "late.part"), []byte("pending"), 0600)
	}); err == nil {
		t.Fatal("late stage accepted")
	}
}
