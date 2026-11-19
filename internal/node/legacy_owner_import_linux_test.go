//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLegacyOwnerImportUsesPairedSignatureAndSurvivesRetry(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", transport)
	follower, db := testNode(t, "Follower", "https://owner.test", transport)
	transport.nodes["https://master.test"], transport.nodes["https://owner.test"] = master, follower
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	masterRow, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ownerRow, err := follower.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.repo.Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := follower.LegacyReadScope(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	var dbPath string
	if err = db.Database().QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&dbPath); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(dbPath)
	mediaPath := filepath.Join(dir, "media")
	if err = os.MkdirAll(filepath.Join(mediaPath, "music", "album"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(mediaPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(mediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, mediaPath, follower.identity)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fence.Acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := lease.Binding(ctx)
	lease.Release()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("encrypted legacy fixture contents")
	oldPath := "music/album/song.mp3"
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(oldPath)), data, 0600); err != nil {
		t.Fatal(err)
	}
	object := strings.Repeat("6", 64)
	pathHash := sha256.Sum256([]byte(oldPath))
	digest := sha256.Sum256(data)
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?,?,?)`, object, oldPath, hex.EncodeToString(pathHash[:]), "created", "updated"); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	plan := protocol.LegacyOwnerImportPlan{Kind: "legacy-owner-import-v1", MasterID: masterRow.ID, OwnerID: ownerRow.ID, RelationshipID: relationID, RelationshipBinding: scope.RelationshipBinding, OwnerBinding: scope.OwnerBinding, FenceBinding: binding, Generation: strings.Repeat("4", 64), OperationID: strings.Repeat("1", 64), StageID: strings.Repeat("2", 64), BlobID: strings.Repeat("3", 64), SourceID: object, SourcePath: oldPath, Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(data)), Challenge: strings.Repeat("5", 64), ExpiresAt: time.Now().Unix() + 600}
	sign := func(p protocol.LegacyOwnerImportPlan) string {
		t.Helper()
		payload, e := p.Payload()
		if e != nil {
			t.Fatal(e)
		}
		signed, e := master.identity.signed(masterRow, payload)
		if e != nil {
			t.Fatal(e)
		}
		return signed.Signature
	}
	run := func(p protocol.LegacyOwnerImportPlan, signature string) (Envelope, error) {
		return ImportLegacyOwnerOffline(ctx, gate, dir, dbPath, filepath.Join(dir, "secrets"), db.Database(), p, signature)
	}
	if _, err = run(plan, sign(plan)+"bad"); err == nil {
		t.Fatal("bad Master signature accepted")
	}
	if _, err = os.Lstat(filepath.Join(dir, maintenance.OwnerImportHold)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid plan created hold", err)
	}
	receipt, err := run(plan, sign(plan))
	if err != nil {
		t.Fatal("actual import", err)
	}
	if err = protocol.Verify(relation.PublicKey, receipt.Payload, receipt.Signature); err != nil {
		t.Fatal("Owner receipt signature", err)
	}
	enrollment := protocol.LegacyReadEnrollmentReceipt{Kind: "legacy-media-enrollment-v1", Challenge: strings.Repeat("a", 64), MasterID: plan.MasterID, OwnerID: plan.OwnerID, RelationshipID: plan.RelationshipID, RelationshipBinding: plan.RelationshipBinding, OwnerBinding: plan.OwnerBinding, FenceBinding: plan.FenceBinding, State: "active"}
	enrollmentPayload, err := enrollment.Payload()
	if err != nil {
		t.Fatal(err)
	}
	ownerRelation, err := follower.repo.Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentSigned, err := follower.signOpaqueOwnerReceipt(ctx, ownerRelation, plan.MasterID, plan.OwnerID, relationID, enrollmentPayload)
	if err != nil {
		t.Fatal(err)
	}
	masterBinding := opaqueRelationshipBinding(relation)
	if err = master.VerifyLegacyOwnerImportReceipt(ctx, plan, enrollment, enrollmentSigned, receipt, masterBinding); err != nil {
		t.Fatal("Master rejected real Owner receipt", err)
	}
	wrongPlan := plan
	wrongPlan.SourceID = strings.Repeat("b", 64)
	if err = master.VerifyLegacyOwnerImportReceipt(ctx, wrongPlan, enrollment, enrollmentSigned, receipt, masterBinding); err == nil {
		t.Fatal("receipt accepted for another source")
	}
	wrongEnrollment := enrollment
	wrongEnrollment.FenceBinding = strings.Repeat("c", 64)
	if err = master.VerifyLegacyOwnerImportReceipt(ctx, plan, wrongEnrollment, enrollmentSigned, receipt, masterBinding); err == nil {
		t.Fatal("receipt accepted against another Owner fence")
	}
	if err = master.VerifyLegacyOwnerImportReceipt(ctx, plan, enrollment, enrollmentSigned, receipt, strings.Repeat("d", 64)); err == nil {
		t.Fatal("receipt accepted against another Master relationship")
	}
	if receipt.Payload["operation_id"] != plan.OperationID || receipt.Payload["digest"] != plan.Digest || receipt.Payload["fence_binding"] != binding {
		t.Fatal("receipt scope mismatch")
	}
	newPath, err := sealedtree.BlobPath(plan.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	newData, err := root.ReadFile(newPath)
	if err != nil || !bytes.Equal(newData, data) {
		t.Fatal("published bytes", err)
	}
	oldData, err := root.ReadFile(oldPath)
	if err != nil || !bytes.Equal(oldData, data) {
		t.Fatal("original source changed", err)
	}
	if err = gate.Resume(ctx, func(context.Context) error { return nil }); !errors.Is(err, maintenance.ErrState) {
		t.Fatal("unfinished Owner import resumed", err)
	}
	plan.Challenge = strings.Repeat("7", 64)
	plan.ExpiresAt = time.Now().Unix() + 700
	if _, err = run(plan, sign(plan)); err != nil {
		t.Fatal("new signed challenge did not recover", err)
	}
	changed := plan
	changed.BlobID = strings.Repeat("8", 64)
	if _, err = run(changed, sign(changed)); err == nil {
		t.Fatal("same operation adopted another blob")
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(oldPath)), bytes.Repeat([]byte{1}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = run(plan, sign(plan)); err == nil {
		t.Fatal("changed original accepted on replay")
	}
	if err = os.WriteFile(filepath.Join(mediaPath, filepath.FromSlash(oldPath)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = run(plan, sign(plan)); err != nil {
		t.Fatal("retry after source repair", err)
	}
	sourceFile := filepath.Join(mediaPath, filepath.FromSlash(oldPath))
	if err = os.Rename(sourceFile, sourceFile+".saved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(sourceFile)+".saved", sourceFile); err != nil {
		t.Fatal(err)
	}
	if _, err = run(plan, sign(plan)); err == nil {
		t.Fatal("source symlink accepted")
	}
	if err = os.Remove(sourceFile); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(sourceFile+".saved", sourceFile); err != nil {
		t.Fatal(err)
	}
	targetFile := filepath.Join(mediaPath, filepath.FromSlash(newPath))
	if err = os.Rename(targetFile, targetFile+".saved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(targetFile)+".saved", targetFile); err != nil {
		t.Fatal(err)
	}
	if _, err = run(plan, sign(plan)); err == nil {
		t.Fatal("target symlink accepted")
	}
	if err = os.Remove(targetFile); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(targetFile+".saved", targetFile); err != nil {
		t.Fatal(err)
	}
	if _, err = run(plan, sign(plan)); err != nil {
		t.Fatal("recovery after target rejection", err)
	}
}
