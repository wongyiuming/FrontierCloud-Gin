//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedS3FinalizeRequiresGuardAndRetainsDirectoryAffinity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, tree, _, _, _ := fencedFixture(t)
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	category := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "album"}
	for _, dir := range []Entry{music, category} {
		if err := tree.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	entry := Entry{ParentID: category.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "audio", Name: "private.mp3"}
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	native := fixturePlacement(t, entry.ObjectID)
	native.Bytes, native.Encryption, native.BlobID, native.ReadAlias = meta.CiphertextSize, &meta, "", ""
	admission := &SelectedUploadFact{UploadID: strings.Repeat("4", 32), AdminBinding: strings.Repeat("5", 64), Policy: "S3", Revision: 1}
	var prepared PreparedFile
	err = tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		prepared, e = m.PrepareFileTx(ctx, tx, entry, native, Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: admission})
		if e != nil {
			return e
		}
		return tx.Commit()
	})
	if err != nil {
		t.Fatal("prepare", err)
	}
	s3 := fixtureS3Placement()
	s3.ObjectID, s3.MemberID, s3.ObjectRevision, s3.Encryption = entry.ObjectID, native.OwnerID, 1, &meta
	s3.Proof.MediaID, s3.Proof.ObjectID, s3.Proof.MemberID, s3.Proof.SessionID = entry.ObjectID, entry.ObjectID, native.OwnerID, admission.UploadID
	s3.Proof.MetadataFormat, s3.Proof.MetadataOwner = store.S3OpaqueMetadata, strings.Repeat("6", 64)
	s3.Proof.Key = "objects/" + prepared.BlobID[:2] + "/" + prepared.BlobID[2:4] + "/" + prepared.BlobID + ".blob"
	s3.Proof.Bytes = meta.CiphertextSize
	denied := errors.New("provider proof refused")
	finalize := func(check func(context.Context, SelectedPending, S3Placement) error) error {
		return tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			if e = m.FinalizeSelectedS3Tx(ctx, tx, prepared.OperationID, s3, check); e != nil {
				return e
			}
			return tx.Commit()
		})
	}
	if err = finalize(func(context.Context, SelectedPending, S3Placement) error { return denied }); !errors.Is(err, denied) {
		t.Fatal("guard", err)
	}
	var n int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_pending_files WHERE operation_id=?`, prepared.OperationID).Scan(&n); err != nil || n != 1 {
		t.Fatal("guard did not roll back", n, err)
	}
	if err = finalize(func(context.Context, SelectedPending, S3Placement) error { return nil }); err != nil {
		t.Fatal("finalize", err)
	}
	if _, err = tree.Check(ctx); err != nil {
		t.Fatal("tree consistency", err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := tree.ReadS3ListingObjectWithLease(ctx, lease, entry.ObjectID, false)
	lease.Release()
	if err != nil || view.Placement.Proof.Key != s3.Proof.Key || view.Placement.Encryption == nil || *view.Placement.Encryption != meta {
		t.Fatal("S3 placement", err)
	}
	if _, err = tree.PreflightCategoryAndOwner(ctx, category.ObjectID, native.OwnerID); err != nil {
		t.Fatal("same member affinity", err)
	}
	if _, err = tree.PreflightCategoryAndOwner(ctx, category.ObjectID, strings.Repeat("7", 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("different member accepted", err)
	}
	t.Run("admin deletion dispatch binds file and operation", func(t *testing.T) {
		target := store.SelectedMediaDeleteTarget{Path: "music/album/private.mp3", ResourceID: entry.ObjectID}
		check := func(target store.SelectedMediaDeleteTarget, want MediaDeletionBackend) {
			t.Helper()
			err := tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
				tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
				if err != nil {
					return err
				}
				defer tx.Rollback()
				got, err := m.ClassifyMediaDeletionTx(ctx, tx, target)
				if got != want || (err != nil) != (want == "") {
					t.Fatalf("dispatch = %q, %v, want %q", got, err, want)
				}
				return tx.Commit()
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		check(target, MediaDeletionS3)
		wrongPath := target
		wrongPath.Path = "music/album/different.mp3"
		check(wrongPath, "")
		directory := store.SelectedMediaDeleteTarget{Path: "music/album", ResourceID: category.ObjectID}
		check(directory, "")
		wrongOperation := target
		wrongOperation.OperationID = strings.Repeat("8", 32)
		check(wrongOperation, "")
		checkAdminPending := func(wantOperation string) {
			t.Helper()
			lease, err := tree.AcquireReadFence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			items, cursor, err := tree.ListAdminPendingDeletionsWithLease(ctx, lease, category.ObjectID, "", 2)
			if err != nil || cursor != "" {
				t.Fatal("Admin pending listing", cursor, err)
			}
			if wantOperation == "" {
				if len(items) != 0 {
					t.Fatal("Admin listed a nonpending file as pending")
				}
				return
			}
			if len(items) != 1 || items[0].Entry != entry || items[0].S3Placement == nil || items[0].Facts.S3Deletion == nil || items[0].Facts.S3Deletion.OperationID != wantOperation {
				t.Fatal("Admin lost the exact pending S3 operation")
			}
			public, _, err := tree.ListCatalogPageWithLease(ctx, lease, category.ObjectID, "", 2, true)
			if err != nil || len(public) != 0 {
				t.Fatal("ordinary catalog exposed a pending S3 file", err)
			}
		}
		checkAdminPending("")

		update := func(fn func(*CoordinatedMutation, *sql.Tx, S3MediaDeletionTarget) error) {
			t.Helper()
			if err := tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				view, err := m.ReadS3MediaDeletionTx(ctx, tx, target.ResourceID)
				if err != nil {
					return err
				}
				if err = fn(m, tx, view); err != nil {
					return err
				}
				return tx.Commit()
			}); err != nil {
				t.Fatal(err)
			}
		}
		update(func(m *CoordinatedMutation, tx *sql.Tx, view S3MediaDeletionTarget) error {
			intent, err := m.QueueS3MediaDeletionTx(ctx, tx, view)
			target.OperationID = intent.OperationID
			return err
		})
		check(target, MediaDeletionS3)
		check(wrongOperation, "")
		checkAdminPending(target.OperationID)
		update(func(m *CoordinatedMutation, tx *sql.Tx, view S3MediaDeletionTarget) error {
			return m.FinalizeS3MediaDeletionTx(ctx, tx, view)
		})
		check(target, MediaDeletionS3)
		checkAdminPending("")
		wrongPath.OperationID = target.OperationID
		check(wrongPath, "")
		check(wrongOperation, "")
		target.OperationID = ""
		check(target, "")
	})
}
