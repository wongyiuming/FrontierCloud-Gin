//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestDirectoryDeletionFencesUploadsAndWaitsForExactLeafSettlement(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	for _, stmt := range []string{
		`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT,created_at INTEGER)`,
		`INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master','sealed-fixture',1)`,
		`CREATE TABLE cluster_storage_members(member_id TEXT,member_kind TEXT,transport TEXT,relationship_id TEXT,used_bytes INTEGER)`,
		`INSERT INTO cluster_storage_members VALUES('ffffffffffffffffffffffffffffffff','MasterLocal','Local',NULL,1000)`,
		`CREATE TABLE IF NOT EXISTS sealed_tree_owner_fence(singleton INTEGER PRIMARY KEY,fence_tag TEXT)`,
		`INSERT INTO sealed_tree_owner_fence VALUES(1,'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "album"}
	disc := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "hidden-disc"}
	empty := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "directory", Name: "empty"}
	sibling := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "directory", Name: "sibling"}
	create := func(entry Entry) error {
		facts := Facts{ObjectID: entry.ObjectID}
		if entry == disc {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "fixture"}
		}
		return tree.CreateDirectoryWithFacts(ctx, entry, facts)
	}
	for _, entry := range []Entry{music, album, disc, empty, sibling} {
		if err := create(entry); err != nil {
			t.Fatal(err)
		}
	}
	song := Entry{ParentID: disc.ObjectID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "track.mp3"}
	metadata, err := mediacrypto.NewMetadata(1)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{7}, int(metadata.CiphertextSize))
	digest := sha256.Sum256(content)
	prepare := func(entry Entry) (PreparedFile, error) {
		p := Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: strings.Repeat("f", 32), Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), State: "active", Encryption: &metadata}
		return tree.PrepareFileWithFreshLocators(ctx, entry, p, Facts{ObjectID: entry.ObjectID})
	}
	prepared, err := prepare(song)
	if err != nil {
		t.Fatal(err)
	}
	target := store.SelectedMediaDeleteTarget{Path: "music/album", ResourceID: album.ObjectID, Directory: true}
	if _, err = tree.PreflightDirectoryDeletion(ctx, target); !errors.Is(err, ErrDirectoryDeleteUploadPending) {
		t.Fatal("folder plan passed an active pending upload", err)
	}
	if _, err = tree.PreflightDirectoryDeletion(ctx, store.SelectedMediaDeleteTarget{Path: "music", ResourceID: music.ObjectID, Directory: true}); !errors.Is(err, ErrInvalid) {
		t.Fatal("structural media root was not protected", err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	makePlan := func() *DirectoryDeletePreflight {
		t.Helper()
		plan, err := tree.PreflightDirectoryDeletion(ctx, target)
		if err != nil || len(plan.Leaves()) != 1 || plan.Leaves()[0].ResourceID != song.ObjectID || plan.Leaves()[0].Path != "music/album/hidden-disc/track.mp3" {
			t.Fatal("preflight omitted the hidden descendant", err)
		}
		return plan
	}
	write := func(fn func(*CoordinatedMutation, *sql.Tx) error) error {
		return tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if err = fn(m, tx); err != nil {
				return err
			}
			return tx.Commit()
		})
	}
	var folder, leaf store.SelectedMediaDeleteItem
	queue := func(plan *DirectoryDeletePreflight, queueLeaf bool) error {
		return write(func(m *CoordinatedMutation, tx *sql.Tx) error {
			admit, err := m.AdmitDirectoryDeletionsTx(ctx, tx, []*DirectoryDeletePreflight{plan})
			if err != nil {
				return err
			}
			if queueLeaf {
				leaf, _, err = m.QueueMasterLocalMediaDeletionTx(ctx, tx, plan.Leaves()[0])
				if err != nil {
					return err
				}
			}
			folder, _, err = m.QueueDirectoryDeletionTx(ctx, tx, target, admit)
			return err
		})
	}
	stale := makePlan()
	if err = create(Entry{ParentID: sibling.ObjectID, ObjectID: strings.Repeat("7", 64), Kind: "directory", Name: "unrelated"}); err != nil {
		t.Fatal(err)
	}
	if err = queue(stale, false); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("stale folder census admitted", err)
	}
	plan := makePlan()
	if err = queue(plan, false); !errors.Is(err, ErrConflict) {
		t.Fatal("folder marked without a committed leaf intent", err)
	}
	if err = queue(plan, true); err != nil || folder.State != store.SelectedMediaDeletePending || leaf.State != store.SelectedMediaDeletePending {
		t.Fatal("folder and exact descendant failed to queue atomically", folder, leaf, err)
	}
	if _, err = prepare(Entry{ParentID: disc.ObjectID, ObjectID: strings.Repeat("8", 64), Kind: "audio", Name: "new.mp3"}); err == nil {
		t.Fatal("new upload entered a pending directory")
	}
	if err = create(Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("9", 64), Kind: "directory", Name: "new-dir"}); err == nil {
		t.Fatal("new directory entered a pending directory")
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	folders, _, folderErr := tree.ListDirectoryDeletionsWithLease(ctx, lease, "", 8)
	leaves, _, leafErr := tree.ListMasterLocalMediaDeletionsWithLease(ctx, lease, "", 8)
	snapshot, _, snapshotErr := tree.ReadMasterLocalMediaDeletionWithLease(ctx, lease, leaf)
	lease.Release()
	if folderErr != nil || leafErr != nil || snapshotErr != nil || len(folders) != 1 || folders[0] != folder || len(leaves) != 1 || leaves[0] != leaf {
		t.Fatal("folder and leaf worker index did not remain independently usable", folderErr, leafErr, snapshotErr)
	}
	var finalized bool
	finalize := func(after error) error {
		return write(func(m *CoordinatedMutation, tx *sql.Tx) error {
			var err error
			finalized, _, err = m.FinalizeDirectoryDeletionTx(ctx, tx, folder)
			return errors.Join(err, after)
		})
	}
	if err = finalize(nil); err != nil || finalized {
		t.Fatal("folder finalized before its leaf receipt", err)
	}
	if err = write(func(m *CoordinatedMutation, tx *sql.Tx) error {
		_, err := m.FinalizeMasterLocalMediaDeletionTx(ctx, tx, leaf, snapshot.Placement)
		return err
	}); err != nil {
		t.Fatal("leaf metadata could not settle beneath pending ancestor", err)
	}
	rollback := errors.New("fixture rollback after directory settlement")
	if err = finalize(rollback); !errors.Is(err, rollback) || !finalized {
		t.Fatal("directory transaction rollback was not exercised", err)
	}
	if _, _, err = tree.GetFacts(ctx, empty.ObjectID); err != nil {
		t.Fatal("rollback removed a descendant directory", err)
	}
	if err = finalize(nil); err != nil || !finalized {
		t.Fatal("directory could not settle after leaf receipt", err)
	}
	for _, entry := range []Entry{album, disc, empty} {
		if _, _, err = tree.GetFacts(ctx, entry.ObjectID); err == nil {
			t.Fatal("a deleted subtree directory still has catalog facts", entry.Name)
		}
	}
	if _, _, err = tree.GetFacts(ctx, sibling.ObjectID); err != nil {
		t.Fatal("sibling scope changed", err)
	}
	if err = finalize(nil); err != nil || !finalized {
		t.Fatal("completed folder retry is not idempotent", err)
	}
}
