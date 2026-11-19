//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCoordinatedDirectParentAffinity(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	directory := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, directory, Facts{ObjectID: directory.ObjectID}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("fixture")
	sum := sha256.Sum256(payload)
	entry := Entry{ParentID: directory.ObjectID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "song.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	loc.Bytes, loc.SHA256, loc.BlobID, loc.ReadAlias = int64(len(payload)), hex.EncodeToString(sum[:]), "", ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, entry, loc, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	check := func(owner string) error {
		return s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			return m.CheckDirectParentOwnerTx(ctx, tx, directory.ObjectID, owner)
		})
	}
	if err := check(loc.OwnerID); err != nil {
		t.Fatal("matching owner", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		return m.CheckDirectParentOwnerTx(cancelled, tx, directory.ObjectID, loc.OwnerID)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan accepted", err)
	}
	if err := check(strings.Repeat("2", 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong committed owner", err)
	}
	// A pending reservation must also block a different owner before the blob exists.
	other := Entry{ParentID: directory.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "pending.mp3"}
	p := fixturePlacement(t, other.ObjectID)
	p.OwnerID = strings.Repeat("2", 32)
	p.BlobID, p.ReadAlias = "", ""
	_, err = s.PrepareFileWithFreshLocators(ctx, other, p, Facts{ObjectID: other.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	if err := check(loc.OwnerID); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong pending owner", err)
	}
	// A deleted record cannot silently make a populated folder appear empty:
	// authenticated listing counts remain committed to the original group.
	index, err := s.tree.ObjectIndex(entry.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_records WHERE object_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if err := check(p.OwnerID); err == nil {
		t.Fatal("missing record accepted")
	}
}

// Crosses the page boundary without materializing all pending records at once.
func TestCoordinatedAffinityPagesPending(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	for i := 1; i <= 130; i++ {
		id := fmt.Sprintf("%064x", i)
		entry := Entry{ParentID: s.rootID, ObjectID: id, Kind: "audio", Name: fmt.Sprintf("song-%03d.mp3", i)}
		p := fixturePlacement(t, id)
		p.BlobID, p.ReadAlias = "", ""
		if _, err := s.PrepareFileWithFreshLocators(ctx, entry, p, Facts{ObjectID: id}); err != nil {
			t.Fatalf("prepare %d: %v", i, err)
		}
	}
	err := s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		started := time.Now()
		result := m.CheckDirectParentOwnerTx(ctx, tx, s.rootID, strings.Repeat("f", 32))
		t.Logf("synthetic 130-pending scan time: %s; not a production capacity guarantee", time.Since(started))
		return result
	})
	if err != nil {
		t.Fatal("paged parent affinity", err)
	}
}
