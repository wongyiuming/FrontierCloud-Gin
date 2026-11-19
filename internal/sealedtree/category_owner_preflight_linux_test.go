//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCategoryOwnerPreflightGenerationAndOneShot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, s, _, _, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	category := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "cat"}
	for _, entry := range []Entry{music, category} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	owner := strings.Repeat("f", 32)
	if _, err := s.PreflightCategoryAndOwner(context.Background(), category.ObjectID, owner); err == nil {
		t.Fatal("unbounded preflight accepted")
	}
	consume := func(tree *SQLStore, db *sql.DB, p *CategoryOwnerPreflight, parent, member string) error {
		return tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			return m.ConsumeCategoryOwnerPreflightTx(ctx, tx, p, parent, member)
		})
	}
	p, err := s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	copied := *p
	if err = consume(s, db, p, category.ObjectID, owner); err != nil {
		t.Fatal("valid proof", err)
	}
	if err = consume(s, db, &copied, category.ObjectID, owner); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("copied proof reused", err)
	}
	p, err = s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rolled.Exec(`UPDATE sealed_tree_meta SET write_fence=write_fence+1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err = rolled.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = consume(s, db, p, category.ObjectID, owner); err != nil {
		t.Fatal("rolled back generation invalidated proof", err)
	}
	p, err = s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: category.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "audio", Name: "new.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	loc.BlobID, loc.ReadAlias = "", ""
	if _, err = s.PrepareFileWithFreshLocators(ctx, entry, loc, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if err = consume(s, db, p, category.ObjectID, owner); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("stale generation accepted", err)
	}
	p, err = s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = consume(s, db, p, category.ObjectID, strings.Repeat("e", 32)); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("wrong owner accepted", err)
	}
	p, err = s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	otherDB, other, _, _, _ := fencedFixture(t)
	if err = consume(other, otherDB, p, category.ObjectID, owner); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("foreign tree accepted", err)
	}
	originalCtx, cancelOriginal := context.WithCancel(ctx)
	p, err = s.PreflightCategoryAndOwner(originalCtx, category.ObjectID, owner)
	if err != nil {
		cancelOriginal()
		t.Fatal(err)
	}
	bound, releaseBound, err := p.BindContext(context.Background())
	if err != nil {
		cancelOriginal()
		t.Fatal(err)
	}
	cancelOriginal()
	if err = p.CheckContext(context.Background()); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("cancelled origin context passed final check", err)
	}
	select {
	case <-bound.Done():
	case <-time.After(time.Second):
		t.Fatal("bound transaction not cancelled with origin")
	}
	releaseBound()
	if err = consume(s, db, p, category.ObjectID, owner); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("cancelled origin proof accepted", err)
	}
	p, err = s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	child, cancelChild := context.WithCancel(context.Background())
	bound, releaseBound, err = p.BindContext(child)
	if err != nil {
		t.Fatal(err)
	}
	cancelChild()
	select {
	case <-bound.Done():
	case <-time.After(time.Second):
		t.Fatal("bound transaction not cancelled with caller")
	}
	releaseBound()
	short, done := context.WithTimeout(ctx, 150*time.Millisecond)
	p, err = s.PreflightCategoryAndOwner(short, category.ObjectID, owner)
	if err != nil {
		done()
		t.Fatal(err)
	}
	deadlineBound, releaseDeadline, err := p.BindContext(context.Background())
	if err != nil {
		done()
		t.Fatal(err)
	}
	select {
	case <-deadlineBound.Done():
	case <-time.After(time.Second):
		t.Fatal("proof deadline did not cancel bound transaction")
	}
	releaseDeadline()
	<-short.Done()
	done()
	if err = consume(s, db, p, category.ObjectID, owner); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("expired proof accepted", err)
	}
}

func TestCategoryOwnerSQLiteWALReadSnapshot(t *testing.T) {
	ctx := context.Background()
	db, _, _, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE snapshot_probe(value INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO snapshot_probe VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var before, again, after int
	if err = tx.QueryRow(`SELECT value FROM snapshot_probe`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE snapshot_probe SET value=2`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(`SELECT value FROM snapshot_probe`).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT value FROM snapshot_probe`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != 1 || again != 1 || after != 2 {
		t.Fatal("SQLite read transaction lost snapshot", before, again, after)
	}
}

// Cooperative writers cannot pass a real shared tree fence during a scan.
func TestCategoryOwnerPreflightTreeFenceBlocksWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, s, _, _, _ := fencedFixture(t)
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "writer"}
	go func() { done <- s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}) }()
	select {
	case err := <-done:
		lease.Release()
		t.Fatal("writer passed shared fence", err)
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("writer failed to resume", ctx.Err())
	}
}

// A replaced lock inode never reuses a previously captured preflight.
func TestCategoryOwnerPreflightRejectsFenceReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, s, _, _, dir := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	category := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "cat"}
	for _, entry := range []Entry{music, category} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	owner := strings.Repeat("f", 32)
	p, err := s.PreflightCategoryAndOwner(ctx, category.ObjectID, owner)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, treeFenceFile)
	if err = os.Rename(f, f+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		return m.ConsumeCategoryOwnerPreflightTx(ctx, tx, p, category.ObjectID, owner)
	})
	if err == nil {
		t.Fatal("replacement fence accepted")
	}
}
