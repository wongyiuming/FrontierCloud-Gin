package business

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	_ "modernc.org/sqlite"
)

func TestSealedTreeInventoryStopsAtBudgetWithoutReturningPartialReport(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','sealed',1)`, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{strings.Repeat("b", 64), strings.Repeat("c", 64)} {
		if _, err = db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?,'2026-01-01','2026-01-01')`, id, "music/album/"+id+".mp3", id); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New(db, "sqlite").sealedTreeInventory(ctx, 1)
	if !errors.Is(err, store.ErrSealedTreeInventoryLimit) || report.DatabaseSnapshotOnly || report.LocalObjectRows != 0 {
		t.Fatal("bounded inventory returned partial facts or wrong error", err)
	}
}

func TestSealedTreeInventoryBoundsAuditCountWithoutReturningTruncatedResult(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','sealed',1)`, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{strings.Repeat("b", 32), strings.Repeat("c", 32)} {
		if _, err = db.Exec(`INSERT INTO node_audit(audit_id,action,relationship_id,actor,detail,created_at) VALUES(?,'fixture',NULL,'fixture','{}',1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New(db, "sqlite").sealedTreeInventory(ctx, 1)
	if !errors.Is(err, store.ErrSealedTreeInventoryLimit) || report.DatabaseSnapshotOnly || report.NodeAuditRows != 0 {
		t.Fatal("bounded audit count returned truncated facts or wrong error", err)
	}
}
