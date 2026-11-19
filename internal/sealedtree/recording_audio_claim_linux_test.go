//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// This checks the real tree fence and SQLite transaction, including rollback
// of a synthetic caller intent. It does not test caller authorization or Owner
// publication, which must be completed by the recording coordinator.
func TestRecordingAudioClaimSharesFencedTransaction(t *testing.T) {
	ctx := context.Background()
	db, tree, _, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE test_recording_audio_intent (operation TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	binding := "recording-audio:v1:" + strings.Repeat("1", 32) + ":" + strings.Repeat("2", 64) + ":" + strings.Repeat("3", 32)
	op, other := strings.Repeat("4", 64), strings.Repeat("5", 64)
	if err = tree.ReserveNewMediaPreparation(ctx, meta, binding); err != nil {
		t.Fatal(err)
	}
	apply := func(operation, scope string, commit bool) error {
		return tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO test_recording_audio_intent VALUES(?)`, operation); err != nil {
				return err
			}
			if err = m.ClaimRecordingAudioPreparationTx(ctx, tx, meta, scope, operation); err != nil || !commit {
				return err
			}
			return tx.Commit()
		})
	}
	if err = apply(op, binding, false); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM test_recording_audio_intent`).Scan(&count); err != nil || count != 0 {
		t.Fatal("caller intent survived rollback")
	}
	if err = apply(other, binding, true); err != nil {
		t.Fatal(err)
	}
	if err = apply(other, binding, true); err != nil {
		t.Fatal("same operation retry", err)
	}
	if err = apply(op, binding, true); !errors.Is(err, ErrConflict) {
		t.Fatal("claimed file ID accepted for another operation", err)
	}
	if err = apply(other, binding+":extra", true); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed scope accepted", err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM test_recording_audio_intent`).Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected operation changed caller intent")
	}
}
