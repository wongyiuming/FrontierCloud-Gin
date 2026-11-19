//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestCoordinatedTreeMutationBindsDatabaseAndRollsBack(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	other, _, _, _, _ := fencedFixture(t)
	if err := s.WithCoordinatedMutation(ctx, other, func(*CoordinatedMutation) error { return nil }); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("foreign database accepted", err)
	}
	var saved *CoordinatedMutation
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "fixture.mp3"}
	placement := fixturePlacement(t, entry.ObjectID)
	placement.BlobID = ""
	placement.ReadAlias = ""
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	placement.Bytes, placement.Encryption = metadata.CiphertextSize, &metadata
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		saved = m
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		got, e := m.PrepareFileTx(ctx, tx, entry, placement, Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &SelectedUploadFact{UploadID: strings.Repeat("a", 32), AdminBinding: strings.Repeat("b", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}})
		if e != nil {
			return e
		}
		if got.BlobID == "" || got.ReadAlias == "" || got.BlobID == got.ReadAlias || got.OperationID == got.BlobID {
			return ErrInvalid
		}
		pending, e := m.ReadSelectedFileTx(ctx, tx, got.OperationID)
		descriptor, descriptorErr := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
		if e != nil || descriptorErr != nil || pending.ParentID != entry.ParentID || pending.ObjectID != entry.ObjectID || pending.Placement.Encryption == nil || *pending.Placement.Encryption != metadata || pending.Descriptor != descriptor || pending.Placement.BlobID != got.BlobID {
			return ErrInvalid
		}
		var sealed []byte
		if e = tx.QueryRow("SELECT placement_sealed FROM sealed_tree_pending_files WHERE operation_id=?", got.OperationID).Scan(&sealed); e != nil || bytes.Contains(sealed, []byte(metadata.FileID)) || bytes.Contains(sealed, []byte(entry.Name)) {
			return ErrInvalid
		}
		return errors.New("fixture rollback")
	})
	if err == nil || err.Error() != "fixture rollback" {
		t.Fatal("fault did not roll back", err)
	}
	var n int
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&n); err != nil || n != 0 {
		t.Fatal("pending leaked", n, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = saved.PrepareFileTx(ctx, tx, entry, placement, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired fence reused", err)
	}
}

func TestSelectedPendingCannotUseGenericPublish(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "selected.mp3"}
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{0x42}, int(metadata.CiphertextSize))
	digest := sha256.Sum256(content)
	placement := Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: strings.Repeat("2", 32), Bytes: metadata.CiphertextSize, SHA256: hex.EncodeToString(digest[:]), Encryption: &metadata}
	facts := Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &SelectedUploadFact{UploadID: strings.Repeat("1", 32), AdminBinding: strings.Repeat("2", 64), Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}
	var prepared PreparedFile
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		prepared, e = m.PrepareFileTx(ctx, tx, entry, placement, facts)
		if e != nil {
			return e
		}
		return tx.Commit()
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(content)); !errors.Is(err, ErrInvalid) {
		t.Fatal("generic publisher accepted selected pending", err)
	}
	dest, err := BlobPath(prepared.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generic publisher created physical blob", err)
	}
}

func TestCoordinatedSelectedPreparationClaimIsAtomicAndBound(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	metadata, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	admin := strings.Repeat("b", 64)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "claim.mp3"}
	placement := fixturePlacement(t, entry.ObjectID)
	placement.BlobID, placement.ReadAlias = "", ""
	placement.Bytes, placement.Encryption = metadata.CiphertextSize, &metadata
	facts := Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &SelectedUploadFact{UploadID: strings.Repeat("a", 32), AdminBinding: admin, Policy: "Direct", Revision: 1, Origin: "https://owner.test"}}
	var first PreparedFile
	var expired *CoordinatedMutation
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		expired = m
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = s.reserveMediaPreparationTx(ctx, tx, metadata, "admin:"+admin); e != nil {
			return e
		}
		first, e = m.PrepareFileTx(ctx, tx, entry, placement, facts)
		if e != nil {
			return e
		}
		if e = m.ClaimSelectedMediaPreparationTx(ctx, tx, first.OperationID); e != nil {
			return e
		}
		if e = m.ClaimSelectedMediaPreparationTx(ctx, tx, first.OperationID); e != nil {
			return e
		}
		return tx.Commit()
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		entry.ObjectID = strings.Repeat("d", 64)
		entry.Name = "another-claim.mp3"
		placement.ObjectID, placement.NativeObjectID = entry.ObjectID, entry.ObjectID
		facts.ObjectID = entry.ObjectID
		second, e := m.PrepareFileTx(ctx, tx, entry, placement, facts)
		if e != nil {
			return e
		}
		if e = m.ClaimSelectedMediaPreparationTx(ctx, tx, second.OperationID); !errors.Is(e, ErrConflict) {
			return errors.New("file ID accepted for another operation")
		}
		return nil // Roll back the second pending record.
	})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM sealed_tree_pending_files").Scan(&count); err != nil || count != 1 {
		t.Fatal("conflicting pending leaked", count, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = expired.ClaimSelectedMediaPreparationTx(ctx, tx, first.OperationID); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired fence reused", err)
	}
}
