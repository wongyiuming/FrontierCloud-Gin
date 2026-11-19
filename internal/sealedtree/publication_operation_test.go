package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestCompletedNativePublicationOperationAuthenticatesExactReceipt(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	objectID, blobID := strings.Repeat("b", 64), strings.Repeat("c", 64)
	otherBlobID, op := strings.Repeat("d", 64), strings.Repeat("e", 64)
	object, err := s.tree.ObjectIndex(objectID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.tree.BlobIndex(blobID)
	if err != nil {
		t.Fatal(err)
	}
	otherBlob, err := s.tree.BlobIndex(otherBlobID)
	if err != nil {
		t.Fatal(err)
	}
	read := func(want string, wantErr error) {
		t.Helper()
		tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		got, err := s.completedNativePublicationOperation(ctx, tx, objectID, blobID)
		if got != want || !errors.Is(err, wantErr) {
			t.Fatalf("operation=%q err=%v, want %q %v", got, err, want, wantErr)
		}
	}
	insert := func(operation, blob string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`,
			operation, object, blob, s.completionMAC(operation, object, blob)); err != nil {
			t.Fatal(err)
		}
	}
	insert(strings.Repeat("f", 64), otherBlob)
	read("", ErrConflict)
	insert(op, blob)
	read(op, nil)
	if _, err := db.Exec(`UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, s.completionMAC(op, object, otherBlob), op); err != nil {
		t.Fatal(err)
	}
	read("", ErrConflict)
	if _, err := db.Exec(`UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, s.completionMAC(op, object, blob), op); err != nil {
		t.Fatal(err)
	}
	insert(strings.Repeat("1", 64), blob)
	read("", ErrConflict)
}
