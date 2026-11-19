package preprodimport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"golang.org/x/crypto/hkdf"
	_ "modernc.org/sqlite"
)

// syntheticPendingTree writes a cryptographically valid pending record into a
// fresh SQLite test DB. It deliberately bypasses runtime mutation fencing;
// this is a fixture for source/tree comparison, not publication authorization.
func syntheticPendingTree(t *testing.T, facts sealedtree.Facts, logicalPath string) (*sql.DB, *sealedtree.SQLStore, string) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	master, salt := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x55}, 32)
	tree, err := sealedtree.New(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("8", 64)
	s, err := sealedtree.InitializeSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(logicalPath, "/")
	if len(parts) != 3 || parts[0] != "music" {
		t.Fatal("fixture path")
	}
	parentID := rootID
	for i, id := range []string{strings.Repeat("5", 64), strings.Repeat("6", 64)} {
		dir, e := tree.Seal(parentID, id, "directory", parts[i], 1)
		if e != nil {
			t.Fatal(e)
		}
		encID, e := sealedtree.EncryptionID(dir)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, encID); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(`INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, dir.ObjectIndex, dir.ParentIndex, dir.Lookup, dir.Revision, encID, dir.Sealed); e != nil {
			t.Fatal(e)
		}
		parentID = id
	}
	entry := sealedtree.Entry{ParentID: parentID, ObjectID: facts.ObjectID, Kind: "audio", Name: parts[2]}
	placement := sealedtree.Placement{ObjectID: facts.ObjectID, NativeObjectID: strings.Repeat("b", 64), OwnerID: strings.Repeat("1", 32), BlobID: strings.Repeat("3", 64), ReadAlias: strings.Repeat("4", 64), Bytes: 5, SHA256: digest([]byte("audio"))}
	name, err := tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := tree.SealPlacement(placement, 1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := tree.SealFacts(facts, 1)
	if err != nil {
		t.Fatal(err)
	}
	nameID, err := sealedtree.EncryptionID(name)
	if err != nil {
		t.Fatal(err)
	}
	locID, err := sealedtree.PlacementEncryptionID(loc)
	if err != nil {
		t.Fatal(err)
	}
	factsID, err := sealedtree.FactsEncryptionID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	aliasIndex, err := tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		t.Fatal(err)
	}
	indexKey := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, master, salt, []byte("frontiercloud:sealed-tree:index:v1")), indexKey); err != nil {
		t.Fatal(err)
	}
	defer clear(indexKey)
	op := strings.Repeat("c", 64)
	mac := hmac.New(sha256.New, indexKey)
	for _, value := range []string{"frontiercloud:sealed-tree:pending:v2\x00", op, name.ObjectIndex, name.ParentIndex, name.Lookup, nameID, loc.BlobIndex, locID} {
		mac.Write([]byte(value))
	}
	mac.Write(name.Sealed)
	mac.Write(loc.Sealed)
	mac.Write([]byte{1})
	mac.Write([]byte(factsID))
	mac.Write(sealed.Sealed)
	for _, id := range []string{nameID, locID, factsID} {
		if _, err = db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{loc.BlobIndex, aliasIndex} {
		if _, err = db.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_operation_ids(operation_id) VALUES(?)`, op); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_pending_files(operation_id,operation_mac,object_index,parent_index,lookup_tag,name_encryption_id,name_sealed,blob_index,placement_encryption_id,placement_sealed) VALUES(?,?,?,?,?,?,?,?,?,?)`, op, hex.EncodeToString(mac.Sum(nil)), name.ObjectIndex, name.ParentIndex, name.Lookup, nameID, name.Sealed, loc.BlobIndex, locID, loc.Sealed); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_pending_facts(operation_id,object_index,revision,encryption_id,sealed) VALUES(?,?,?,?,?)`, op, sealed.ObjectIndex, sealed.Revision, factsID, sealed.Sealed); err != nil {
		t.Fatal(err)
	}
	return db, s, op
}
