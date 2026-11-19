//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestCoordinatedMediaLayout(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	category := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "first"}
	nested := Entry{ParentID: category.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "sub"}
	second := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "directory", Name: "second"}
	secondSub := Entry{ParentID: second.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "directory", Name: "sub"}
	for _, d := range []Entry{music, category, nested, second, secondSub} {
		if err := s.CreateDirectoryWithFacts(ctx, d, Facts{ObjectID: d.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(parent string) error {
		return s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			return m.CheckMediaCategoryLayoutTx(ctx, tx, parent)
		})
	}
	checkBoth := func(parent, owner string) error {
		return s.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			return m.CheckMediaCategoryAndOwnerTx(ctx, tx, parent, owner)
		})
	}
	if err := check(category.ObjectID); err != nil {
		t.Fatal("empty nested dir", err)
	}
	if err := check(nested.ObjectID); err != nil {
		t.Fatal("empty category", err)
	}
	direct := Entry{ParentID: category.ObjectID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "direct.mp3"}
	p := fixturePlacement(t, direct.ObjectID)
	p.BlobID, p.ReadAlias = "", ""
	if _, err := s.PrepareFileWithFreshLocators(ctx, direct, p, Facts{ObjectID: direct.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if err := check(nested.ObjectID); !errors.Is(err, ErrConflict) {
		t.Fatal("direct pending must block nested", err)
	}
	if err := check(category.ObjectID); err != nil {
		t.Fatal("matching direct pending", err)
	}
	if err := checkBoth(category.ObjectID, p.OwnerID); err != nil {
		t.Fatal("combined matching direct pending", err)
	}
	if err := checkBoth(category.ObjectID, strings.Repeat("d", 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("combined wrong direct owner", err)
	}
	if err := checkBoth(nested.ObjectID, p.OwnerID); !errors.Is(err, ErrConflict) {
		t.Fatal("combined layout conflict", err)
	}
	if err := check(secondSub.ObjectID); err != nil {
		t.Fatal("other category affected", err)
	}
	// A nested reservation participates even before an Owner has any bytes.
	reserved := Entry{ParentID: secondSub.ObjectID, ObjectID: strings.Repeat("8", 64), Kind: "audio", Name: "reserved.mp3"}
	rp := fixturePlacement(t, reserved.ObjectID)
	rp.BlobID, rp.ReadAlias = "", ""
	if _, err := s.PrepareFileWithFreshLocators(ctx, reserved, rp, Facts{ObjectID: reserved.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if err := check(second.ObjectID); !errors.Is(err, ErrConflict) {
		t.Fatal("nested pending must block direct", err)
	}
	if err := check(secondSub.ObjectID); err != nil {
		t.Fatal("matching nested pending", err)
	}
	// A committed nested file also blocks a direct upload in its category.
	child := Entry{ParentID: secondSub.ObjectID, ObjectID: strings.Repeat("7", 64), Kind: "audio", Name: "child.mp3"}
	loc := fixturePlacement(t, child.ObjectID)
	data := []byte("fixture")
	sum := sha256.Sum256(data)
	loc.BlobID, loc.ReadAlias, loc.Bytes, loc.SHA256 = "", "", int64(len(data)), hex.EncodeToString(sum[:])
	prep, err := s.PrepareFileWithFreshLocators(ctx, child, loc, Facts{ObjectID: child.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prep.OperationID, pub, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err := check(second.ObjectID); !errors.Is(err, ErrConflict) {
		t.Fatal("nested committed must block direct", err)
	}
	if err := check(secondSub.ObjectID); err != nil {
		t.Fatal("matching nested file", err)
	}
	if err := checkBoth(secondSub.ObjectID, loc.OwnerID); err != nil {
		t.Fatal("combined matching nested", err)
	}
	if err := checkBoth(secondSub.ObjectID, strings.Repeat("d", 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("combined wrong nested owner", err)
	}
	if err := checkBoth(second.ObjectID, loc.OwnerID); !errors.Is(err, ErrConflict) {
		t.Fatal("combined nested layout conflict", err)
	}
	if err := check(music.ObjectID); err == nil {
		t.Fatal("category root accepted")
	}
	if err := check(strings.Repeat("f", 64)); err == nil {
		t.Fatal("unknown parent accepted")
	}
}
