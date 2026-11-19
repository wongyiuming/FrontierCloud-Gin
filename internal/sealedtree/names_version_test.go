package sealedtree

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func legacyNameFixture(t *testing.T, tree *Tree, entry Entry) Record {
	t.Helper()
	object, err := tree.ObjectIndex(entry.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := tree.ParentIndex(entry.ParentID)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := tree.Lookup(entry.ParentID, entry.Name)
	if err != nil || len(entry.Name) > legacyComponentBytes {
		t.Fatal("legacy name", err)
	}
	plain := make([]byte, legacyPayloadBytes)
	defer clear(plain)
	plain[0] = kindByte(entry.Kind)
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(entry.Name)))
	copy(plain[3:67], entry.ParentID)
	copy(plain[67:131], entry.ObjectID)
	copy(plain[131:], entry.Name)
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		t.Fatal(err)
	}
	aead, err := tree.recordCipher(random[:recordSaltBytes], "name")
	if err != nil {
		t.Fatal(err)
	}
	sealed := append([]byte{recordVersion}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, nameAAD(object, 1, recordVersion))
	return Record{ObjectIndex: object, ParentIndex: parent, Lookup: lookup, Revision: 1, Sealed: sealed}
}

func TestNameV2SupportsUnicodeAndReadsV1(t *testing.T) {
	tree := fixture(t)
	parent, object := strings.Repeat("a", 64), strings.Repeat("b", 64)
	oldEntry := Entry{ParentID: parent, ObjectID: object, Kind: "directory", Name: "旧目录"}
	old := legacyNameFixture(t, tree, oldEntry)
	if got, err := tree.Open(parent, old); err != nil || got != oldEntry {
		t.Fatal("legacy read", err)
	}
	name := strings.Repeat("😀", 1024)
	record, err := tree.Seal(parent, object, "directory", name, 2)
	if err != nil {
		t.Fatal("legal unicode component", err)
	}
	if record.Sealed[0] != nameRecordVersion {
		t.Fatal("wrong name version")
	}
	if got, err := tree.Open(parent, record); err != nil || got.Name != name {
		t.Fatal("unicode roundtrip", err)
	}
	if _, err = tree.Seal(parent, object, "directory", name+"😀", 3); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized name accepted", err)
	}
	damaged := old
	damaged.Sealed = append([]byte(nil), old.Sealed...)
	damaged.Sealed[0] = nameRecordVersion
	if _, err = tree.Open(parent, damaged); !errors.Is(err, ErrInvalid) {
		t.Fatal("version substitution accepted", err)
	}
}

func TestFactsSupportFourBytePathsAndEscapedMaximum(t *testing.T) {
	tree := fixture(t)
	id := strings.Repeat("b", 64)
	path := strings.Repeat("😀", 1024)
	f := Facts{ObjectID: id, Playback: &PlaybackFact{LegacyMediaPath: path, CreatedAt: "x", UpdatedAt: "x"}, Lyric: &LyricFact{LegacyMediaPath: path, LyricID: strings.Repeat("c", 64), LegacyLyricPath: path, CreatedAt: "x", UpdatedAt: "x"}}
	r, err := tree.SealFacts(f, 1)
	if err != nil {
		t.Fatal("legal paths", err)
	}
	got, err := tree.OpenFacts(r)
	if err != nil || got.Playback.LegacyMediaPath != path || got.Lyric.LegacyLyricPath != path {
		t.Fatal("path roundtrip", err)
	}
	f.Playback.LegacyMediaPath += "😀"
	if _, err = tree.SealFacts(f, 2); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized path accepted", err)
	}
	// JSON escapes U+2028 into six bytes; three maximum paths still fit v2.
	escaped := strings.Repeat("\u2028", 1024)
	f.Playback.LegacyMediaPath, f.Lyric.LegacyMediaPath, f.Lyric.LegacyLyricPath = escaped, escaped, escaped
	if _, err = tree.SealFacts(f, 3); err != nil {
		t.Fatal("maximum escaped paths do not fit", err)
	}
}
