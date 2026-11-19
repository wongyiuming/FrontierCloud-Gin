package sealedtree

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) *Tree {
	t.Helper()
	tree, err := New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestDistinctEnvironmentSecretsCannotOpenEachOthersTree(t *testing.T) {
	production, err := NewMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(production)
	preproduction, err := NewMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(preproduction)
	if len(production) != 32 || len(preproduction) != 32 || bytes.Equal(production, preproduction) {
		t.Fatal("environment tree secrets are not independent")
	}
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	prodTree, err := New(production, salt)
	if err != nil {
		t.Fatal(err)
	}
	preTree, err := New(preproduction, salt)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	record, err := prodTree.Seal(parent, child, "audio", "secret.mp3", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = preTree.Open(parent, record); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other environment decrypted tree: %v", err)
	}
}

func TestEncryptedComponentsBindParentObjectAndKind(t *testing.T) {
	tree := fixture(t)
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, tc := range []struct{ kind, name string }{
		{"directory", "黃耀明專輯"}, {"audio", "晴天.mp3"}, {"lyric", "晴天.lrc"}, {"video", "演唱會.mp4"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			r, err := tree.Seal(parent, child, tc.kind, tc.name, 1)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tree.Open(parent, r)
			if err != nil || got.Kind != tc.kind || got.Name != tc.name || got.ObjectID != child {
				t.Fatalf("round trip failed: %v", err)
			}
			encoded, err := json.Marshal(r)
			if err != nil || bytes.Contains(encoded, []byte(tc.name)) || bytes.Contains(encoded, []byte(tc.kind)) || bytes.Contains(encoded, []byte(parent)) || bytes.Contains(encoded, []byte(child)) || bytes.Contains(r.Sealed, []byte(tc.name)) || strings.Contains(r.Lookup, tc.name) {
				t.Fatal("record contains component plaintext")
			}
			other, err := tree.Seal(parent, child, tc.kind, tc.name, 1)
			if err != nil || other.Lookup != r.Lookup || bytes.Equal(other.Sealed, r.Sealed) {
				t.Fatal("lookup must be stable and ciphertext probabilistic")
			}
		})
	}
}

func TestEncryptedComponentsRejectTamperingAndWrongSecrets(t *testing.T) {
	tree := fixture(t)
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r, err := tree.Seal(parent, child, "audio", "private.mp3", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Record)
	}{
		{"parent-index", func(v *Record) { v.ParentIndex = strings.Repeat("c", 64) }},
		{"object", func(v *Record) { v.ObjectIndex = strings.Repeat("d", 64) }},
		{"revision", func(v *Record) { v.Revision++ }},
		{"lookup", func(v *Record) { v.Lookup = strings.Repeat("e", 64) }},
		{"ciphertext", func(v *Record) { v.Sealed[len(v.Sealed)-1] ^= 1 }},
		{"record-salt", func(v *Record) { v.Sealed[1] ^= 1 }},
		{"nonce", func(v *Record) { v.Sealed[1+recordSaltBytes] ^= 1 }},
		{"version", func(v *Record) { v.Sealed[0] = recordVersion }},
		{"truncated", func(v *Record) { v.Sealed = v.Sealed[:3] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := r
			altered.Sealed = append([]byte(nil), r.Sealed...)
			tc.edit(&altered)
			if got, err := tree.Open(parent, altered); !errors.Is(err, ErrInvalid) || got != (Entry{}) {
				t.Fatalf("modified record accepted: %v", err)
			}
		})
	}
	for _, input := range []struct{ key, salt byte }{{0x43, 0x91}, {0x42, 0x92}} {
		other, err := New(bytes.Repeat([]byte{input.key}, 32), bytes.Repeat([]byte{input.salt}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := other.Open(parent, r); !errors.Is(err, ErrInvalid) || got != (Entry{}) {
			t.Fatal("wrong key or cluster salt opened a record")
		}
	}
	if got, err := tree.Open(strings.Repeat("c", 64), r); !errors.Is(err, ErrInvalid) || got != (Entry{}) {
		t.Fatal("different parent opened a record")
	}
}

func TestLookupIsParentScopedAndNeverAPlainHash(t *testing.T) {
	tree := fixture(t)
	p1, p2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	x, err := tree.Lookup(p1, "same.mp3")
	if err != nil {
		t.Fatal(err)
	}
	y, err := tree.Lookup(p2, "same.mp3")
	if err != nil || x == y {
		t.Fatal("same name across parents leaked a shared lookup")
	}
	other, _ := New(bytes.Repeat([]byte{0x43}, 32), bytes.Repeat([]byte{0x91}, 32))
	z, _ := other.Lookup(p1, "same.mp3")
	if x == z {
		t.Fatal("different secrets generated same lookup")
	}
	group1, err := tree.ParentIndex(p1)
	if err != nil {
		t.Fatal(err)
	}
	group2, err := tree.ParentIndex(p2)
	if err != nil || group1 == p1 || group1 == group2 {
		t.Fatal("parent group is not keyed and isolated")
	}
	objectIndex, err := tree.ObjectIndex(p1)
	if err != nil || objectIndex == p1 || objectIndex == group1 {
		t.Fatal("object and parent tags are not domain separated")
	}
	short, _ := tree.Seal(p1, p2, "audio", "a.mp3", 1)
	long, _ := tree.Seal(p1, p2, "audio", strings.Repeat("x", 900)+".mp3", 1)
	if len(short.Sealed) != len(long.Sealed) {
		t.Fatal("ciphertext leaked component length")
	}
}

func TestRenameAndMovePreserveOpaqueIdentity(t *testing.T) {
	tree := fixture(t)
	rootA, rootB, directory, child := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	original, err := tree.Seal(rootA, directory, "directory", "专辑", 1)
	if err != nil {
		t.Fatal(err)
	}
	childRecord, err := tree.Seal(directory, child, "audio", "歌曲.mp3", 1)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := tree.Seal(rootA, directory, "directory", "新专辑", 2)
	if err != nil || renamed.ObjectIndex != original.ObjectIndex || renamed.ParentIndex != original.ParentIndex || renamed.Lookup == original.Lookup {
		t.Fatal("rename changed identity or failed to change lookup")
	}
	moved, err := tree.Seal(rootB, directory, "directory", "新专辑", 3)
	if err != nil || moved.ObjectIndex != original.ObjectIndex || moved.ParentIndex == original.ParentIndex || moved.Lookup == renamed.Lookup {
		t.Fatal("move changed identity or preserved old parent binding")
	}
	if _, err := tree.Open(rootA, moved); !errors.Is(err, ErrInvalid) {
		t.Fatal("moved object opened under prior parent")
	}
	entry, err := tree.Open(rootB, moved)
	if err != nil || entry.ObjectID != directory || entry.Name != "新专辑" {
		t.Fatal("moved object unavailable at new parent")
	}
	entry, err = tree.Open(directory, childRecord)
	if err != nil || entry.ObjectID != child || entry.Name != "歌曲.mp3" {
		t.Fatal("moving parent changed a descendant's parent identity")
	}
	// The persistence layer must atomically compare-and-swap revisions and keep
	// encryption ID reservations: this primitive authenticates revision but
	// cannot independently detect a rollback of an entire database snapshot.
}

func TestInvalidInputsFailClosed(t *testing.T) {
	tree := fixture(t)
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "a\x00b", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := tree.Seal(parent, child, "audio", name, 1); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid component accepted: %q", name)
		}
	}
	for _, value := range []struct{ parent, child, kind string }{
		{"", child, "audio"}, {parent, parent, "audio"}, {parent, child, "unknown"}, {parent, strings.Repeat("A", 64), "audio"},
	} {
		if _, err := tree.Seal(value.parent, value.child, value.kind, "song.mp3", 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid identity accepted")
		}
	}
	if _, err := tree.Seal(parent, child, "audio", "song.mp3", 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("nonpositive revision accepted")
	}
	if _, err := New(make([]byte, 31), make([]byte, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid master accepted")
	}
	if _, err := New(make([]byte, 32), make([]byte, 31)); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid salt accepted")
	}
	if _, err := New(make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero salt accepted")
	}
	a, err := NewSalt()
	if err != nil || len(a) != 32 {
		t.Fatal("failed to generate tree salt")
	}
	b, err := NewSalt()
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("independent tree salts not generated")
	}
}

func TestLookupPreservesExactUnicodeAndCase(t *testing.T) {
	tree := fixture(t)
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	// Existing persisted paths use binary equality. Display sorting may fold case,
	// but migration must not silently collapse byte-distinct existing names.
	names := []string{"é.mp3", "e\u0301.mp3", "A.mp3", "a.mp3", "line\nbreak.mp3"}
	seen := map[string]bool{}
	for _, name := range names {
		r, err := tree.Seal(parent, child, "audio", name, 1)
		if err != nil || seen[r.Lookup] {
			t.Fatalf("distinct existing name rejected or collapsed: %q %v", name, err)
		}
		seen[r.Lookup] = true
		got, err := tree.Open(parent, r)
		if err != nil || got.Kind != "audio" || got.Name != name || got.ObjectID != child {
			t.Fatalf("binary exact name failed: %q %v", name, err)
		}
	}
}

func TestConcurrentSealsUseIndependentRecordKeys(t *testing.T) {
	tree := fixture(t)
	parent, child := strings.Repeat("a", 64), strings.Repeat("b", 64)
	const n = 256
	results := make(chan Record, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := tree.Seal(parent, child, "audio", "same.mp3", 1)
			results <- r
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for r := range results {
		id, err := EncryptionID(r)
		if err != nil || seen[id] {
			t.Fatal("duplicate or invalid per-record encryption ID")
		}
		seen[id] = true
		entry, err := tree.Open(parent, r)
		if err != nil || entry.Kind != "audio" || entry.Name != "same.mp3" || entry.ObjectID != child {
			t.Fatal("concurrent record did not authenticate")
		}
	}
	if len(seen) != n {
		t.Fatal("concurrent records missing")
	}
}

func TestBlobLocatorHasNoBusinessPathAndRejectsTraversal(t *testing.T) {
	a, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBlobID()
	if err != nil || a == b {
		t.Fatal("independent blob IDs not generated")
	}
	p, err := BlobPath(a)
	if err != nil || p != "objects/"+a[:2]+"/"+a[2:4]+"/"+a+".blob" {
		t.Fatal("invalid opaque location")
	}
	for _, id := range []string{"", "../music/song.mp3", strings.Repeat("A", 64), strings.Repeat("a", 63) + "/", strings.Repeat("g", 64)} {
		if _, err := BlobPath(id); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid blob ID accepted")
		}
	}
}
