package merkleindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

func TestBuildReadRangeAndTampering(t *testing.T) {
	ctx := context.Background()
	data := bytes.Repeat([]byte("abcdef0123456789"), int((2*BlockBytes+113)/16+1))[:2*BlockBytes+113]
	key := bytes.Repeat([]byte{7}, 32)
	version := sha256.Sum256([]byte("synthetic version"))
	sealed := map[int64][]byte{}
	manifest, tree, err := Build(ctx, bytes.NewReader(data), int64(len(data)), version, key, func(page int64, value []byte) error {
		sealed[page] = value
		return nil
	})
	if err != nil || manifest.ContentSHA256 != sha256.Sum256(data) {
		t.Fatal("build", err)
	}
	firstBlock := sha256.Sum256(data[:BlockBytes])
	if bytes.Contains(sealed[0], firstBlock[:]) {
		t.Fatal("digest page was not sealed")
	}
	provider := func(_ context.Context, page int64) ([]byte, []Hash, error) {
		proof, err := tree.Proof(page)
		return sealed[page], proof, err
	}
	for _, tc := range []struct{ start, length int64 }{{0, 1}, {BlockBytes - 7, 19}, {2*BlockBytes + 3, 60}, {int64(len(data)), 0}} {
		var out bytes.Buffer
		if err := ReadRange(ctx, bytes.NewReader(data), key, manifest, tc.start, tc.length, provider, &out); err != nil || !bytes.Equal(out.Bytes(), data[tc.start:tc.start+tc.length]) {
			t.Fatal("range", tc, err)
		}
	}
	pageCalls := 0
	countedProvider := func(c context.Context, page int64) ([]byte, []Hash, error) { pageCalls++; return provider(c, page) }
	if err := ReadRange(ctx, bytes.NewReader(data), key, manifest, 0, int64(len(data)), countedProvider, io.Discard); err != nil || pageCalls != 1 {
		t.Fatal("same-page cache", pageCalls, err)
	}
	badData := append([]byte(nil), data...)
	badData[BlockBytes+1] ^= 1
	var out bytes.Buffer
	if err := ReadRange(ctx, bytes.NewReader(badData), key, manifest, BlockBytes, 3, provider, &out); !errors.Is(err, ErrInvalid) || out.Len() != 0 {
		t.Fatal("tampered block returned", err)
	}
	badPage := append([]byte(nil), sealed[0]...)
	badPage[len(badPage)-1] ^= 1
	badProvider := func(context.Context, int64) ([]byte, []Hash, error) { return badPage, nil, nil }
	out.Reset()
	if err := ReadRange(ctx, bytes.NewReader(data), key, manifest, 0, 1, badProvider, &out); !errors.Is(err, ErrInvalid) || out.Len() != 0 {
		t.Fatal("tampered sealed page accepted", err)
	}
	wrongVersion := manifest
	wrongVersion.Version[0] ^= 1
	if err := ReadRange(ctx, bytes.NewReader(data), key, wrongVersion, 0, 1, provider, io.Discard); !errors.Is(err, ErrInvalid) {
		t.Fatal("cross-version page accepted", err)
	}
	wrongRoot := manifest
	wrongRoot.Root[0] ^= 1
	if err := ReadRange(ctx, bytes.NewReader(data), key, wrongRoot, 0, 1, provider, io.Discard); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong root accepted", err)
	}
	if _, _, err := Build(ctx, bytes.NewReader(data[:10]), 11, version, key, func(int64, []byte) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("short source accepted", err)
	}
	if _, _, err := Build(ctx, bytes.NewReader(data[:11]), 10, version, key, func(int64, []byte) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("long source accepted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := ReadRange(cancelled, bytes.NewReader(data), key, manifest, 0, 1, provider, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored", err)
	}
}

func TestOddMerklePageMembership(t *testing.T) {
	pages := [][]byte{bytes.Repeat([]byte{1}, maxPageBytes), bytes.Repeat([]byte{2}, maxPageBytes), bytes.Repeat([]byte{3}, sha256.Size)}
	leaves := make([]Hash, len(pages))
	for i, page := range pages {
		leaves[i] = pageHash(int64(i), page)
	}
	tree := treeFromLeaves(leaves)
	manifest := Manifest{Size: (2*HashesPerPage + 1) * BlockBytes, Version: sha256.Sum256([]byte("odd version")), Root: tree.Root()}
	for i, page := range pages {
		proof, err := tree.Proof(int64(i))
		if err != nil || VerifyPage(manifest, int64(i), page, proof) != nil {
			t.Fatal("valid proof rejected", i, err)
		}
		if VerifyPage(manifest, int64(i), page, append(proof, Hash{})) == nil {
			t.Fatal("extra sibling accepted", i)
		}
	}
	proof, _ := tree.Proof(2)
	proof[0][0] ^= 1
	if VerifyPage(manifest, 2, pages[2], proof) == nil {
		t.Fatal("wrong odd-level duplicate accepted")
	}
	proof, _ = tree.Proof(0)
	if VerifyPage(manifest, 1, pages[0], proof) == nil {
		t.Fatal("page reorder accepted")
	}
}

func TestEmptyManifestAndPageSeal(t *testing.T) {
	version := sha256.Sum256([]byte("empty version"))
	key := bytes.Repeat([]byte{1}, 32)
	manifest, tree, err := Build(context.Background(), bytes.NewReader(nil), 0, version, key, func(int64, []byte) error { t.Fatal("empty page emitted"); return nil })
	if err != nil || tree.Root() != emptyRoot || manifest.ContentSHA256 != emptyContent {
		t.Fatal("empty build", err)
	}
	if err := ReadRange(context.Background(), bytes.NewReader(nil), key, manifest, 0, 0, func(context.Context, int64) ([]byte, []Hash, error) {
		t.Fatal("empty page requested")
		return nil, nil, nil
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest.Root[0] ^= 1
	if err := ReadRange(context.Background(), bytes.NewReader(nil), key, manifest, 0, 0, func(context.Context, int64) ([]byte, []Hash, error) { return nil, nil, nil }, io.Discard); !errors.Is(err, ErrInvalid) {
		t.Fatal("forged empty root accepted", err)
	}
}

type mutatingPageWriter struct {
	bytes.Buffer
	page []byte
}

func (w *mutatingPageWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	clear(w.page) // Simulate the untrusted provider reusing its output buffer.
	return n, err
}

type pageTestReaderAt struct {
	io.ReaderAt
	reads int
}

func (r *pageTestReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return r.ReaderAt.ReadAt(p, off)
}

func TestMasterVerifiesOwnerPageWithoutOwnerKey(t *testing.T) {
	ctx := context.Background()
	data := bytes.Repeat([]byte("independent page"), int(2*BlockBytes/16+2))[:2*BlockBytes+3]
	key := bytes.Repeat([]byte{9}, 32)
	version := sha256.Sum256([]byte("independent owner version"))
	var sealed []byte
	manifest, tree, err := Build(ctx, bytes.NewReader(data), int64(len(data)), version, key, func(_ int64, page []byte) error {
		sealed = page
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := openPage(key, version, 0, sealed)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.Proof(0)
	if err != nil {
		t.Fatal(err)
	}
	provider := func(context.Context, int64) ([]byte, []Hash, error) { return raw, proof, nil }
	out := &mutatingPageWriter{page: raw}
	if err := ReadRangeProven(ctx, bytes.NewReader(data), manifest, 0, int64(len(data)), provider, out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("private page copy", err)
	}
	reader := &pageTestReaderAt{ReaderAt: bytes.NewReader(data)}
	if err := ReadRangeProven(ctx, reader, manifest, 0, 1, provider, io.Discard); !errors.Is(err, ErrInvalid) || reader.reads != 0 {
		t.Fatal("tampered page reached source", err, reader.reads)
	}
	oversized := func(context.Context, int64) ([]byte, []Hash, error) { return make([]byte, maxPageBytes+1), nil, nil }
	if err := ReadRangeProven(ctx, reader, manifest, 0, 1, oversized, io.Discard); !errors.Is(err, ErrInvalid) || reader.reads != 0 {
		t.Fatal("oversized page reached source", err, reader.reads)
	}
}

func TestSeekableReaderCachesVerifiedBlocksAndFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	data := bytes.Repeat([]byte{42}, int(BlockBytes)+21)
	data[BlockBytes] = 7
	key := bytes.Repeat([]byte{3}, 32)
	version := sha256.Sum256([]byte("seek version"))
	var sealed []byte
	manifest, tree, err := Build(ctx, bytes.NewReader(data), int64(len(data)), version, key, func(_ int64, page []byte) error { sealed = page; return nil })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := openPage(key, version, 0, sealed)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := tree.Proof(0)
	readerAt := &pageTestReaderAt{ReaderAt: bytes.NewReader(data)}
	r, err := NewReader(ctx, readerAt, manifest, func(context.Context, int64) ([]byte, []Hash, error) { return raw, proof, nil })
	if err != nil {
		t.Fatal(err)
	}
	var got [4]byte
	for i := 0; i < 10; i++ {
		if _, err := io.ReadFull(r, got[:]); err != nil {
			t.Fatal(err)
		}
	}
	if readerAt.reads != 1 {
		t.Fatal("small reads reloaded block", readerAt.reads)
	}
	clear(raw) // The reader retained a verified private copy.
	if _, err := r.Seek(BlockBytes-1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, got[:]); err != nil || !bytes.Equal(got[:], data[BlockBytes-1:BlockBytes+3]) || readerAt.reads != 2 {
		t.Fatal("cross-block seek", got, readerAt.reads, err)
	}
	if _, err := r.Seek(-1, io.SeekStart); !errors.Is(err, ErrInvalid) {
		t.Fatal("negative seek", err)
	}
	if _, err := r.Seek(int64(len(data))+1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(got[:]); err != io.EOF {
		t.Fatal("seek past end", err)
	}
	cancel()
	if _, err := r.Seek(0, io.SeekStart); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(got[:]); !errors.Is(err, ErrInvalid) {
		t.Fatal("closed reader", err)
	}
}

func TestSeekableReaderRejectsTamperingAndShortReads(t *testing.T) {
	data := bytes.Repeat([]byte{17}, int(BlockBytes)+1)
	key := bytes.Repeat([]byte{5}, 32)
	version := sha256.Sum256([]byte("tamper version"))
	var sealed []byte
	manifest, tree, err := Build(context.Background(), bytes.NewReader(data), int64(len(data)), version, key, func(_ int64, page []byte) error { sealed = page; return nil })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := openPage(key, version, 0, sealed)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := tree.Proof(0)
	provider := func(context.Context, int64) ([]byte, []Hash, error) { return raw, proof, nil }
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"short", data[:20]},
		{"changed", append([]byte{99}, data[1:]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewReader(context.Background(), bytes.NewReader(tc.data), manifest, provider)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			out := []byte{123}
			if n, err := r.Read(out); n != 0 || !errors.Is(err, ErrInvalid) || out[0] != 123 {
				t.Fatal("unverified bytes exposed", n, err, out)
			}
		})
	}
	badPage := bytes.Clone(raw)
	badPage[0] ^= 1
	counted := &pageTestReaderAt{ReaderAt: bytes.NewReader(data)}
	r, err := NewReader(context.Background(), counted, manifest, func(context.Context, int64) ([]byte, []Hash, error) { return badPage, proof, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrInvalid) || counted.reads != 0 {
		t.Fatal("bad page reached source", n, err, counted.reads)
	}
}
