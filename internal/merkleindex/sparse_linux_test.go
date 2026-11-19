//go:build linux

package merkleindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"syscall"
	"testing"
)

type countedReaderAt struct {
	file  *os.File
	bytes int64
}

func (r *countedReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.file.ReadAt(p, offset)
	r.bytes += int64(n)
	return n, err
}

// This creates an empty sparse 10 TiB logical file and writes only a few bytes.
// Synthetic page hashes/root are used to test bounded high-offset mechanics;
// it is not evidence that a full-object digest or durable index was produced.
func TestSparseTenTiBRangeProof(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sparse-*.blob")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(MaxPlainBytes); err != nil {
		t.Skipf("filesystem cannot represent sparse 10 TiB fixture: %v", err)
	}
	start := int64(9<<40) + 12345
	payload := []byte("synthetic high offset bytes")
	if _, err := f.WriteAt(payload, start); err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks*512 > 8<<20 {
		t.Fatal("fixture did not remain sparse")
	}
	block := start / BlockBytes
	pageIndex := block / HashesPerPage
	blockBytes := make([]byte, int(BlockBytes))
	if n, err := f.ReadAt(blockBytes, block*BlockBytes); n != len(blockBytes) || err != nil {
		t.Fatal(n, err)
	}
	actual := sha256.Sum256(blockBytes)
	zero := sha256.Sum256(make([]byte, int(BlockBytes)))
	raw := make([]byte, maxPageBytes)
	for i := int64(0); i < HashesPerPage; i++ {
		copy(raw[i*sha256.Size:], zero[:])
	}
	copy(raw[(block%HashesPerPage)*sha256.Size:], actual[:])
	_, pageCount, err := counts(MaxPlainBytes)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]Hash, pageCount)
	for i := range leaves {
		leaves[i] = sha256.Sum256([]byte{byte(i), byte(i >> 8)})
	}
	leaves[pageIndex] = pageHash(pageIndex, raw)
	tree := treeFromLeaves(leaves)
	proof, err := tree.Proof(pageIndex)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) > 14 {
		t.Fatal("unbounded proof", len(proof))
	}
	key := bytes.Repeat([]byte{9}, 32)
	version := sha256.Sum256([]byte("sparse fixture"))
	sealed, err := SealPage(key, version, pageIndex, raw)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Size: MaxPlainBytes, Version: version, Root: tree.Root()}
	provider := func(_ context.Context, page int64) ([]byte, []Hash, error) {
		if page != pageIndex {
			return nil, nil, ErrInvalid
		}
		return sealed, proof, nil
	}
	counted := &countedReaderAt{file: f}
	var out bytes.Buffer
	if err := ReadRange(context.Background(), counted, key, manifest, start, int64(len(payload)), provider, &out); err != nil || !bytes.Equal(out.Bytes(), payload) || counted.bytes != BlockBytes {
		t.Fatal("sparse range", err, counted.bytes)
	}
	broken := append([]Hash(nil), proof...)
	broken[0][0] ^= 1
	bad := func(context.Context, int64) ([]byte, []Hash, error) { return sealed, broken, nil }
	out.Reset()
	counted.bytes = 0
	if err := ReadRange(context.Background(), counted, key, manifest, start, int64(len(payload)), bad, &out); !errors.Is(err, ErrInvalid) || out.Len() != 0 || counted.bytes != 0 {
		t.Fatal("unverified page caused output or object IO", err)
	}
}
