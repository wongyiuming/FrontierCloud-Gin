// Package merkleindex contains an isolated, bounded-memory prototype for
// authenticating plaintext byte ranges. It is not wired into upload, import,
// owner storage, readiness or public serving.
package merkleindex

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

const BlockBytes int64 = 1 << 20
const HashesPerPage int64 = 1024
const MaxPlainBytes int64 = 10 << 40
const maxPageBytes = int(HashesPerPage) * sha256.Size

var ErrInvalid = errors.New("invalid authenticated range index")

type Hash [sha256.Size]byte

// Manifest must be bound by the Master to the exact owner, random blob,
// immutable version and authorization lifecycle. A root supplied only by the
// resource owner is not authority. Version must be independently random.
type Manifest struct {
	Size          int64
	ContentSHA256 Hash
	Root          Hash
	Version       Hash
}

func counts(size int64) (blocks, pages int64, err error) {
	if size < 0 || size > MaxPlainBytes {
		return 0, 0, ErrInvalid
	}
	blocks = size / BlockBytes
	if size%BlockBytes != 0 {
		blocks++
	}
	pages = blocks / HashesPerPage
	if blocks%HashesPerPage != 0 {
		pages++
	}
	return blocks, pages, nil
}

func pageHash(index int64, raw []byte) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:range-index:page:v1\x00"))
	var value [16]byte
	binary.BigEndian.PutUint64(value[:8], uint64(index))
	binary.BigEndian.PutUint64(value[8:], uint64(len(raw)))
	_, _ = h.Write(value[:])
	_, _ = h.Write(raw)
	var sum Hash
	copy(sum[:], h.Sum(nil))
	return sum
}

func parentHash(left, right Hash) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:range-index:node:v1\x00"))
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var sum Hash
	copy(sum[:], h.Sum(nil))
	return sum
}

var emptyRoot = sha256.Sum256([]byte("frontiercloud:range-index:empty:v1\x00"))
var emptyContent = sha256.Sum256(nil)

func validManifest(manifest Manifest) bool {
	if _, _, err := counts(manifest.Size); err != nil || manifest.Version == (Hash{}) {
		return false
	}
	if manifest.Size == 0 {
		return manifest.Root == emptyRoot && manifest.ContentSHA256 == emptyContent
	}
	return manifest.Root != (Hash{})
}

// Tree holds only page hashes and internal nodes, not the chunk-hash pages.
// At the 10 TiB limit this is less than 1 MiB. The caller must protect any
// persisted tree nodes and publish them atomically with sealed pages.
type Tree struct{ levels [][]Hash }

func treeFromLeaves(leaves []Hash) *Tree {
	if len(leaves) == 0 {
		return &Tree{}
	}
	level := append([]Hash(nil), leaves...)
	tree := &Tree{levels: [][]Hash{level}}
	for len(level) > 1 {
		next := make([]Hash, (len(level)+1)/2)
		for i := range next {
			left := level[2*i]
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			next[i] = parentHash(left, right)
		}
		tree.levels = append(tree.levels, next)
		level = next
	}
	return tree
}

func (t *Tree) Root() Hash {
	if t == nil || len(t.levels) == 0 {
		return emptyRoot
	}
	return t.levels[len(t.levels)-1][0]
}

func (t *Tree) Proof(page int64) ([]Hash, error) {
	if t == nil || len(t.levels) == 0 || page < 0 || page >= int64(len(t.levels[0])) {
		return nil, ErrInvalid
	}
	result := make([]Hash, 0, len(t.levels)-1)
	index := int(page)
	for _, level := range t.levels[:len(t.levels)-1] {
		sibling := index ^ 1
		if sibling >= len(level) {
			sibling = index
		}
		result = append(result, level[sibling])
		index /= 2
	}
	return result, nil
}

// Build consumes exactly size bytes once. emit receives only independently
// sealed digest pages. Pages are staged, not authorized: the caller must
// compare ContentSHA256 with its trusted expectation before publishing any
// manifest. A failed read, emit or cancellation yields no valid manifest.
// The caller must provide hard source deadlines and durable staged publication.
func Build(ctx context.Context, src io.Reader, size int64, version Hash, key []byte, emit func(int64, []byte) error) (Manifest, *Tree, error) {
	var empty Manifest
	blocks, pages, err := counts(size)
	if err != nil || ctx == nil || src == nil || emit == nil || version == (Hash{}) || len(key) != 32 {
		return empty, nil, ErrInvalid
	}
	buf := make([]byte, int(BlockBytes))
	defer clear(buf)
	page := make([]byte, 0, maxPageBytes)
	defer clear(page)
	leaves := make([]Hash, 0, int(pages))
	whole := sha256.New()
	remaining := size
	for block := int64(0); block < blocks; block++ {
		if err := ctx.Err(); err != nil {
			return empty, nil, err
		}
		want := int(min(BlockBytes, remaining))
		if _, err := io.ReadFull(src, buf[:want]); err != nil {
			return empty, nil, ErrInvalid
		}
		_, _ = whole.Write(buf[:want])
		sum := sha256.Sum256(buf[:want])
		page = append(page, sum[:]...)
		remaining -= int64(want)
		if len(page) == maxPageBytes || block == blocks-1 {
			index := int64(len(leaves))
			leaf := pageHash(index, page)
			sealed, err := SealPage(key, version, index, page)
			if err != nil {
				return empty, nil, err
			}
			if err := emit(index, sealed); err != nil {
				return empty, nil, err
			}
			leaves = append(leaves, leaf)
			clear(page)
			page = page[:0]
		}
	}
	var extra [1]byte
	if n, err := io.ReadFull(src, extra[:]); n != 0 || err != io.EOF {
		return empty, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	tree := treeFromLeaves(leaves)
	manifest := Manifest{Size: size, Root: tree.Root(), Version: version}
	copy(manifest.ContentSHA256[:], whole.Sum(nil))
	return manifest, tree, nil
}

func pageAAD(version Hash, page int64) []byte {
	aad := append([]byte("frontiercloud:range-index:sealed-page:v1\x00"), version[:]...)
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(page))
	return append(aad, index[:]...)
}

// SealPage uses an independently managed owner-local key; it must not be the
// Master tree key, media encryption key or a browser-provided secret.
func SealPage(key []byte, version Hash, page int64, raw []byte) ([]byte, error) {
	if len(key) != 32 || version == (Hash{}) || page < 0 || len(raw) == 0 || len(raw) > maxPageBytes || len(raw)%sha256.Size != 0 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, raw, pageAAD(version, page)), nil
}

func openPage(key []byte, version Hash, page int64, sealed []byte) ([]byte, error) {
	if len(key) != 32 || version == (Hash{}) || page < 0 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() || len(sealed) > aead.NonceSize()+aead.Overhead()+maxPageBytes {
		return nil, ErrInvalid
	}
	raw, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], pageAAD(version, page))
	if err != nil {
		return nil, ErrInvalid
	}
	return raw, nil
}

// VerifyPage authenticates both page contents and membership against the
// Master-bound root. It rejects reordered, omitted, extra and cross-version
// pages, including malformed duplicate siblings at an odd tree level.
func VerifyPage(manifest Manifest, page int64, raw []byte, proof []Hash) error {
	blocks, pages, err := counts(manifest.Size)
	if err != nil || !validManifest(manifest) || page < 0 || page >= pages {
		return ErrInvalid
	}
	expected := min(HashesPerPage, blocks-page*HashesPerPage)
	if int64(len(raw)) != expected*sha256.Size {
		return ErrInvalid
	}
	value, width, index, depth := pageHash(page, raw), pages, page, 0
	for width > 1 {
		if depth >= len(proof) {
			return ErrInvalid
		}
		sibling := proof[depth]
		if index%2 == 0 {
			if index+1 >= width && subtle.ConstantTimeCompare(value[:], sibling[:]) != 1 {
				return ErrInvalid
			}
			value = parentHash(value, sibling)
		} else {
			value = parentHash(sibling, value)
		}
		index /= 2
		width = (width + 1) / 2
		depth++
	}
	if depth != len(proof) || subtle.ConstantTimeCompare(value[:], manifest.Root[:]) != 1 {
		return ErrInvalid
	}
	return nil
}

type PageProvider func(context.Context, int64) (sealed []byte, proof []Hash, err error)

// ProvenPageProvider supplies a decrypted page and its Merkle proof from an
// untrusted owner over a separately authenticated transport. The caller must
// bind the manifest to the authorized owner, blob and immutable version.
type ProvenPageProvider func(context.Context, int64) (raw []byte, proof []Hash, err error)

// ReadRange authenticates each page and full 1 MiB block before writing any
// bytes from that block. It retains at most one block and one page. Failure
// after earlier blocks requires the HTTP caller to abort, not claim success.
func ReadRange(ctx context.Context, source io.ReaderAt, key []byte, manifest Manifest, start, length int64, pages PageProvider, dst io.Writer) error {
	if pages == nil || len(key) != 32 {
		return ErrInvalid
	}
	return readRange(ctx, source, manifest, start, length, func(ctx context.Context, page int64) ([]byte, []Hash, error) {
		sealed, proof, err := pages(ctx, page)
		if err != nil {
			return nil, nil, err
		}
		raw, err := openPage(key, manifest.Version, page, sealed)
		return raw, proof, err
	}, dst, true)
}

// ReadRangeProven allows the Master to verify pages without possessing the
// owner's encryption key. The returned page and proof are treated as
// untrusted, copied into bounded private storage, and verified against the
// Master-bound root before any corresponding object bytes are emitted.
func ReadRangeProven(ctx context.Context, source io.ReaderAt, manifest Manifest, start, length int64, pages ProvenPageProvider, dst io.Writer) error {
	return readRange(ctx, source, manifest, start, length, pages, dst, false)
}

func readRange(ctx context.Context, source io.ReaderAt, manifest Manifest, start, length int64, pages ProvenPageProvider, dst io.Writer, ownsPage bool) error {
	_, _, err := counts(manifest.Size)
	if err != nil || !validManifest(manifest) || ctx == nil || source == nil || dst == nil || pages == nil || start < 0 || length < 0 || start > manifest.Size || length > manifest.Size-start {
		return ErrInvalid
	}
	if length == 0 {
		return ctx.Err()
	}
	buf := make([]byte, int(BlockBytes))
	defer clear(buf)
	var cachedPage []byte
	defer func() { clear(cachedPage) }()
	lastPage := int64(-1)
	end := start + length
	for pos := start; pos < end; {
		if err := ctx.Err(); err != nil {
			return err
		}
		block := pos / BlockBytes
		page := block / HashesPerPage
		if page != lastPage {
			clear(cachedPage)
			cachedPage = nil
			raw, proof, err := pages(ctx, page)
			if err != nil {
				return err
			}
			// 10 TiB requires at most 10,240 pages and 14 proof nodes.
			if len(raw) > maxPageBytes || len(proof) > 14 {
				if ownsPage {
					clear(raw)
				}
				return ErrInvalid
			}
			cachedPage = bytes.Clone(raw)
			if ownsPage {
				clear(raw)
			}
			privateProof := append([]Hash(nil), proof...)
			if err = VerifyPage(manifest, page, cachedPage, privateProof); err != nil {
				return err
			}
			lastPage = page
		}
		offset := int((block % HashesPerPage) * sha256.Size)
		var expected Hash
		copy(expected[:], cachedPage[offset:offset+sha256.Size])
		blockStart := block * BlockBytes
		want := int(min(BlockBytes, manifest.Size-blockStart))
		if n, err := source.ReadAt(buf[:want], blockStart); n != want || err != nil {
			return ErrInvalid
		}
		actual := sha256.Sum256(buf[:want])
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			return ErrInvalid
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		from := pos - blockStart
		until := min(int64(want), end-blockStart)
		for chunk := buf[from:until]; len(chunk) > 0; {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := dst.Write(chunk)
			if n < 0 || n > len(chunk) {
				return ErrInvalid
			}
			chunk = chunk[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		pos = blockStart + until
	}
	return nil
}
