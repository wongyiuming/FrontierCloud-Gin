package merkleindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math"
)

// Reader is an isolated seekable verified reader. The caller must hold its
// object/version and authorization leases for its entire lifetime, enforce
// deadlines and serialize access. Close clears the bounded plaintext cache.
type Reader struct {
	ctx                   context.Context
	source                io.ReaderAt
	manifest              Manifest
	pages                 ProvenPageProvider
	pos, page, block      int64
	pageBytes, blockBytes []byte
	closed                bool
}

// NewReader verifies untrusted pages against an independently authenticated
// Master manifest, without requiring the owner's page-encryption key.
func NewReader(ctx context.Context, source io.ReaderAt, manifest Manifest, pages ProvenPageProvider) (*Reader, error) {
	if ctx == nil || source == nil || pages == nil || !validManifest(manifest) {
		return nil, ErrInvalid
	}
	return &Reader{ctx: ctx, source: source, manifest: manifest, pages: pages, page: -1, block: -1}, nil
}

func (r *Reader) Close() error {
	if r != nil {
		clear(r.pageBytes)
		clear(r.blockBytes)
		r.pageBytes, r.blockBytes = nil, nil
		r.closed = true
	}
	return nil
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	if r == nil || r.closed {
		return 0, ErrInvalid
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		base = r.manifest.Size
	default:
		return 0, ErrInvalid
	}
	if (offset > 0 && base > math.MaxInt64-offset) || (offset < 0 && base < math.MinInt64-offset) {
		return 0, ErrInvalid
	}
	next := base + offset
	if next < 0 {
		return 0, ErrInvalid
	}
	r.pos = next
	return next, nil
}

func (r *Reader) loadBlock(block int64) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	page := block / HashesPerPage
	if page != r.page {
		raw, proof, err := r.pages(r.ctx, page)
		if err != nil {
			return err
		}
		if len(raw) > maxPageBytes || len(proof) > 14 {
			return ErrInvalid
		}
		private := bytes.Clone(raw)
		if err = VerifyPage(r.manifest, page, private, append([]Hash(nil), proof...)); err != nil {
			clear(private)
			return err
		}
		clear(r.pageBytes)
		r.pageBytes, r.page = private, page
	}
	if block == r.block {
		return nil
	}
	if r.blockBytes == nil {
		r.blockBytes = make([]byte, int(BlockBytes))
	}
	clear(r.blockBytes)
	r.block = -1
	start := block * BlockBytes
	want := int(min(BlockBytes, r.manifest.Size-start))
	if n, err := r.source.ReadAt(r.blockBytes[:want], start); n != want || err != nil {
		return ErrInvalid
	}
	sum := sha256.Sum256(r.blockBytes[:want])
	offset := int((block % HashesPerPage) * sha256.Size)
	if subtle.ConstantTimeCompare(sum[:], r.pageBytes[offset:offset+sha256.Size]) != 1 {
		clear(r.blockBytes)
		return ErrInvalid
	}
	if err := r.ctx.Err(); err != nil {
		clear(r.blockBytes)
		return err
	}
	r.block = block
	return nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r == nil || r.closed {
		return 0, ErrInvalid
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos >= r.manifest.Size {
		return 0, io.EOF
	}
	written := 0
	for len(p) > 0 && r.pos < r.manifest.Size {
		block := r.pos / BlockBytes
		if err := r.loadBlock(block); err != nil {
			return written, err
		}
		offset := r.pos % BlockBytes
		available := min(BlockBytes-offset, r.manifest.Size-r.pos)
		n := copy(p, r.blockBytes[offset:offset+available])
		written += n
		p = p[n:]
		r.pos += int64(n)
	}
	return written, nil
}
