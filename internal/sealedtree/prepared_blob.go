package sealedtree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
)

// PreparedBlob is a same-process optimization for a freshly created stage.
// The coordinator must hold its real exclusive Owner filesystem lock and policy
// lease from before Prepare until after Publish or Close. This type does not
// authorize the operation or protect against a hostile Owner administrator.
// Recovery after process death must use PublishStaged, which rereads the file.
type PreparedBlob struct {
	publisher           *BlobPublisher
	file                *os.File
	info                os.FileInfo
	operationID, blobID string
	size                int64
	published           bool
}

// Prepare performs one pass over src. The hash writer runs only after the file
// writer accepted each full chunk; any short write or error fails closed.
func (p *BlobPublisher) Prepare(ctx context.Context, operationID, blobID string, size int64, digest string, src io.Reader) (out *PreparedBlob, err error) {
	if p == nil || p.root == nil || ctx == nil || ctx.Err() != nil || src == nil || !hexID(operationID) || !hexID(blobID) || operationID == blobID || size < 0 || size > maxObjectBytes || !hexID(digest) {
		return nil, ErrInvalid
	}
	stage, e := stagePath(operationID)
	if e != nil {
		return nil, ErrInvalid
	}
	dest, e := BlobPath(blobID)
	if e != nil {
		return nil, ErrInvalid
	}
	if p.root.MkdirAll("staging", 0700) != nil || p.root.MkdirAll(path.Dir(dest), 0700) != nil || syncRootDir(p.root, "staging") != nil || syncBlobParents(p.root, blobID) != nil {
		return nil, ErrBlobIncomplete
	}
	f, e := blobOpen(p.root, stage, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, ErrBlobIncomplete
	}
	defer func() {
		if out == nil {
			_ = f.Close()
		}
	}()
	if copyPreparedBytes(ctx, f, src, size, digest) != nil || f.Sync() != nil {
		return nil, ErrBlobIncomplete
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != size || syncRootDir(p.root, "staging") != nil || ctx.Err() != nil {
		return nil, ErrBlobIncomplete
	}
	return &PreparedBlob{publisher: p, file: f, info: info, operationID: operationID, blobID: blobID, size: size}, nil
}

func copyPreparedBytes(ctx context.Context, dst io.Writer, src io.Reader, size int64, digest string) error {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(&contextReader{ctx: ctx, r: src}, size+1))
	if err != nil || n != size || ctx.Err() != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrBlobIncomplete
	}
	return nil
}

// Publish links the exact still-held inode; preexisting or replaced paths fail
// closed and must go through the full re-verifying recovery path. The caller
// must perform final lease/context checks while retaining its filesystem fence.
func (b *PreparedBlob) Publish(ctx context.Context) error {
	if b == nil || b.publisher == nil || b.file == nil || b.published || ctx == nil || ctx.Err() != nil {
		return ErrBlobIncomplete
	}
	root := b.publisher.root
	stage, e := stagePath(b.operationID)
	if e != nil {
		return ErrBlobIncomplete
	}
	dest, e := BlobPath(b.blobID)
	if e != nil {
		return ErrBlobIncomplete
	}
	held, e := b.file.Stat()
	if e != nil || !os.SameFile(b.info, held) || held.Size() != b.size || !held.ModTime().Equal(b.info.ModTime()) {
		return ErrBlobIncomplete
	}
	current, e := blobOpen(root, stage, os.O_RDONLY, 0)
	if e != nil {
		return ErrBlobIncomplete
	}
	currentInfo, e := current.Stat()
	_ = current.Close()
	if e != nil || !os.SameFile(held, currentInfo) || currentInfo.Size() != b.size || !currentInfo.ModTime().Equal(b.info.ModTime()) || ctx.Err() != nil {
		return ErrBlobIncomplete
	}
	if blobLink(root, stage, dest, held, false) != nil {
		return ErrBlobIncomplete
	}
	target, e := blobOpen(root, dest, os.O_RDONLY, 0)
	if e != nil {
		return ErrBlobIncomplete
	}
	targetInfo, e := target.Stat()
	_ = target.Close()
	if e != nil || !os.SameFile(held, targetInfo) || targetInfo.Size() != b.size || !targetInfo.ModTime().Equal(b.info.ModTime()) || syncRootDir(root, path.Dir(dest)) != nil {
		return ErrBlobIncomplete
	}
	b.published = true
	return nil
}

func (b *PreparedBlob) Close() error {
	if b == nil || b.file == nil {
		return nil
	}
	err := b.file.Close()
	b.file = nil
	return err
}
