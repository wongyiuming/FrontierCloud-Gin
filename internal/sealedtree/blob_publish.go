package sealedtree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
)

// ErrBlobIncomplete does not include identifiers or filesystem paths. A
// caller must retain its authenticated, encrypted operation journal and must
// never make the new placement visible on this error.
var ErrBlobIncomplete = errors.New("sealed blob publication incomplete")

// BlobPublisher is an isolated filesystem primitive, not an application write
// path. It requires exclusive control over its root throughout publication and
// recovery. A hostile storage node can later replace or withhold bytes; every
// consumer still needs end-to-end authentication and integrity checks.
//
// The caller must durably persist an authenticated encrypted intent containing
// independent random operation and blob IDs, size, and digest before calling
// Publish. Keep the old placement until a separate fenced metadata commit and
// verification have completed. Publish never removes either link.
type BlobPublisher struct{ root *os.Root }

func NewBlobPublisher(root *os.Root) (*BlobPublisher, error) {
	if root == nil {
		return nil, ErrInvalid
	}
	return &BlobPublisher{root: root}, nil
}

func stagePath(operationID string) (string, error) {
	if !hexID(operationID) {
		return "", ErrInvalid
	}
	return path.Join("staging", operationID+".part"), nil
}

func verifyBlob(ctx context.Context, root *os.Root, name string, size int64, digest string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrBlobIncomplete
	}
	f, err := blobOpen(root, name, os.O_RDONLY, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return ErrBlobIncomplete
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, r: f}, size+1))
	if err != nil || ctx.Err() != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrBlobIncomplete
	}
	current, err := blobOpen(root, name, os.O_RDONLY, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	currentInfo, statErr := current.Stat()
	_ = current.Close()
	if statErr != nil || !os.SameFile(info, currentInfo) || currentInfo.Size() != size {
		return ErrBlobIncomplete
	}
	return nil
}

// A recovered stage may have reached the correct length before the previous
// process issued fsync. Revalidate and sync it before linking it into place.
func syncBlob(root *os.Root, name string) error {
	f, err := blobOpen(root, name, os.O_RDONLY, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return ErrBlobIncomplete
	}
	return nil
}

// Publish writes exactly the expected bytes and atomically creates a new blob
// hard link without replacing an existing object. On restart, the same IDs and
// digest recover only an already-complete stage; an incomplete or different
// stage fails closed and requires a new operation after explicit reconciliation.
// Existing destinations are accepted only after verifying their stored bytes.
// Neither a successful return nor a node's receipt proves future availability.
func (p *BlobPublisher) Publish(ctx context.Context, operationID, blobID string, size int64, digest string, src io.Reader) error {
	if err := p.Stage(ctx, operationID, blobID, size, digest, src); err != nil {
		return err
	}
	// Stage just verified the file in this call. Preserve the legacy read count;
	// the separate recovery entry point must reverify an independently staged file.
	return p.publishStaged(ctx, operationID, blobID, size, digest, false)
}

// Stage durably writes and verifies an opaque object without making the final
// blob path visible. It does not itself authorize a caller or reserve quota.
func (p *BlobPublisher) Stage(ctx context.Context, operationID, blobID string, size int64, digest string, src io.Reader) error {
	if p == nil || p.root == nil || ctx == nil || src == nil || !hexID(operationID) || !hexID(blobID) || operationID == blobID || size < 0 || size > maxObjectBytes || !hexID(digest) {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrBlobIncomplete
	}
	stage, err := stagePath(operationID)
	if err != nil {
		return ErrInvalid
	}
	dest, err := BlobPath(blobID)
	if err != nil {
		return ErrInvalid
	}
	if err = p.root.MkdirAll("staging", 0700); err != nil {
		return ErrBlobIncomplete
	}
	if err = p.root.MkdirAll(path.Dir(dest), 0700); err != nil {
		return ErrBlobIncomplete
	}
	if err = syncRootDir(p.root, "staging"); err != nil {
		return ErrBlobIncomplete
	}
	if err = syncBlobParents(p.root, blobID); err != nil {
		return ErrBlobIncomplete
	}
	file, err := blobOpen(p.root, stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(file, h), io.LimitReader(&contextReader{ctx: ctx, r: src}, size+1))
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
			return ErrBlobIncomplete
		}
		if err = syncRootDir(p.root, "staging"); err != nil {
			return ErrBlobIncomplete
		}
	} else if !errors.Is(err, os.ErrExist) {
		return ErrBlobIncomplete
	}
	if err = ctx.Err(); err != nil {
		return ErrBlobIncomplete
	}
	if verifyBlob(ctx, p.root, stage, size, digest) != nil {
		return ErrBlobIncomplete
	}
	if syncBlob(p.root, stage) != nil {
		return ErrBlobIncomplete
	}
	return nil
}

// PublishStaged makes an already verified stage visible. A selected-upload
// coordinator must keep the actual Owner policy lease held and recheck its
// admitted authorization at the publication point. This method alone does not
// authorize publication, commit Master metadata, or release a reservation.
func (p *BlobPublisher) PublishStaged(ctx context.Context, operationID, blobID string, size int64, digest string) error {
	return p.publishStaged(ctx, operationID, blobID, size, digest, true)
}

func (p *BlobPublisher) publishStaged(ctx context.Context, operationID, blobID string, size int64, digest string, reverify bool) error {
	if p == nil || p.root == nil || ctx == nil || !hexID(operationID) || !hexID(blobID) || operationID == blobID || size < 0 || size > maxObjectBytes || !hexID(digest) || ctx.Err() != nil {
		return ErrInvalid
	}
	stage, err := stagePath(operationID)
	if err != nil {
		return ErrInvalid
	}
	dest, err := BlobPath(blobID)
	if err != nil {
		return ErrInvalid
	}
	held, err := blobOpen(p.root, stage, os.O_RDONLY, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer held.Close()
	info, err := held.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return ErrBlobIncomplete
	}
	if reverify {
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, r: held}, size+1))
		if readErr != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest || held.Sync() != nil {
			return ErrBlobIncomplete
		}
	}
	if ctx.Err() != nil || blobLink(p.root, stage, dest, info, true) != nil {
		return ErrBlobIncomplete
	}
	if verifyBlob(ctx, p.root, dest, size, digest) != nil {
		return ErrBlobIncomplete
	}
	if err = syncRootDir(p.root, path.Dir(dest)); err != nil {
		return ErrBlobIncomplete
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func syncBlobParents(root *os.Root, blobID string) error {
	for _, name := range []string{".", "objects", path.Join("objects", blobID[:2]), path.Join("objects", blobID[:2], blobID[2:4])} {
		if err := syncRootDir(root, name); err != nil {
			return err
		}
	}
	return nil
}
