package media

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueBlob retains the volume read lock and bounded read slot until Close.
// The method that opens it determines whether Reader is content-verified or
// ciphertext that the browser must authenticate before releasing plaintext.
type OpaqueBlob struct {
	Reader io.ReadSeeker
	Info   os.FileInfo
	close  func()
}

func (b *OpaqueBlob) Close() {
	if b != nil && b.close != nil {
		b.close()
	}
}

// VerifiedOpaqueBlob preserves the existing verified-reader API name.
type VerifiedOpaqueBlob = OpaqueBlob

// OpenVerifiedOpaqueBlob is a storage primitive, not an authorization API.
// blob, digest and size must come from a verified Master capability. It never
// accepts or resolves a logical name, and it does not bypass chunk integrity
// for encrypted data. The caller must close the result on every path.
func (s *Service) OpenVerifiedOpaqueBlob(ctx context.Context, blob, digest string, size int64) (*VerifiedOpaqueBlob, error) {
	return s.openVerifiedOpaqueBlob(ctx, blob, digest, size, true, nil)
}

// OpenAuthorizedOpaqueBlob also enforces the durable owner alias state under
// the same volume lease held throughout the content-verified read.
func (s *Service) OpenAuthorizedOpaqueBlob(ctx context.Context, binding OpaqueOwnerBinding) (*VerifiedOpaqueBlob, error) {
	if !validOpaqueOwnerBinding(binding) {
		return nil, store.ErrNodeState
	}
	return s.openVerifiedOpaqueBlob(ctx, binding.Blob, binding.Digest, binding.Size, true, &binding)
}

func (s *Service) openVerifiedOpaqueBlob(ctx context.Context, blob, digest string, size int64, checkReady bool, binding *OpaqueOwnerBinding) (*VerifiedOpaqueBlob, error) {
	return s.openOpaqueBlob(ctx, blob, digest, size, checkReady, binding, true)
}

// OpaqueBrowserCipher contains ciphertext only. Its caller must establish the
// complete descriptor from the trusted Master and authenticate every chunk in
// the browser before releasing plaintext. It is not a content proof for
// migration, backup, or any server-side plaintext consumer.
type OpaqueBrowserCipher = OpaqueBlob

type recordingCipherHandle struct{ blob *OpaqueBlob }

func (h *recordingCipherHandle) Read(p []byte) (int, error) { return h.blob.Reader.Read(p) }
func (h *recordingCipherHandle) Seek(offset int64, whence int) (int64, error) {
	return h.blob.Reader.Seek(offset, whence)
}
func (h *recordingCipherHandle) Close() error { h.blob.Close(); return nil }

// OpenRecordingBrowserCipher is a trusted-runtime storage primitive, not an
// authorization API. The caller must obtain all arguments from an authenticated
// Master recording intent and validate the Owner and account under the proper
// fences. The browser must authenticate every encrypted chunk before use. The
// returned handle retains the media volume read lease until Close.
func (s *Service) OpenRecordingBrowserCipher(ctx context.Context, blob, digest string, size int64) (io.ReadSeekCloser, error) {
	if size <= 0 {
		return nil, store.ErrNodeState
	}
	b, err := s.openOpaqueBlob(ctx, blob, digest, size, true, nil, false)
	if err != nil {
		return nil, err
	}
	return &recordingCipherHandle{blob: b}, nil
}

// OpenAuthorizedOpaqueBrowserCipher is only for an authenticated v5 browser
// ciphertext capability. A v5 descriptor is computed and signed by the
// trusted Master after validating complete encryption metadata. A plaintext
// descriptor is rejected here; opaque binding and volume locks remain held.
func (s *Service) OpenAuthorizedOpaqueBrowserCipher(ctx context.Context, binding OpaqueOwnerBinding) (*OpaqueBrowserCipher, error) {
	plain, err := protocol.IngressMediaDescriptor(binding.Size, nil)
	if err != nil || !validOpaqueOwnerBinding(binding) || binding.Size <= 0 || binding.Descriptor == plain {
		return nil, store.ErrNodeState
	}
	return s.openOpaqueBlob(ctx, binding.Blob, binding.Digest, binding.Size, true, &binding, false)
}

type contextOpaqueCipherReader struct {
	ctx  context.Context
	file *os.File
	err  error
}

func (r *contextOpaqueCipherReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		r.err = err
		return 0, err
	}
	n, err := r.file.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func (r *contextOpaqueCipherReader) Seek(offset int64, whence int) (int64, error) {
	if err := r.ctx.Err(); err != nil {
		r.err = err
		return 0, err
	}
	position, err := r.file.Seek(offset, whence)
	if err != nil {
		r.err = err
	}
	return position, err
}

func (r *contextOpaqueCipherReader) Err() error { return r.err }

func (s *Service) openOpaqueBlob(ctx context.Context, blob, digest string, size int64, checkReady bool, binding *OpaqueOwnerBinding, verify bool) (*VerifiedOpaqueBlob, error) {
	if s == nil || ctx == nil || !ownedObjectID.MatchString(blob) || !ownedObjectID.MatchString(digest) || size < 0 || size > 10*store.GiB {
		return nil, store.ErrNodeState
	}
	slot, err := s.acquirePlainRead(ctx)
	if err != nil {
		return nil, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		slot()
		return nil, err
	}
	fail := func(err error) (*VerifiedOpaqueBlob, error) { release(); slot(); return nil, err }
	if checkReady {
		if err = s.ready(); err != nil {
			return fail(err)
		}
	}
	if binding != nil {
		if err = s.checkOpaqueOwnerBindingLocked(*binding); err != nil {
			return fail(err)
		}
	}
	parent, err := openOpaqueBlobParent(s.root, blob)
	if err != nil {
		return fail(err)
	}
	before, err := parent.Leaf().Lstat(blob + ".blob")
	if err != nil || !before.Mode().IsRegular() {
		parent.Close()
		return fail(store.ErrNodeState)
	}
	file, err := parent.Leaf().Open(blob + ".blob")
	if err != nil {
		parent.Close()
		return fail(err)
	}
	failFile := func(err error) (*VerifiedOpaqueBlob, error) { _ = file.Close(); parent.Close(); return fail(err) }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() != size {
		return failFile(store.ErrNodeState)
	}
	var reader io.ReadSeeker
	if verify {
		index, err := s.verifiedPlainIndex(ctx, file, blob, digest, size)
		if err != nil {
			return failFile(err)
		}
		reader = &verifiedPlainReader{ctx: ctx, file: file, index: index, loaded: -1}
	} else {
		reader = &contextOpaqueCipherReader{ctx: ctx, file: file}
	}
	if err = ctx.Err(); err != nil {
		return failFile(err)
	}
	if err = parent.Check(); err != nil {
		return failFile(err)
	}
	var once sync.Once
	return &VerifiedOpaqueBlob{Reader: reader, Info: info, close: func() {
		once.Do(func() { _ = file.Close(); parent.Close(); release(); slot() })
	}}, nil
}
