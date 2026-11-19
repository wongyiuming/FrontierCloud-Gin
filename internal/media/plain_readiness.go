package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ProbeVerifiedPlain performs a bounded synthetic read through the same index
// and verified chunk reader used by the owner data handler. It never examines
// user objects or establishes authorization for a browser request.
func (s *Service) ProbeVerifiedPlain(ctx context.Context) error {
	if s == nil {
		return store.ErrNodeState
	}
	free, err := s.acquirePlainRead(ctx)
	if err != nil {
		return err
	}
	defer free()
	f, err := os.CreateTemp("", "frontiercloud-plain-probe-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	data := protocol.PlainProbeFixture()
	if _, err := f.Write(data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	// Use a separate ephemeral cache so a large user-object index build cannot
	// hold the probe behind its build lock or evict real object proofs.
	probe := &Service{}
	index, err := probe.verifiedPlainIndex(ctx, f, strings.Repeat("0", 64), hex.EncodeToString(sum[:]), int64(len(data)))
	if err != nil {
		return err
	}
	reader := &verifiedPlainReader{ctx: ctx, file: f, index: index, loaded: -1}
	if _, err = reader.Seek(plainChunkBytes-4, io.SeekStart); err != nil {
		return err
	}
	result := make([]byte, 12)
	if _, err = io.ReadFull(reader, result); err != nil || !bytes.Equal(result, data[plainChunkBytes-4:plainChunkBytes+8]) {
		return store.ErrNodeState
	}
	if _, err = f.WriteAt([]byte("X"), plainChunkBytes+1); err != nil {
		return err
	}
	changed := &verifiedPlainReader{ctx: ctx, file: f, index: index, loaded: -1}
	if _, err = changed.Seek(plainChunkBytes+1, io.SeekStart); err != nil {
		return err
	}
	if n, err := changed.Read(result); n != 0 || !errors.Is(err, store.ErrNodeState) {
		return store.ErrNodeState
	}
	return nil
}

// ProbeVerifiedOpaqueBlob exercises the actual opaque locator and verified
// reader against disposable synthetic bytes, without reading the user tree.
func (s *Service) ProbeVerifiedOpaqueBlob(ctx context.Context) error {
	if s == nil {
		return store.ErrNodeState
	}
	release, err := s.acquirePlainRead(ctx)
	if err != nil {
		return err
	}
	defer release()
	dir, err := os.MkdirTemp("", "frontiercloud-opaque-probe-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	blob := strings.Repeat("1", 64)
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		return err
	}
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		return err
	}
	data := protocol.PlainProbeFixture()
	if err = os.WriteFile(full, data, 0600); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	probe := &Service{root: root, identity: s.identity}
	digest := hex.EncodeToString(sum[:])
	alias := strings.Repeat("2", 64)
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(data)), nil)
	if err != nil {
		return err
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(alias, blob, digest, descriptor, int64(len(data)))
	if err != nil {
		return err
	}
	binding := OpaqueOwnerBinding{MasterID: strings.Repeat("3", 32), OwnerID: strings.Repeat("4", 32), RelationshipID: strings.Repeat("5", 32), Alias: alias, Blob: blob, Revision: revision, Digest: digest, Descriptor: descriptor, Size: int64(len(data))}
	if err = probe.registerOpaqueOwnerBinding(ctx, binding, false); err != nil {
		return err
	}
	opened, err := probe.openVerifiedOpaqueBlob(ctx, blob, digest, int64(len(data)), false, &binding)
	if err != nil {
		return err
	}
	defer opened.Close()
	if _, err = opened.Reader.Seek(plainChunkBytes-4, io.SeekStart); err != nil {
		return err
	}
	result := make([]byte, 12)
	if _, err = io.ReadFull(opened.Reader, result); err != nil || !bytes.Equal(result, data[plainChunkBytes-4:plainChunkBytes+8]) {
		return store.ErrNodeState
	}
	opened.Close()
	data[plainChunkBytes+1] ^= 0xff
	if err = os.WriteFile(full, data, 0600); err != nil {
		return err
	}
	replaced, err := probe.openVerifiedOpaqueBlob(ctx, blob, digest, int64(len(data)), false, &binding)
	if err != nil {
		return err
	}
	defer replaced.Close()
	if _, err = replaced.Reader.Seek(plainChunkBytes, io.SeekStart); err != nil {
		return err
	}
	if n, err := replaced.Reader.Read(result); n != 0 || !errors.Is(err, store.ErrNodeState) {
		return store.ErrNodeState
	}
	replaced.Close()
	if err := probe.RevokeOpaqueOwnerBinding(ctx, strings.Repeat("6", 32), binding); err != nil {
		return err
	}
	if denied, err := probe.openVerifiedOpaqueBlob(ctx, blob, digest, int64(len(data)), false, &binding); err == nil {
		denied.Close()
		return store.ErrNodeState
	}
	return nil
}
