package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const opaqueRegistryDirectory = ".opaque-aliases"

// OpaqueOwnerBinding is accepted only from an authenticated Master, never a
// browser. Registry lifecycle is not yet wired into product startup.
type OpaqueOwnerBinding = protocol.OpaqueOwnerBinding

type opaqueRevocation struct {
	OperationID string             `json:"operation_id"`
	Binding     OpaqueOwnerBinding `json:"binding"`
}

func validOpaqueOwnerBinding(b OpaqueOwnerBinding) bool {
	return b.Valid()
}

func (s *Service) opaqueRegistryDir(create bool) error {
	if create {
		if err := s.root.Mkdir(opaqueRegistryDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return store.ErrNodeState
		}
	}
	info, err := s.root.Lstat(opaqueRegistryDirectory)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return store.ErrNodeState
	}
	if create && s.syncDirectory(".") != nil {
		return store.ErrNodeState
	}
	return nil
}

func opaqueRegistryFile(alias, suffix string) string {
	return path.Join(opaqueRegistryDirectory, alias+suffix)
}

func opaqueBlobReservation(blob string) string {
	return path.Join(opaqueRegistryDirectory, ".blob-"+blob+".reserved")
}

func (s *Service) readOpaqueRecord(name string, target any) error {
	info, err := s.root.Lstat(name)
	if err != nil {
		return err
	}
	if s.identity == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8192 {
		return store.ErrNodeState
	}
	f, err := s.root.Open(name)
	if err != nil {
		return store.ErrNodeState
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return store.ErrNodeState
	}
	sealed, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(sealed) > 8192 {
		return store.ErrNodeState
	}
	raw, err := s.identity.OpenOpaqueOwnerRecord(name, string(sealed))
	if err != nil {
		return store.ErrNodeState
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return store.ErrNodeState
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return store.ErrNodeState
	}
	return nil
}

// writeOpaqueRecordLocked never replaces a record. Replaying identical data
// re-syncs it before acknowledging, covering a crash after create but before
// the original caller received an acknowledgement.
func (s *Service) writeOpaqueRecordLocked(name string, record any) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 2048 || s.identity == nil {
		return store.ErrNodeState
	}
	newSealed, err := s.identity.SealOpaqueOwnerRecord(name, raw)
	if err != nil {
		return store.ErrNodeState
	}
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = s.root.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			return store.ErrNodeState
		}
		info, statErr := f.Stat()
		current, pathErr := s.root.Lstat(name)
		if statErr != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || info.Size() <= 0 || info.Size() > 8192 {
			f.Close()
			return store.ErrNodeState
		}
		sealed, readErr := io.ReadAll(io.LimitReader(f, 8193))
		existing, openErr := s.identity.OpenOpaqueOwnerRecord(name, string(sealed))
		if readErr != nil || openErr != nil || !bytes.Equal(existing, raw) {
			f.Close()
			return store.ErrNodeState
		}
	} else if err != nil {
		return store.ErrNodeState
	} else {
		if n, writeErr := f.WriteString(newSealed); writeErr != nil || n != len(newSealed) {
			f.Close()
			return store.ErrNodeState
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return store.ErrNodeState
	}
	if err := f.Close(); err != nil {
		return store.ErrNodeState
	}
	if err := s.syncDirectory(opaqueRegistryDirectory); err != nil {
		return store.ErrNodeState
	}
	return nil
}

// RegisterOpaqueOwnerBinding validates the complete blob before publishing an
// immutable alias binding. It acquires the same exclusive owner volume fence
// used by revocation and legacy writes; callers authenticate Master first.
func (s *Service) RegisterOpaqueOwnerBinding(ctx context.Context, binding OpaqueOwnerBinding) error {
	return s.registerOpaqueOwnerBinding(ctx, binding, true)
}

func (s *Service) registerOpaqueOwnerBinding(ctx context.Context, binding OpaqueOwnerBinding, checkReady bool) error {
	if s == nil || ctx == nil || !validOpaqueOwnerBinding(binding) {
		return store.ErrNodeState
	}
	release, err := s.acquire(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	if checkReady {
		if err := s.ready(); err != nil {
			return err
		}
	}
	if err := s.opaqueRegistryDir(true); err != nil {
		return err
	}
	if _, err := s.root.Lstat(opaqueRegistryFile(binding.Alias, ".revoked")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return store.ErrNodeState
	}
	parent, err := openOpaqueBlobParent(s.root, binding.Blob)
	if err != nil {
		return err
	}
	defer parent.Close()
	before, err := parent.Leaf().Lstat(binding.Blob + ".blob")
	if err != nil || !before.Mode().IsRegular() {
		return store.ErrNodeState
	}
	f, err := parent.Leaf().Open(binding.Blob + ".blob")
	if err != nil {
		return store.ErrNodeState
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() != binding.Size {
		return store.ErrNodeState
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(&contextReader{ctx, f}, binding.Size+1), make([]byte, 64<<10))
	if err != nil || n != binding.Size || hex.EncodeToString(hash.Sum(nil)) != binding.Digest || ctx.Err() != nil || parent.Check() != nil {
		return store.ErrNodeState
	}
	// Reservation precedes activation and is permanent. A crash can leave an
	// unused reservation, but never permits another alias to claim this blob.
	if err := s.writeOpaqueRecordLocked(opaqueBlobReservation(binding.Blob), binding); err != nil {
		return err
	}
	return s.writeOpaqueRecordLocked(opaqueRegistryFile(binding.Alias, ".active"), binding)
}

// RevokeOpaqueOwnerBinding durably denies subsequent reads before returning.
// A different operation ID cannot overwrite an existing tombstone. Long reads
// retain a shared volume lease; a caller's context bounds the wait for them.
func (s *Service) RevokeOpaqueOwnerBinding(ctx context.Context, operationID string, binding OpaqueOwnerBinding) error {
	if s == nil || ctx == nil || !node.ValidIdentifier(operationID) || !validOpaqueOwnerBinding(binding) {
		return store.ErrNodeState
	}
	release, err := s.acquire(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	if err := s.opaqueRegistryDir(false); err != nil {
		return err
	}
	return s.revokeOpaqueOwnerBindingLocked(ctx, operationID, binding)
}

// RevokeOpaqueOwnerReceipt resolves the durable binding by random alias while
// holding the owner volume's exclusive fence; no historical ID or content
// metadata needs to cross the control channel.
func (s *Service) RevokeOpaqueOwnerReceipt(ctx context.Context, receipt protocol.OpaqueRevocationReceipt) error {
	if s == nil || ctx == nil {
		return store.ErrNodeState
	}
	if _, err := receipt.Payload(); err != nil {
		return store.ErrNodeState
	}
	release, err := s.acquire(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	if err = s.opaqueRegistryDir(false); err != nil {
		return err
	}
	var actual OpaqueOwnerBinding
	if err = s.readOpaqueRecord(opaqueRegistryFile(receipt.Alias, ".active"), &actual); err != nil || !actual.Valid() || actual.MasterID != receipt.MasterID || actual.OwnerID != receipt.OwnerID || actual.RelationshipID != receipt.RelationshipID || actual.Alias != receipt.Alias || actual.Blob != receipt.Blob || actual.Revision != receipt.Revision {
		return store.ErrNodeState
	}
	return s.revokeOpaqueOwnerBindingLocked(ctx, receipt.OperationID, actual)
}

func (s *Service) revokeOpaqueOwnerBindingLocked(ctx context.Context, operationID string, binding OpaqueOwnerBinding) error {
	var actual OpaqueOwnerBinding
	if err := s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".active"), &actual); err != nil || actual != binding {
		return store.ErrNodeState
	}
	var reserved OpaqueOwnerBinding
	if err := s.readOpaqueRecord(opaqueBlobReservation(binding.Blob), &reserved); err != nil || reserved != binding {
		return store.ErrNodeState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.writeOpaqueRecordLocked(opaqueRegistryFile(binding.Alias, ".revoked"), opaqueRevocation{OperationID: operationID, Binding: binding})
}

// checkOpaqueOwnerBindingLocked runs under the same shared lease held for the
// entire read. A malformed/missing binding or any tombstone denies access.
func (s *Service) checkOpaqueOwnerBindingLocked(binding OpaqueOwnerBinding) error {
	if !validOpaqueOwnerBinding(binding) || s.opaqueRegistryDir(false) != nil {
		return store.ErrNodeState
	}
	if _, err := s.root.Lstat(opaqueRegistryFile(binding.Alias, ".revoked")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return store.ErrNodeState
	}
	var actual OpaqueOwnerBinding
	if err := s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".active"), &actual); err != nil || actual != binding {
		return store.ErrNodeState
	}
	var reserved OpaqueOwnerBinding
	if err := s.readOpaqueRecord(opaqueBlobReservation(binding.Blob), &reserved); err != nil || reserved != binding {
		return store.ErrNodeState
	}
	return nil
}
