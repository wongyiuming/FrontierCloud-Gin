package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaqueDeletionIntent struct {
	Revocation           opaqueRevocation `json:"revocation"`
	ParentDevice         uint64           `json:"parent_device"`
	ParentInode          uint64           `json:"parent_inode"`
	PublicationOperation string           `json:"publication_operation,omitempty"`
}

// DeleteOpaqueOwnerBlob removes only a uniquely reserved, already revoked
// random blob. The durable deletion intent precedes unlink; the durable result
// follows file-directory sync. The only permitted extra link is the exact
// completed publication stage authorized by the Master for the same inode.
// The result certifies unlink and directory sync for this object on this volume.
func (s *Service) DeleteOpaqueOwnerBlob(ctx context.Context, receipt protocol.OpaqueDeletionReceipt) error {
	if s == nil || ctx == nil {
		return store.ErrNodeState
	}
	if _, err := receipt.Payload(); err != nil {
		return store.ErrNodeState
	}
	ctx, cancel := context.WithTimeout(ctx, protocol.OpaqueDeletionVerificationTimeout)
	defer cancel()
	// Reject duplicate verification while the durable queue already has an
	// Owner request in flight. Ordinary volume readers remain independent.
	if !s.opaqueDeleteVerification.TryLock() {
		return store.ErrNodeState
	}
	defer s.opaqueDeleteVerification.Unlock()
	release, err := s.acquire(ctx, true)
	if err != nil {
		return err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	binding, err := s.opaqueOwnerDeletionBinding(receipt)
	if err != nil {
		return err
	}
	wanted := opaqueRevocation{OperationID: receipt.OperationID, Binding: binding}
	intentPath := opaqueRegistryFile(binding.Alias, ".delete-intent")
	resultPath := opaqueRegistryFile(binding.Alias, ".deleted")
	parent, err := openOpaqueBlobParent(s.root, binding.Blob)
	if err != nil {
		return err
	}
	defer parent.Close()
	parentInfo, err := parent.Leaf().Stat(".")
	if err != nil {
		return store.ErrNodeState
	}
	device, inode, valid := opaqueDirectoryIdentity(parentInfo)
	if !valid {
		return store.ErrNodeState
	}
	wantedIntent := opaqueDeletionIntent{Revocation: wanted, ParentDevice: device, ParentInode: inode, PublicationOperation: receipt.PublicationOperation}
	clearPublicationStage := func() error {
		if receipt.PublicationOperation == "" {
			return nil
		}
		return s.removeOpaquePublicationLink(ctx, receipt.PublicationOperation, binding.Blob, binding.Size, context.Context.Err, parent.Check)
	}
	name := binding.Blob + ".blob"
	var prior opaqueDeletionIntent
	resultErr := s.readOpaqueRecord(resultPath, &prior)
	if resultErr == nil {
		if prior != wantedIntent {
			return store.ErrNodeState
		}
		var committedIntent opaqueDeletionIntent
		if s.readOpaqueRecord(intentPath, &committedIntent) != nil || committedIntent != wantedIntent {
			return store.ErrNodeState
		}
		if _, statErr := parent.Leaf().Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
			return store.ErrNodeState
		}
		if clearPublicationStage() != nil || parent.Check() != nil || fsutil.SyncDirectory(parent.Leaf(), ".") != nil || parent.Check() != nil {
			return store.ErrNodeState
		}
		return s.writeOpaqueRecordLocked(resultPath, wantedIntent)
	}
	if !errors.Is(resultErr, os.ErrNotExist) {
		return store.ErrNodeState
	}
	var intent opaqueDeletionIntent
	intentErr := s.readOpaqueRecord(intentPath, &intent)
	if intentErr == nil && intent != wantedIntent || intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) {
		return store.ErrNodeState
	}
	info, err := parent.Leaf().Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		// An absent object is proof only after a matching durable delete intent.
		if intentErr != nil {
			return store.ErrNodeState
		}
		if err = clearPublicationStage(); err != nil {
			return err
		}
	} else {
		if err != nil || !info.Mode().IsRegular() || info.Size() != binding.Size ||
			!(opaqueSingleLink(info) || receipt.PublicationOperation != "" && opaqueExactLinks(info, 2)) {
			return store.ErrNodeState
		}
		// A completed publication may retain a redundant stage link. Clear
		// only that authenticated link while keeping the published inode.
		if opaqueExactLinks(info, 2) {
			if err = clearPublicationStage(); err != nil {
				return err
			}
		}
		before, statErr := parent.Leaf().Lstat(name)
		if statErr != nil || !before.Mode().IsRegular() || !os.SameFile(info, before) || before.Size() != binding.Size || !opaqueSingleLink(before) || parent.Check() != nil {
			return store.ErrNodeState
		}
		file, openErr := openOpaqueDeleteFile(parent.Leaf(), name)
		if openErr != nil {
			return store.ErrNodeState
		}
		defer file.Close()
		checkFile := func() bool {
			current, statErr := parent.Leaf().Lstat(name)
			opened, openErr := file.Stat()
			return statErr == nil && openErr == nil && sameOpaqueDeleteFile(before, current) &&
				sameOpaqueDeleteFile(before, opened) && parent.Check() == nil
		}
		if !checkFile() {
			return store.ErrNodeState
		}
		release()
		release = nil
		hash := sha256.New()
		n, readErr := io.CopyBuffer(hash, io.LimitReader(&contextReader{ctx, file}, binding.Size+1), make([]byte, 64<<10))
		if readErr != nil || n != binding.Size || hex.EncodeToString(hash.Sum(nil)) != binding.Digest || ctx.Err() != nil {
			return store.ErrNodeState
		}
		release, err = s.acquire(ctx, true)
		if err != nil {
			return err
		}
		currentBinding, err := s.opaqueOwnerDeletionBinding(receipt)
		if err != nil || currentBinding != binding {
			return store.ErrNodeState
		}
		if !errors.Is(s.readOpaqueRecord(resultPath, &prior), os.ErrNotExist) {
			return store.ErrNodeState
		}
		intentErr = s.readOpaqueRecord(intentPath, &intent)
		if intentErr == nil && intent != wantedIntent || intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) || !checkFile() {
			return store.ErrNodeState
		}
		if err = clearPublicationStage(); err != nil {
			return err
		}
		if intentErr != nil {
			if err = s.writeOpaqueRecordLocked(intentPath, wantedIntent); err != nil {
				return err
			}
		}
		if !checkFile() || ctx.Err() != nil {
			return store.ErrNodeState
		}
		if err = unlinkOpaqueFile(parent.Leaf(), name); err != nil {
			return store.ErrNodeState
		}
	}
	if parent.Check() != nil || fsutil.SyncDirectory(parent.Leaf(), ".") != nil || parent.Check() != nil {
		return store.ErrNodeState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.writeOpaqueRecordLocked(resultPath, wantedIntent)
}

func (s *Service) opaqueOwnerDeletionBinding(receipt protocol.OpaqueDeletionReceipt) (OpaqueOwnerBinding, error) {
	if err := s.opaqueRegistryDir(false); err != nil {
		return OpaqueOwnerBinding{}, err
	}
	var binding, reservation OpaqueOwnerBinding
	if err := s.readOpaqueRecord(opaqueRegistryFile(receipt.Alias, ".active"), &binding); err != nil ||
		!binding.Valid() || binding.MasterID != receipt.MasterID || binding.OwnerID != receipt.OwnerID ||
		binding.RelationshipID != receipt.RelationshipID || binding.Alias != receipt.Alias ||
		binding.Blob != receipt.Blob || binding.Revision != receipt.Revision {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	var revoked opaqueRevocation
	if err := s.readOpaqueRecord(opaqueBlobReservation(binding.Blob), &reservation); err != nil || reservation != binding {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	if err := s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".revoked"), &revoked); err != nil ||
		revoked != (opaqueRevocation{OperationID: receipt.OperationID, Binding: binding}) {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	return binding, nil
}
