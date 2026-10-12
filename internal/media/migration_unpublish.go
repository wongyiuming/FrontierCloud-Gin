package media

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path"
)

// MigrationCancelPublication removes only an unaccounted, task-bound hard link.
// SQL admission is repeated under the volume coordinator before unlinking.
// Reserved capacity remains held until the whole unit cancellation receipt.
func (s *Service) MigrationCancelPublication(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationShadowGrant, peer store.MigrationPeerRepository, audit store.NodeAudit) error {
	if peer == nil || g.Object.Resource != "media" {
		return store.ErrMigrationState
	}
	admission := func() error {
		if e := peer.PreparePeerMigrationPublicationAbort(ctx, relationship, l, g, audit); e != nil {
			return e
		}
		_, e := peer.AuthorizePeerMigration(ctx, relationship, l, g.Object.ID, "unpublish")
		return e
	}
	if e := admission(); e != nil {
		return e
	}
	v, e := peer.AuthorizePeerMigration(ctx, relationship, l, g.Object.ID, "unpublish")
	if e != nil {
		return e
	}
	o := v.Object
	spec := migrationdata.Spec{TaskID: l.TaskID, MasterID: v.Header.MasterID, SourceID: v.Header.SourceID, TargetID: v.Header.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: v.Proof.SHA256, Encryption: o.Encryption, Recording: o.Recording}
	r, e := s.MigrationReceiver(ctx)
	if e != nil {
		return e
	}
	cp, e := r.CancelPublication(ctx, spec, admission, func(stage string) error {
		release, e := s.acquire(ctx, true)
		if e != nil {
			return e
		}
		defer release()
		if e = s.ready(); e != nil {
			return e
		}
		if e = admission(); e != nil {
			return e
		}
		anchor, e := s.root.Lstat(stage)
		if e != nil {
			return e
		}
		target, e := s.safeInfo(spec.TargetPath)
		if errors.Is(e, os.ErrNotExist) {
			e = s.syncDirectory(path.Dir(spec.TargetPath))
			if errors.Is(e, os.ErrNotExist) {
				return nil
			}
			return e
		}
		if e != nil {
			return e
		}
		if !anchor.Mode().IsRegular() || !target.Mode().IsRegular() || !os.SameFile(anchor, target) || target.Size() != spec.Bytes {
			return store.ErrMigrationState
		}
		if e = s.root.Remove(spec.TargetPath); e != nil {
			return e
		}
		return s.syncDirectory(path.Dir(spec.TargetPath))
	})
	if e != nil {
		return e
	}
	if cp.State != "aborted" || !cp.PublicationUnlinked {
		return store.ErrMigrationState
	}
	// A replay must not turn an unexpected replacement business file into a
	// successful cancellation receipt, even after the private bytes are gone.
	release, e := s.acquire(ctx, true)
	if e != nil {
		return e
	}
	defer release()
	if e = s.ready(); e != nil {
		return e
	}
	if e = admission(); e != nil {
		return e
	}
	if _, e = s.safeInfo(spec.TargetPath); !errors.Is(e, os.ErrNotExist) {
		if e != nil {
			return e
		}
		return store.ErrMigrationState
	}
	return peer.CompletePeerMigrationAbort(ctx, relationship, l, o.ID, audit)
}
