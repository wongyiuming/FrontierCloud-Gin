package migrationdata

import (
	"context"
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
)

// CancelPublication handles the durable publishing checkpoint, never a published
// SQL receipt. The service callback must prove absent business metadata and only
// unlink this task's same-inode business link under its mutation coordinator.
// Its absence is accepted only when replaying this persisted cancellation intent.
func (r *Receiver) CancelPublication(ctx context.Context, s Spec, admission func() error, unpublish func(stage string) error) (Checkpoint, error) {
	if unpublish == nil {
		return Checkpoint{}, ErrState
	}
	return r.cancelPublication(ctx, s, admission, func(stage string, _ os.FileInfo) error { return unpublish(stage) }, nil)
}

func (r *Receiver) cancelPublication(ctx context.Context, s Spec, admission func() error, unpublish func(string, os.FileInfo) error, confirmAbsent func(string, bool) error) (Checkpoint, error) {
	if !r.valid(s) || admission == nil {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	if e = admission(); e != nil {
		return Checkpoint{}, e
	}
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	stage, _, _ := names(s)
	if c.State == "aborted" && c.PublicationCancelling && c.PublicationUnlinked {
		if confirmAbsent != nil {
			return c, confirmAbsent(stage, true)
		}
		return c, nil
	}
	if c.State != "publishing" && !(c.State == "aborting" && c.PublicationCancelling) || c.AnchorRetiring || c.AnchorRetired {
		return c, ErrState
	}
	var proof os.FileInfo
	if !c.PublicationUnlinked {
		f, e := r.private(stage, os.O_RDONLY)
		if e != nil {
			return c, e
		}
		defer f.Close()
		proof, e = verifyCheckpointFile(ctx, c, f)
		if e != nil {
			return c, e
		}
		if e = admission(); e != nil {
			return c, e
		}
		if !c.PublicationCancelling {
			c.State = "aborting"
			c.PublicationCancelling = true
			if e = r.save(c); e != nil {
				return c, e
			}
		}
		if e = r.check(ctx); e != nil {
			return c, e
		}
		if e = unpublish(stage, proof); e != nil {
			return c, e
		}
		c.PublicationUnlinked = true
		if e = r.save(c); e != nil {
			return c, e
		}
	}
	if e = admission(); e != nil {
		return c, e
	}
	f, e := r.private(stage, os.O_RDONLY)
	if e == nil {
		defer f.Close()
		if proof == nil || confirmAbsent == nil {
			// A retained private file needs fresh byte proof after interruption.
			proof, e = verifyCheckpointFile(ctx, c, f)
			if e != nil {
				return c, e
			}
		}
		if e = admission(); e != nil {
			return c, e
		}
		if e = r.check(ctx); e != nil {
			return c, e
		}
		if confirmAbsent != nil {
			if e = confirmAbsent(stage, false); e != nil {
				return c, e
			}
			current, err := r.root.Lstat(stage)
			if err != nil || !sameCheckpointFile(current, proof) {
				return c, ErrState
			}
		}
		if e = r.root.Remove(stage); e != nil {
			return c, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return c, e
	} else if confirmAbsent != nil {
		if e = confirmAbsent(stage, true); e != nil {
			return c, e
		}
	}
	if e = fsutil.SyncDirectory(r.root, "."); e != nil {
		return c, e
	}
	if confirmAbsent != nil {
		if e = confirmAbsent(stage, true); e != nil {
			return c, e
		}
	}
	c.State = "aborted"
	return c, r.save(c)
}
