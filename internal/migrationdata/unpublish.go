package migrationdata

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"os"
)

// CancelPublication handles the durable publishing checkpoint, never a published
// SQL receipt. The service callback must prove absent business metadata and only
// unlink this task's same-inode business link under its mutation coordinator.
// Its absence is accepted only when replaying this persisted cancellation intent.
func (r *Receiver) CancelPublication(ctx context.Context, s Spec, admission func() error, unpublish func(stage string) error) (Checkpoint, error) {
	if !r.valid(s) || admission == nil || unpublish == nil {
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
	if c.State == "aborted" && c.PublicationCancelling && c.PublicationUnlinked {
		return c, nil
	}
	if c.State != "publishing" && !(c.State == "aborting" && c.PublicationCancelling) || c.AnchorRetiring || c.AnchorRetired {
		return c, ErrState
	}
	if !c.PublicationUnlinked {
		if _, e = r.inspect(ctx, c); e != nil {
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
		stage, _, _ := names(s)
		if e = unpublish(stage); e != nil {
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
	stage, _, _ := names(s)
	f, e := r.private(stage, os.O_RDONLY)
	if e == nil {
		f.Close()
		// A retained private file still needs actual byte proof on replay; the
		// unlink intent does not authorize deleting replacement/corrupt material.
		if _, e = r.inspect(ctx, c); e != nil {
			return c, e
		}
		if e = admission(); e != nil {
			return c, e
		}
		if e = r.root.Remove(stage); e != nil {
			return c, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return c, e
	}
	if e = fsutil.SyncDirectory(r.root, "."); e != nil {
		return c, e
	}
	c.State = "aborted"
	return c, r.save(c)
}
