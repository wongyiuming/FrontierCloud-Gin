package migrationdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RetireDeletedAnchor is distinct from target-anchor retirement: the managed
// business copy has already been deleted by a version-bound transaction. The
// caller authenticates that current deletion fact before and after disk work.
func (r *Receiver) RetireDeletedAnchor(ctx context.Context, s Spec, admission func() error) error {
	if !r.valid(s) || admission == nil {
		return ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return e
	}
	defer release()
	c, e := r.load(s)
	if e != nil {
		return e
	}
	if c.State != "published" || c.Offset != s.Bytes || c.PrefixSHA != s.SHA256 {
		return ErrState
	}
	if e = admission(); e != nil {
		return e
	}
	name, _, _ := names(s)
	_, e = r.root.Lstat(name)
	exists := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if c.AnchorRetired {
		if exists {
			return ErrState
		}
		return nil
	}
	if !exists && !c.AnchorRetiring {
		return ErrState
	}
	if exists {
		if _, e = r.inspect(ctx, c); e != nil {
			return e
		}
	}
	if e = admission(); e != nil {
		return e
	}
	if !c.AnchorRetiring {
		c.AnchorRetiring = true
		if e = r.save(c); e != nil {
			return e
		}
	}
	if exists {
		if e = r.root.Remove(name); e != nil {
			return e
		}
	}
	if e = fsutil.SyncDirectory(r.root, "."); e != nil {
		return e
	}
	c.AnchorRetiring = false
	c.AnchorRetired = true
	return r.save(c)
}

// HistoricalAnchors scans bounded directory batches and only the checkpoint
// suffix for this logical object. It never adopts an unrelated path or identity.
func (r *Receiver) HistoricalAnchors(ctx context.Context, master string, o store.MigrationObject, sha string, admission func() error) error {
	_, e := r.historicalAnchors(ctx, master, o, sha, admission, true)
	return e
}
func (r *Receiver) HistoricalAnchorsFinished(ctx context.Context, master string, o store.MigrationObject, sha string) (bool, error) {
	return r.historicalAnchors(ctx, master, o, sha, func() error { return nil }, false)
}
func (r *Receiver) historicalAnchors(ctx context.Context, master string, o store.MigrationObject, sha string, admission func() error, retire bool) (finished bool, result error) {
	finished = true
	if admission == nil || !identifier.MatchString(master) || o.Resource != r.resource || !digest.MatchString(sha) {
		return false, ErrState
	}
	hash := sha256.Sum256([]byte(o.Resource + ":" + o.ID))
	suffix := "-" + hex.EncodeToString(hash[:]) + ".json"
	dir, e := r.root.Open(".")
	if e != nil {
		return false, e
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(64)
		if err != nil && err != io.EOF {
			return false, err
		}
		for _, entry := range entries {
			if e = ctx.Err(); e != nil {
				return false, e
			}
			name := entry.Name()
			if !strings.HasPrefix(name, ".migration-data-") || !strings.HasSuffix(name, suffix) {
				continue
			}
			f, e := r.private(name, os.O_RDONLY)
			if e != nil {
				return false, e
			}
			info, e := f.Stat()
			if e != nil || info.Size() > journalLimit {
				f.Close()
				return false, ErrState
			}
			var saved journalRecord
			d := json.NewDecoder(io.LimitReader(f, journalLimit+1))
			d.DisallowUnknownFields()
			e = d.Decode(&saved)
			var extra any
			if e == nil && d.Decode(&extra) != io.EOF {
				e = ErrState
			}
			f.Close()
			if e != nil {
				return false, e
			}
			s := saved.Spec
			_, expected, _ := names(s)
			if expected != name || !r.valid(s) || s.MasterID != master || s.LogicalID != o.ID || s.ObjectID != o.ObjectID || s.TargetPath != o.Path || s.Bytes != o.Bytes || s.SHA256 != sha {
				return false, ErrState
			}
			if (s.Encryption == nil) != (o.Encryption == nil) || s.Encryption != nil && *s.Encryption != *o.Encryption {
				return false, ErrState
			}
			if s.Resource == "recording" && (s.Recording == nil || o.Recording == nil || s.Recording.ID != o.Recording.ID || s.Recording.UserID != o.Recording.UserID || s.Recording.Filename != o.Recording.Filename || s.Recording.ContentType != o.Recording.ContentType || s.Recording.MetadataSHA256 != o.Recording.MetadataSHA256) {
				return false, ErrState
			}
			if retire {
				if e = r.RetireDeletedAnchor(ctx, s, admission); e != nil {
					return false, e
				}
			} else {
				c, e := r.load(s)
				if e != nil {
					return false, e
				}
				name, _, _ := names(s)
				_, e = r.root.Lstat(name)
				if !c.AnchorRetired || e == nil {
					finished = false
				} else if !errors.Is(e, os.ErrNotExist) {
					return false, e
				}
			}
		}
		if err == io.EOF {
			return finished, nil
		}
	}
}
