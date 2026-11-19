//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecoveryOpaqueCensus proves only the observed set of published opaque blob
// names. It neither authenticates their contents nor proves staging settled.
type RecoveryOpaqueCensus struct {
	Version       int    `json:"version"`
	Count         int    `json:"count"`
	SetCommitment string `json:"set_commitment"`
}

// VisitRecoveryOpaqueCensus requires the Owner lease and an independently
// authenticated, settled, complete union of all published object IDs, including
// media, lyrics, recordings and retained operations. The caller holds its tree
// lease in Owner -> tree -> volume order. A callback must not reenter Service.
// Its result is provisional until return nil and the caller retains authority.
// This is a cooperative volume snapshot, not protection against a malicious
// host bypassing locks. Contents need separate authenticated full-byte checks.
func (s *Service) VisitRecoveryOpaqueCensus(ctx context.Context, owner store.OwnerControlLease, ownerID string, expected []string, visit func(RecoveryOpaqueCensus) error) error {
	return s.visitRecoveryOpaqueCensus(ctx, owner, ownerID, expected, visit, nil)
}

func (s *Service) visitRecoveryOpaqueCensus(ctx context.Context, owner store.OwnerControlLease, ownerID string, expected []string, visit func(RecoveryOpaqueCensus) error, volumeCheck func() error) error {
	if s == nil || s.root == nil || s.identity == nil || !recoveryValuePresent(s.nodes) || !recoveryValuePresent(s.repository) || ctx == nil || !recoveryValuePresent(owner) || visit == nil || len(expected) > 100000 || ownerID == "" {
		return store.ErrNodeState
	}
	ids := append([]string(nil), expected...)
	for i, id := range ids {
		if !ownedObjectID.MatchString(id) || (i > 0 && ids[i-1] >= id) {
			return store.ErrNodeState
		}
	}
	observer, ok := s.nodes.(recoveryOwnerMarker)
	if !ok || owner.Check(ctx) != nil {
		return store.ErrNodeState
	}
	control, err := owner.Binding(ctx)
	if err != nil || !ownedObjectID.MatchString(control) || observer.VerifyOwnerControlBinding(ctx, control) != nil {
		return store.ErrNodeState
	}
	identity, err := s.nodes.ReadIdentity(ctx)
	if err != nil || identity.ID != ownerID || identity.ID != s.identity.ID || (identity.Role != "Master" && identity.Role != "Follower") {
		return store.ErrNodeState
	}
	checkOwner := func() error {
		if ctx.Err() != nil || owner.Check(ctx) != nil {
			return store.ErrNodeState
		}
		b, e := owner.Binding(ctx)
		if e != nil || b != control || observer.VerifyOwnerControlBinding(ctx, control) != nil {
			return store.ErrNodeState
		}
		current, e := s.nodes.ReadIdentity(ctx)
		if e != nil || current != identity || owner.Check(ctx) != nil {
			return store.ErrNodeState
		}
		return nil
	}
	checkVolume := volumeCheck
	if checkVolume == nil {
		release, check, e := s.recoveryOpaqueVolume(ctx)
		if e != nil {
			return e
		}
		defer release()
		checkVolume = check
	}
	check := func() error {
		if checkOwner() != nil || checkVolume() != nil {
			return store.ErrNodeState
		}
		return nil
	}
	if s.ready() != nil || check() != nil {
		return store.ErrNodeState
	}
	seen := make([]bool, len(ids))
	count := 0
	before, err := s.root.Lstat("objects")
	if errors.Is(err, os.ErrNotExist) {
		if len(ids) != 0 {
			return store.ErrNodeState
		}
	} else if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return store.ErrNodeState
	} else {
		dir, e := s.root.OpenRoot("objects")
		if e != nil {
			return store.ErrNodeState
		}
		defer dir.Close()
		opened, e := dir.Stat(".")
		if e != nil || !sameCensusDirectory(before, opened) {
			return store.ErrNodeState
		}
		var walk func(*os.Root, int, string) error
		walk = func(parent *os.Root, level int, prefix string) error {
			if check() != nil {
				return store.ErrNodeState
			}
			pinned, e := parent.Stat(".")
			if e != nil {
				return store.ErrNodeState
			}
			f, e := parent.Open(".")
			if e != nil {
				return store.ErrNodeState
			}
			defer f.Close()
			for {
				entries, readErr := f.ReadDir(256)
				for _, ent := range entries {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					name := ent.Name()
					info, e := parent.Lstat(name)
					if e != nil || info.Mode()&os.ModeSymlink != 0 {
						return store.ErrNodeState
					}
					if level < 2 {
						if len(name) != 2 || !censusHexPrefix(name) || !info.IsDir() {
							return store.ErrNodeState
						}
						child, e := parent.OpenRoot(name)
						if e != nil {
							return store.ErrNodeState
						}
						opened, e := child.Stat(".")
						if e == nil && sameCensusDirectory(info, opened) {
							e = walk(child, level+1, prefix+name)
						} else {
							e = store.ErrNodeState
						}
						after, ae := child.Stat(".")
						current, ce := parent.Lstat(name)
						child.Close()
						if e != nil || ae != nil || ce != nil || !sameCensusDirectory(info, after) || !sameCensusDirectory(info, current) {
							return store.ErrNodeState
						}
					} else {
						if !strings.HasSuffix(name, ".blob") {
							return store.ErrNodeState
						}
						id := strings.TrimSuffix(name, ".blob")
						if !ownedObjectID.MatchString(id) || !strings.HasPrefix(id, prefix) || !info.Mode().IsRegular() || !opaqueSingleLink(info) {
							return store.ErrNodeState
						}
						i := sort.SearchStrings(ids, id)
						if i == len(ids) || ids[i] != id || seen[i] {
							return store.ErrNodeState
						}
						seen[i] = true
						count++
					}
				}
				if check() != nil {
					return store.ErrNodeState
				}
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil || len(entries) == 0 {
					return store.ErrNodeState
				}
			}
			current, e := parent.Stat(".")
			if e != nil || !sameCensusDirectory(pinned, current) {
				return store.ErrNodeState
			}
			return nil
		}
		if walk(dir, 0, "") != nil {
			return store.ErrNodeState
		}
		after, ae := dir.Stat(".")
		current, ce := s.root.Lstat("objects")
		if ae != nil || ce != nil || !sameCensusDirectory(before, after) || !sameCensusDirectory(before, current) {
			return store.ErrNodeState
		}
	}
	if count != len(ids) || check() != nil {
		return store.ErrNodeState
	}
	h := sha256.New()
	h.Write([]byte("frontiercloud:recovery-opaque-census:v1\x00" + ownerID + control))
	for _, id := range ids {
		h.Write([]byte(id))
	}
	proof := RecoveryOpaqueCensus{Version: 1, Count: count, SetCommitment: hex.EncodeToString(h.Sum(nil))}
	if err := visit(proof); err != nil {
		return err
	}
	if before == nil {
		if _, err = s.root.Lstat("objects"); !errors.Is(err, os.ErrNotExist) {
			return store.ErrNodeState
		}
	} else {
		after, e := s.root.Lstat("objects")
		if e != nil || !sameCensusDirectory(before, after) {
			return store.ErrNodeState
		}
	}
	if s.ready() != nil || check() != nil {
		return store.ErrNodeState
	}
	return nil
}

func censusHexPrefix(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sameCensusDirectory(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.IsDir() || !b.IsDir() || a.Mode() != b.Mode() || !os.SameFile(a, b) || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xo := a.Sys().(*syscall.Stat_t)
	y, yo := b.Sys().(*syscall.Stat_t)
	return xo && yo && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}
