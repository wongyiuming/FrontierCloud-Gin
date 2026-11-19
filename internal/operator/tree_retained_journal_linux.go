//go:build linux

package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

const (
	treeRetainedJournal = ".fc-tree-retained-recovery.json"
	treePreparing       = "preparing"
	treeInstalling      = "installing"
	treeInstalled       = "installed"
	treeRebinding       = "rebinding"
	treeRepairingSQLite = "repairing_sqlite"
	treeReboundFenced   = "rebound_fenced"
)

type retainedTreeFilePin struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type retainedTreeProgress struct {
	Version  int                 `json:"version"`
	Binding  string              `json:"binding_sha256"`
	Phase    string              `json:"phase"`
	Database retainedTreeFilePin `json:"database"`
	Fence    retainedTreeFilePin `json:"fence"`
	Intent   string              `json:"intent_sha256,omitempty"`
	// LocalProof is provisional and never part of the persisted recovery journal.
	LocalProof *runtimefacts.TreeRetainedLocalProof `json:"-"`
}

func readRetainedTreeProgress(directory, binding string) (retainedTreeProgress, error) {
	var state retainedTreeProgress
	name := filepath.Join(directory, treeRetainedJournal)
	info, err := os.Lstat(name)
	if err != nil {
		return state, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Nlink != 1 || owner.Uid != uint32(os.Geteuid()) {
		return state, recovery.ErrUnsafe
	}
	raw, err := readRegular(name, 4096)
	if err != nil {
		return state, err
	}
	if _, err = protocol.ParseStrictJSON(raw, 4096); err != nil {
		return state, recovery.ErrUnsafe
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&state) != nil || dec.Decode(new(any)) != io.EOF || state.Version != 1 || state.Binding != binding {
		return state, recovery.ErrUnsafe
	}
	switch state.Phase {
	case treePreparing, treeInstalling:
		if state.Database.Inode == 0 && state.Fence.Inode == 0 && state.Intent == "" {
			return state, nil
		}
	case treeInstalled, treeRebinding, treeRepairingSQLite:
		if state.Database.Inode != 0 && state.Fence.Inode != 0 && state.Intent == "" {
			return state, nil
		}
	case treeReboundFenced:
		if state.Database.Inode != 0 && state.Fence.Inode != 0 && validRetainedTreeDigest(state.Intent) {
			return state, nil
		}
	}
	return state, recovery.ErrUnsafe
}

func retainedTreeIntentProof(root *os.Root) (string, error) {
	name := sealedtree.MasterRebindIntentFile
	pin, err := retainedTreePin(root, name)
	if err != nil {
		return "", err
	}
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < 1 || info.Size() > 4096 {
		return "", recovery.ErrUnsafe
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != pin.Device || st.Ino != pin.Inode {
		return "", recovery.ErrUnsafe
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	after, afterErr := f.Stat()
	current, pathErr := root.Lstat(name)
	if err != nil || int64(len(raw)) != info.Size() || afterErr != nil || pathErr != nil || !sameTreeRuntimeFile(info, after) || !sameTreeRuntimeFile(info, current) {
		return "", recovery.ErrUnsafe
	}
	sum := sha256.Sum256(raw)
	return upgradeHash(struct {
		Pin retainedTreeFilePin
		SHA string
	}{pin, hex.EncodeToString(sum[:])}), nil
}

func retainedTreePin(root *os.Root, name string) (retainedTreeFilePin, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return retainedTreeFilePin{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || stat.Ino == 0 {
		return retainedTreeFilePin{}, recovery.ErrUnsafe
	}
	return retainedTreeFilePin{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

// The outer host operation lock is held throughout. Fenced sections pin the
// original mounts and hold native/site leases. Rebinding takes those leases
// itself, so it runs between sections while the persistent hold stays armed.
type retainedTreeSteps struct {
	database       string
	fenced         func(context.Context, func(context.Context, *os.Root) error) error
	retain         func(context.Context) error
	verifyRetained func(context.Context) error
	install        func(context.Context) error
	repair         func(context.Context) error
	rebind         func(context.Context) error
}

func advanceRetainedTreeState(ctx context.Context, directory, binding string, steps retainedTreeSteps) (retainedTreeProgress, error) {
	state, err := readRetainedTreeProgress(directory, binding)
	if err != nil {
		return state, err
	}
	var resumeRebound bool
	step := func(next string) error {
		state.Phase = next
		return replaceJSON(filepath.Join(directory, treeRetainedJournal), state)
	}
	readPins := func(root *os.Root) (retainedTreeFilePin, retainedTreeFilePin, error) {
		db, dbErr := retainedTreePin(root, steps.database)
		fence, fenceErr := retainedTreePin(root, sealedtree.MasterStatePaths()[0])
		return db, fence, errors.Join(dbErr, fenceErr)
	}
	requireNoIntent := func(root *os.Root) error {
		present, e := sealedtree.RetainedTreeRebindIntentPresent(root)
		if e != nil || present {
			return errors.New("retained tree rebind intent does not match the recovery phase")
		}
		return nil
	}
	err = steps.fenced(ctx, func(c context.Context, root *os.Root) error {
		if state.Phase != treePreparing {
			if e := steps.verifyRetained(c); e != nil {
				return e
			}
		}
		if state.Phase == treePreparing {
			if e := requireNoIntent(root); e != nil {
				return e
			}
			if e := steps.retain(c); e != nil {
				return e
			}
			if e := step(treeInstalling); e != nil {
				return e
			}
		}
		if state.Phase == treeRebinding || state.Phase == treeReboundFenced {
			db, fence, e := readPins(root)
			if e != nil || db != state.Database || fence != state.Fence {
				return errors.New("retained tree rebind file identity changed")
			}
			if state.Phase == treeReboundFenced {
				resumeRebound = true
				proof, err := retainedTreeIntentProof(root)
				if err != nil || proof != state.Intent {
					return errors.New("rebound retained tree intent changed")
				}
				return nil
			}
			present, e := sealedtree.RetainedTreeRebindIntentPresent(root)
			if e != nil || present {
				return e // Once published, only the runtime may verify or resume it.
			}
			if e = step(treeRepairingSQLite); e != nil {
				return e
			}
		}
		if state.Phase == treeInstalling || state.Phase == treeRepairingSQLite {
			if e := requireNoIntent(root); e != nil {
				return e
			}
			if state.Phase == treeInstalling {
				if e := steps.install(c); e != nil {
					return e
				}
			} else {
				fence, e := retainedTreePin(root, sealedtree.MasterStatePaths()[0])
				if e != nil || fence != state.Fence {
					return errors.New("retained tree fence changed during SQLite repair")
				}
				if e = steps.repair(c); e != nil {
					return e
				}
			}
			if e := requireNoIntent(root); e != nil {
				return e
			}
			db, fence, e := readPins(root)
			if e != nil || state.Phase == treeRepairingSQLite && fence != state.Fence {
				return errors.New("installed retained tree files cannot be pinned")
			}
			state.Database, state.Fence = db, fence
			if e = step(treeInstalled); e != nil {
				return e
			}
		}
		if state.Phase != treeInstalled {
			return recovery.ErrUnsafe
		}
		db, fence, e := readPins(root)
		if e != nil || db != state.Database || fence != state.Fence {
			return errors.New("installed retained tree files changed before rebinding")
		}
		if e = requireNoIntent(root); e != nil {
			return e
		}
		return step(treeRebinding)
	})
	if err != nil || resumeRebound {
		return state, err
	}
	if err = steps.rebind(ctx); err != nil {
		return state, err
	}
	err = steps.fenced(ctx, func(c context.Context, root *os.Root) error {
		if e := steps.verifyRetained(c); e != nil {
			return e
		}
		db, fence, e := readPins(root)
		if e != nil || db != state.Database || fence != state.Fence {
			return errors.New("retained tree file identity changed after rebinding")
		}
		if state.Intent, e = retainedTreeIntentProof(root); e != nil {
			return e
		}
		return step(treeReboundFenced)
	})
	return state, err
}
