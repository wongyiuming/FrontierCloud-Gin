//go:build linux

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type retainedTreeRuntime struct {
	hold   func(ctx context.Context, binding, data string) error
	rebind func(ctx context.Context, binding, archiveSHA string, manifest recovery.Manifest, data, secrets, database string) error
	local  func(ctx context.Context, binding, archiveSHA string, manifest recovery.Manifest, database string) (runtimefacts.TreeRetainedLocalProof, error)
}

// This private coordinator ends with the SQLite/tree binding recovered and
// both fences still armed. The caller keeps Owner admission held throughout;
// authorize rechecks that admission without taking the local native leases.
// The caller supplies the independently reviewed, locally available helper.
// Full resource verification and explicit opening are separate operations.
func (d *Deployment) restoreRetainedTreeState(ctx context.Context, live, source Receipt, helper release.ImageProof, archive, checksum, node, directory string, authorize func(context.Context, recovery.Report) error) (state retainedTreeProgress, err error) {
	if ctx == nil || authorize == nil || !validRetainedTreeDigest(checksum) || live.Role != "master" || live.Database != "sqlite" || live.State != "upgrade_fenced" ||
		source.Role != live.Role || source.Database != live.Database || source.State != "ready" || source.Project != live.Project || source.SelectionHash != live.SelectionHash || !equalStrings(source.Files, live.Files) {
		return state, recovery.ErrUnsafe
	}
	done, err := d.AcquireOperation()
	if err != nil {
		return state, err
	}
	defer func() { err = errors.Join(err, done()) }()
	cfg, err := d.ValidateReceipt(ctx, live)
	if err != nil {
		return state, err
	}
	roots, err := d.upgradeRecoveryRoots(ctx, cfg)
	if err != nil {
		return state, err
	}
	directory, err = safeRecoveryDirectory(directory, false)
	if err != nil || !filepath.IsAbs(archive) || filepath.Clean(archive) != archive {
		return state, recovery.ErrUnsafe
	}
	if treePathsOverlap(directory, archive) {
		return state, recovery.ErrUnsafe
	}
	pins := make(map[string]os.FileInfo, len(roots)+1)
	for _, mount := range roots {
		if treePathsOverlap(mount, directory) || treePathsOverlap(mount, archive) {
			return state, recovery.ErrUnsafe
		}
		for other := range pins {
			if treePathsOverlap(mount, other) {
				return state, recovery.ErrUnsafe
			}
		}
		real, resolveErr := filepath.EvalSymlinks(mount)
		info, statErr := os.Lstat(mount)
		if resolveErr != nil || real != mount || statErr != nil || !info.IsDir() {
			return state, recovery.ErrUnsafe
		}
		pins[mount] = info
	}
	if roots["data"] == "" || roots["runtime_secrets"] == "" {
		return state, recovery.ErrUnsafe
	}
	if err = d.stoppedWriters(ctx); err != nil {
		return state, err
	}
	if err = prepareRetainedTreeDirectory(directory); err != nil {
		return state, err
	}
	if _, err = os.Lstat(filepath.Join(directory, treeRetainedJournal)); errors.Is(err, os.ErrNotExist) {
		err = d.validateBackupAdmission(ctx, cfg, live, RuntimeFact{NodeID: node})
	}
	if err != nil {
		return state, err
	}
	pins[directory], err = os.Lstat(directory)
	if err != nil {
		return state, err
	}
	mountProofs := make(map[string]runtimefacts.TreeBackupMount, len(pins))
	for name, info := range pins {
		if mountProofs[name], err = treeRuntimeMount(info); err != nil {
			return state, err
		}
	}
	var authorizedReport *recovery.Report
	recheck := func(c context.Context) error {
		if e := c.Err(); e != nil {
			return e
		}
		for name, before := range pins {
			info, e := os.Lstat(name)
			if e != nil || !sameTreeRuntimeDirectory(before, info) {
				return errors.New("retained recovery directory or mount changed")
			}
		}
		if e := matchRetainedTreeReceipt(filepath.Join(d.Directory, ReceiptFile), live); e != nil {
			return e
		}
		if e := d.stoppedWriters(c); e != nil {
			return e
		}
		if authorizedReport != nil {
			return authorize(c, *authorizedReport)
		}
		return nil
	}
	if err = recheck(ctx); err != nil {
		return state, err
	}
	runtime, err := d.treeRetainedDockerRuntime(ctx, cfg, helper, roots, recheck)
	if err != nil {
		return state, err
	}
	material := filepath.Join(directory, "material")
	var report recovery.Report
	if _, err = os.Lstat(material); errors.Is(err, os.ErrNotExist) {
		archiveInfo, statErr := os.Lstat(archive)
		free, freeErr := diskFree(directory)
		if statErr != nil || freeErr != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Size() <= 0 || free < 512<<20 || uint64(archiveInfo.Size()) > free-(512<<20) {
			return state, errors.New("retained recovery workspace lacks safe extraction capacity")
		}
		report, err = recovery.ApplyTreeStateArchive(ctx, archive, material, checksum, node)
	} else if err == nil {
		report, err = recovery.CheckTreeArchiveAuthenticated(ctx, archive, checksum)
	}
	if err != nil {
		return state, err
	}
	m := report.Manifest
	if !report.Verified || report.SHA256 != checksum || m.NodeID != node || m.Revision != source.Revision || m.Role != "Master" || m.Scope != recovery.UpgradeStateScope || m.Database != "sqlite" || m.SchemaGeneration != migrations.Generation {
		return state, recovery.ErrUnsafe
	}
	if err = recovery.CheckTreeMaterial(ctx, material, report); err != nil {
		return state, err
	}
	if err = matchRetainedTreeReceipt(filepath.Join(material, "deployment", ReceiptFile), source); err != nil {
		return state, err
	}
	install, err := prepareTreeRetainedInstall(ctx, cfg, source, roots, report)
	if err != nil {
		return state, err
	}
	failed := filepath.Join(directory, "failed")
	install.retained = failed
	if err = authorize(ctx, report); err != nil {
		return state, err
	}
	authorizedReport = &report
	binding := upgradeHash(struct {
		Version               int
		Archive, Source, Live string
		Node, Database        string
		Helper                release.ImageProof
		Mounts                map[string]runtimefacts.TreeBackupMount
	}{1, checksum, upgradeHash(source), upgradeHash(live), node, install.database, helper, mountProofs})
	if _, err = readRetainedTreeProgress(directory, binding); errors.Is(err, os.ErrNotExist) {
		err = exclusiveJSON(filepath.Join(directory, treeRetainedJournal), retainedTreeProgress{Version: 1, Binding: binding, Phase: treePreparing})
	}
	if err != nil {
		return state, err
	}
	if err = recheck(ctx); err != nil {
		return state, err
	}
	if err = runtime.hold(ctx, binding, roots["data"]); err != nil {
		return state, err
	}
	gate, err := maintenance.Open(roots["data"])
	if err != nil {
		return state, err
	}
	defer gate.Close()
	fenced := func(c context.Context, run func(context.Context, *os.Root) error) error {
		return gate.Inspect(c, func(c context.Context) error {
			root, e := os.OpenRoot(roots["data"])
			if e != nil {
				return e
			}
			defer root.Close()
			lease, e := sitecontrol.Lease(c, root, true)
			if e != nil {
				return e
			}
			defer lease()
			check := func() error {
				if e := recheck(c); e != nil {
					return e
				}
				return gate.VerifyTreeRecoveryHoldBinding(c, binding)
			}
			if e = check(); e != nil {
				return e
			}
			if e = run(c, root); e != nil {
				return e
			}
			return check()
		})
	}
	state, err = advanceRetainedTreeState(ctx, directory, binding, retainedTreeSteps{
		database: install.database, fenced: fenced,
		retain: func(c context.Context) error {
			if e := d.validateBackupAdmission(c, cfg, live, RuntimeFact{NodeID: node}); e != nil {
				return e
			}
			return install.retain(c, failed)
		},
		verifyRetained: func(c context.Context) error {
			_, e := install.verifyRetained(c, failed)
			return e
		},
		install: func(c context.Context) error { return install.install(c, material) },
		repair:  func(c context.Context) error { return install.repairSQLite(c, material) },
		rebind: func(c context.Context) error {
			if e := recheck(c); e != nil {
				return e
			}
			return runtime.rebind(c, binding, checksum, m, roots["data"], roots["runtime_secrets"], install.database)
		},
	})
	if err != nil {
		return state, err
	}
	proof, err := runtime.local(ctx, binding, checksum, m, install.database)
	if err != nil {
		return state, err
	}
	state.LocalProof = &proof
	return state, nil
}

func prepareRetainedTreeDirectory(directory string) error {
	parent, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Stat(".")
	if err != nil || !retainedTreeWorkspaceOwner(info, 0022) {
		return recovery.ErrUnsafe
	}
	name := filepath.Base(directory)
	if err = parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err = parent.Lstat(name)
	if err != nil || !retainedTreeWorkspaceOwner(info, 0077) {
		return recovery.ErrUnsafe
	}
	return fsutil.SyncDirectory(parent, ".")
}

func retainedTreeWorkspaceOwner(info os.FileInfo, forbidden os.FileMode) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm()&forbidden == 0 && st.Uid == uint32(os.Geteuid())
}

func matchRetainedTreeReceipt(file string, expected Receipt) error {
	raw, err := readRegular(file, 1<<20)
	if err != nil {
		return err
	}
	var receipt Receipt
	if _, err = protocol.ParseStrictJSON(raw, 1<<20); err != nil || json.Unmarshal(raw, &receipt) != nil || !reflect.DeepEqual(receipt, expected) {
		return errors.New("retained tree receipt differs from approved recovery")
	}
	return nil
}
