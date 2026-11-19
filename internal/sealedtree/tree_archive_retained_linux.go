//go:build linux

package sealedtree

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type treeRecoveryTarget struct {
	material, data, secrets string
	retained                bool
	guard                   func(context.Context) error
}

// RebindRetainedMasterTreeState verifies private extracted state and binds an
// already installed SQLite database to the fence at its final retained mount.
// The caller must have kept writers stopped and installed only archive-selected
// state. This operation never installs files, validates Owners, or opens service.
func RebindRetainedMasterTreeState(ctx context.Context, gate *maintenance.Gate, archive, expectedSHA, material, data, secrets, databaseRel, nodeID string) (bool, error) {
	if err := checkRetainedTreeRoots(material, data, secrets); err != nil {
		return false, err
	}
	target := treeRecoveryTarget{material: material, data: data, secrets: secrets, retained: true}
	return rebindTreeArchiveAt(ctx, gate, archive, expectedSHA, target, databaseRel, MasterFenceDirectory, nodeID)
}

// RebindVerifiedRetainedMasterTreeState binds installed state under the runtime
// UID. The trusted local coordinator must pass the exact manifest and archive
// checksum from CheckTreeArchiveAuthenticated and verify its private material
// with CheckTreeMaterial before installing. Neither source need be visible to
// the runtime. The runtime checks the evidence against its live key, hashes
// selected installed bytes before opening SQLite, and proves the old/new fence
// state under its native lease. This does not verify Owners or reopen service.
func RebindVerifiedRetainedMasterTreeState(ctx context.Context, gate *maintenance.Gate, archiveSHA string, manifest recovery.Manifest, data, secrets, databaseRel, nodeID string) (bool, error) {
	return rebindVerifiedRetainedMasterTreeState(ctx, gate, archiveSHA, manifest, data, secrets, databaseRel, nodeID, nil)
}

// RebindHeldRetainedMasterTreeState additionally requires the same persistent
// hold and runtime mount identity under the SQLite lease, including immediately
// before the CAS. Neither guard acquires a second maintenance lease.
func RebindHeldRetainedMasterTreeState(ctx context.Context, gate *maintenance.Gate, binding, archiveSHA string, manifest recovery.Manifest, data, secrets, databaseRel, nodeID string, verifyMounts func() error) (bool, error) {
	if gate == nil || !lowerHex(binding, 64) || verifyMounts == nil {
		return false, ErrInvalid
	}
	return rebindVerifiedRetainedMasterTreeState(ctx, gate, archiveSHA, manifest, data, secrets, databaseRel, nodeID, func(held context.Context) error {
		if err := verifyMounts(); err != nil {
			return err
		}
		return gate.VerifyTreeRecoveryHoldBinding(held, binding)
	})
}

func rebindVerifiedRetainedMasterTreeState(ctx context.Context, gate *maintenance.Gate, archiveSHA string, manifest recovery.Manifest, data, secrets, databaseRel, nodeID string, guard func(context.Context) error) (bool, error) {
	if manifest.Format != recovery.Format || manifest.Version != 2 ||
		manifest.Role != "Master" || manifest.Database != "sqlite" || manifest.Scope != recovery.UpgradeStateScope ||
		manifest.SchemaGeneration != migrations.Generation || len(manifest.Files) > recovery.MaxFiles ||
		len(manifest.Directories) > recovery.MaxFiles || len(manifest.TreeEvidence) == 0 || len(manifest.TreeEvidence) > 4096 {
		return false, ErrFenceRequired
	}
	if err := checkRetainedTreeRoots(data, secrets); err != nil {
		return false, err
	}
	report := recovery.Report{Manifest: manifest, SHA256: archiveSHA}
	target := treeRecoveryTarget{data: data, secrets: secrets, retained: true, guard: guard}
	return rebindTreeManifestAt(ctx, gate, report, target, databaseRel, MasterFenceDirectory, nodeID)
}

// RetainedTreeRebindIntentPresent blocks installation on any named intent,
// including malformed entries. The caller must hold the host operation and
// native offline fences across this observation and any file replacement.
// Absence is only one part of admission: the durable operation journal must
// also establish that the verified restore was interrupted before publication.
func RetainedTreeRebindIntentPresent(data *os.Root) (bool, error) {
	if data == nil {
		return false, ErrInvalid
	}
	_, err := data.Lstat(treeRebindIntentName)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func checkRetainedTreeRoots(paths ...string) error {
	for i, directory := range paths {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == string(os.PathSeparator) {
			return ErrInvalid
		}
		canonical, err := filepath.EvalSymlinks(directory)
		if err != nil || canonical != directory {
			return ErrFenceRequired
		}
		for _, other := range paths[:i] {
			if directory == other || strings.HasPrefix(directory, other+string(os.PathSeparator)) || strings.HasPrefix(other, directory+string(os.PathSeparator)) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// The canonical data mount is traversable for the Nginx worker. The
// runtime must own it and other users cannot write it. Keys, fence files
// and SQLite still require their own private modes and ownership checks.
func checkRetainedTreeDataDirectory(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		return ErrFenceRequired
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrFenceRequired
	}
	switch info.Mode().Perm() {
	case 0700, 0750, 0755:
		return nil
	default:
		return ErrFenceRequired
	}
}

func checkRetainedTreeSQLite(ctx context.Context, data *os.Root, database, fence string, report recovery.Report, checkDatabase bool) error {
	fenceFile := filepath.ToSlash(filepath.Join(fence, treeFenceFile))
	bindingFile := filepath.ToSlash(filepath.Join(fence, existingMasterBindingFile))
	var selection []string
	for _, entry := range report.Manifest.Files {
		if name, ok := strings.CutPrefix(entry.Path, "data/"); ok {
			selection = append(selection, name)
		}
	}
	sources := []recovery.Root{{Class: "data", IncludePaths: selection}}
	if err := validateTreeUpgradeSelection(sources, filepath.ToSlash(database), fenceFile, bindingFile); err != nil {
		return err
	}
	names := []string{fenceFile, bindingFile}
	if checkDatabase {
		names = append(names, database, database+"-wal", database+"-shm")
	}
	for _, name := range names {
		archiveName := "data/" + filepath.ToSlash(name)
		if treeArchiveContains(report, archiveName) {
			if err := verifyArchivedFile(ctx, data, name, archiveName, report); err != nil {
				return err
			}
		} else if _, err := data.Lstat(name); !os.IsNotExist(err) {
			return ErrFenceRequired
		}
	}
	return nil
}
