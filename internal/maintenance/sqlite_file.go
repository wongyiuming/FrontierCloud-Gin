package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// InspectSQLiteFile opens the selected DATA_ROOT database read-only while the
// existing persistent maintenance marker and both native lifecycle leases are
// held. The callback must consume this exact FD, not reopen databasePath or use
// a previously pooled SQL connection. check must be called before accepting
// each externally visible result; it rejects replaced paths, closed FDs and
// ordinary size/modification changes while the lease is held.
//
// This is a local cooperative-process fence, not proof that legacy/unmanaged
// writers stopped, SQLite WAL is checkpointed, database contents are complete,
// an ABA write did not occur, a snapshot is authenticated, or a remote owner
// is safe. A caller must independently establish those conditions. This method
// has no product route and never changes a database or maintenance marker.
func (g *Gate) InspectSQLiteFile(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, *os.File, func() error) error) error {
	if g == nil || ctx == nil || offline == nil {
		return ErrState
	}
	return g.InspectSQLite(ctx, dataRoot, databasePath, func(held context.Context, checkLease func() error) error {
		if checkLease() != nil {
			return ErrState
		}
		rootPath, err := filepath.Abs(g.root.Name())
		if err != nil {
			return ErrState
		}
		absolute, err := filepath.Abs(databasePath)
		if err != nil {
			return ErrState
		}
		relative, err := filepath.Rel(rootPath, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return ErrState
		}
		before, err := g.root.Lstat(relative)
		if err != nil || !privateSingleLink(before) {
			return ErrState
		}
		file, err := g.root.Open(relative)
		if err != nil {
			return ErrState
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !privateSingleLink(opened) || !os.SameFile(before, opened) {
			return ErrState
		}
		checkFile := func() error {
			if held.Err() != nil || checkLease() != nil {
				return ErrState
			}
			current, e := g.root.Lstat(relative)
			if e != nil || !privateSingleLink(current) || !os.SameFile(opened, current) || current.Size() != opened.Size() || !current.ModTime().Equal(opened.ModTime()) {
				return ErrState
			}
			actual, e := file.Stat()
			if e != nil || !privateSingleLink(actual) || !os.SameFile(opened, actual) || actual.Size() != opened.Size() || !actual.ModTime().Equal(opened.ModTime()) {
				return ErrState
			}
			return nil
		}
		if checkFile() != nil {
			return ErrState
		}
		if err = offline(held, file, checkFile); err != nil {
			return err
		}
		return checkFile()
	})
}

// InspectSQLiteCleanFile is a deliberately strict prerequisite for a future
// offline, read-only file capture: the held file must have a rollback-journal
// header and no WAL, SHM or rollback-journal sidecars. It never checkpoints,
// removes files, changes journal mode, or asserts that unmanaged writers have
// stopped. An active or crash-recovery WAL therefore remains blocked until a
// separate identity-bound, crash-safe recovery procedure has completed.
func (g *Gate) InspectSQLiteCleanFile(ctx context.Context, dataRoot, databasePath string, offline func(context.Context, *os.File, func() error) error) error {
	if g == nil || ctx == nil || offline == nil {
		return ErrState
	}
	return g.InspectSQLiteFile(ctx, dataRoot, databasePath, func(held context.Context, file *os.File, checkFile func() error) error {
		rootPath, err := filepath.Abs(g.root.Name())
		if err != nil {
			return ErrState
		}
		absolute, err := filepath.Abs(databasePath)
		if err != nil {
			return ErrState
		}
		relative, err := filepath.Rel(rootPath, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return ErrState
		}
		checkClean := func() error {
			if checkFile() != nil {
				return ErrState
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, e := g.root.Lstat(relative + suffix); !errors.Is(e, os.ErrNotExist) {
					return ErrState
				}
			}
			var header [100]byte
			if _, e := file.ReadAt(header[:], 0); e != nil || string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
				return ErrState
			}
			return checkFile()
		}
		if checkClean() != nil {
			return ErrState
		}
		if err = offline(held, file, checkClean); err != nil {
			return err
		}
		return checkClean()
	})
}
