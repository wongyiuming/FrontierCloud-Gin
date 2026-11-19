package maintenance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
)

const ownerImportHoldContent = "frontiercloud-owner-import-hold-v1\n"

// ownerImportHeld intentionally treats every existing filesystem object as a
// hold, even if malformed. A corrupted or substituted marker cannot reopen
// a stopped Owner's old writer.
func (g *Gate) ownerImportHeld() (bool, error) {
	if g == nil || g.root == nil {
		return true, ErrState
	}
	_, err := g.root.Lstat(OwnerImportHold)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return true, nil
}

// InspectSQLiteOwnerImport authenticates a plan before arming a durable hold,
// then performs the Owner operation under the same maintenance leases. The
// hold has no release operation until complete Owner reconciliation exists.
func (g *Gate) InspectSQLiteOwnerImport(ctx context.Context, dataRoot, databasePath string, authorize func(context.Context, func() error) (func(), error), work func(context.Context, func() error) error) error {
	if authorize == nil || work == nil {
		return ErrState
	}
	return g.InspectSQLite(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		release, err := authorize(held, check)
		if release != nil {
			defer release()
		}
		if err != nil {
			return err
		}
		if release == nil {
			return ErrState
		}
		if err := g.armOwnerImportHeld(held, check); err != nil {
			return err
		}
		if err := work(held, check); err != nil {
			return err
		}
		return check()
	})
}

func (g *Gate) armOwnerImportHeld(ctx context.Context, check func() error) error {
	if g == nil || g.root == nil || ctx == nil || check == nil || ctx.Err() != nil || check() != nil {
		return ErrState
	}
	enabled, err := g.Enabled()
	if err != nil || !enabled {
		return ErrState
	}
	info, err := g.root.Lstat(OwnerImportHold)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(ownerImportHoldContent)) {
			return ErrState
		}
		file, e := g.root.Open(OwnerImportHold)
		if e != nil {
			return ErrState
		}
		opened, e := file.Stat()
		if e != nil || !os.SameFile(info, opened) {
			file.Close()
			return ErrState
		}
		data, e := io.ReadAll(io.LimitReader(file, int64(len(ownerImportHoldContent))+1))
		closeErr := file.Close()
		if e != nil || closeErr != nil || string(data) != ownerImportHoldContent || check() != nil {
			return ErrState
		}
		return ctx.Err()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrState
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ErrState
	}
	temp := ".owner-import-hold-" + hex.EncodeToString(random[:])
	file, err := g.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrState
	}
	defer g.root.Remove(temp)
	if err = fsutil.InheritOwner(file, g.root); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.WriteString(ownerImportHoldContent)
	syncErr, closeErr := file.Sync(), file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err = g.root.Link(temp, OwnerImportHold); err != nil {
		return ErrState
	}
	if err = fsutil.SyncDirectory(g.root, "."); err != nil {
		return err
	}
	if ctx.Err() != nil || check() != nil {
		return ErrState
	}
	return nil
}
