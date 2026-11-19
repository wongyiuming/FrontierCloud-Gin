//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func resumeBusinessStateCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("resume-business-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterID := flags.String("target-master-id", "", "existing imported SQLite Master ID")
	mountProof := flags.String("mount-proof", "", "exact mounted data and secrets identity")
	manualProof := flags.String("manual-proof", "", "device and inode of existing public maintenance marker")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || !node.ValidIdentifier(*masterID) || output == nil {
		return errors.New("resume-business-state requires pinned target, mount and manual maintenance identities")
	}
	deviceText, inodeText, found := strings.Cut(*manualProof, ":")
	device, deviceErr := strconv.ParseUint(deviceText, 10, 64)
	inode, inodeErr := strconv.ParseUint(inodeText, 10, 64)
	if !found || deviceErr != nil || inodeErr != nil || inode == 0 || strconv.FormatUint(device, 10) != deviceText || strconv.FormatUint(inode, 10) != inodeText {
		return maintenance.ErrState
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	checkAvailable, err := businessStateTargetGuard(settings, *mountProof)
	if err != nil {
		return err
	}
	if err := checkAvailable(); err != nil {
		return err
	}
	gate, err := maintenance.OpenExisting(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	root, err := os.OpenRoot(settings.DataRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	checkRoot := func() error {
		named, err := os.Lstat(settings.DataRoot)
		opened, statErr := root.Stat(".")
		if err != nil || statErr != nil || !named.IsDir() || !os.SameFile(named, opened) {
			return maintenance.ErrState
		}
		return checkAvailable()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var releaseSite func()
	var manual *os.File
	defer func() {
		if manual != nil {
			_ = manual.Close()
		}
		if releaseSite != nil {
			releaseSite()
		}
	}()
	err = gate.ResumeExistingSQLite(ctx, settings.DataRoot, settings.SQLitePath, func(held context.Context, check func() error) error {
		if err := checkRoot(); err != nil {
			return err
		}
		// Keep this lease outside the validation callback. The native gate still
		// has to remove and sync its own marker after the callback returns.
		releaseSite, err = sitecontrol.Lease(held, root, true)
		if err != nil {
			return err
		}
		manual, err = root.OpenFile(sitecontrol.Manual, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return maintenance.ErrState
		}
		if err := checkBusinessManualMarker(root, manual, device, inode); err != nil {
			return err
		}
		if err := verifyBusinessResumeTarget(held, settings, *masterID, root, check); err != nil {
			return err
		}
		if err := checkRoot(); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		return checkBusinessManualMarker(root, manual, device, inode)
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(runtimefacts.BusinessNativeResumeReport{TargetMasterID: *masterID, Resumed: true})
}

func checkBusinessManualMarker(root *os.Root, file *os.File, device, inode uint64) error {
	const contents = "manual\n"
	valid := func(info os.FileInfo) bool {
		if info == nil || !sitecontrol.ValidManualMode(info.Mode()) || info.Size() != int64(len(contents)) {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && uint64(st.Dev) == device && st.Ino == inode && st.Nlink == 1 && st.Uid == uint32(os.Geteuid()) && st.Gid == uint32(os.Getegid())
	}
	before, err := file.Stat()
	if err != nil || !valid(before) {
		return maintenance.ErrState
	}
	var raw [len(contents)]byte
	if _, err := file.ReadAt(raw[:], 0); err != nil || string(raw[:]) != contents {
		return maintenance.ErrState
	}
	after, err := file.Stat()
	named, nameErr := root.Lstat(sitecontrol.Manual)
	if err != nil || nameErr != nil || !valid(after) || !valid(named) || !os.SameFile(before, after) || !os.SameFile(after, named) ||
		before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim || after.Sys().(*syscall.Stat_t).Ctim != named.Sys().(*syscall.Stat_t).Ctim {
		return maintenance.ErrState
	}
	if _, err := root.Lstat(sitecontrol.ForceOpen); !os.IsNotExist(err) {
		return maintenance.ErrState
	}
	return nil
}

func verifyBusinessResumeTarget(ctx context.Context, settings config.Config, masterID string, root *os.Root, check func() error) error {
	if _, err := deployment.ReadRetainedBinding(settings); err != nil {
		return err
	}
	db, err := sqlitestore.OpenReadOnly(ctx, settings.SQLitePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.VerifyPreparedRuntime(ctx); err != nil {
		return err
	}
	identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
	if err != nil || identity.ID != masterID || identity.Role != "Master" {
		return backup.ErrBusinessStateTarget
	}
	if err := identity.CheckNativeRuntime(ctx, settings.DataRoot); err != nil {
		return err
	}
	owner, err := openRuntimeOwner(ctx, settings, db, identity)
	if err != nil || owner == nil {
		return backup.ErrBusinessStateTarget
	}
	defer owner.Close()
	tree, closeTree, err := openOpaqueMasterTree(ctx, db, settings)
	if err != nil || tree == nil || closeTree == nil {
		return backup.ErrBusinessStateTarget
	}
	defer closeTree()
	if err := verifyFreshBusinessResources(ctx, db, root); err != nil {
		return err
	}
	snapshot, err := db.Maintenance().InspectMaintenance(ctx)
	if err != nil || snapshot.Role != "Master" || snapshot.LogicalIdle || snapshot.Pending["sealed_tree_unrecoverable"] != 1 {
		return backup.ErrBusinessStateTarget
	}
	for name, count := range snapshot.Pending {
		if name != "sealed_tree_unrecoverable" && count != 0 {
			return backup.ErrBusinessStateTarget
		}
	}
	s3, err := business.OpenSelectedS3FileGate(root, tree, func(context.Context) error { return check() })
	if err != nil {
		return err
	}
	return s3.Close()
}
