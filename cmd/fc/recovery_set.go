package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

type recoveryDirectories []string

func (d *recoveryDirectories) String() string { return "explicit member deployment directories" }
func (d *recoveryDirectories) Set(value string) error {
	if value == "" {
		return errors.New("empty deployment directory")
	}
	*d = append(*d, value)
	return nil
}

func recoverySetCommand(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("fc "+args[0]+" "+args[1], flag.ContinueOnError)
	var directories recoveryDirectories
	flags.Var(&directories, "deployment", "repeat once for every local Master/Storage bundle directory")
	input := flags.String("file", "", "directory holding recovery-set.json and member archives")
	output := flags.String("output", "", "absent private recovery-set output directory")
	target := flags.String("target", "", "restoration material parent; absent for set-apply")
	prefix := flags.String("project-prefix", "", "new project prefix for the entire restored set")
	offline := flags.Bool("confirm-all-sources-offline", false, "confirm every source identity is stopped on every host")
	sha := flags.String("sha256", "", "expected recovery-set manifest SHA-256")
	master := flags.String("confirm-master-id", "", "exact source Master NodeID")
	freeze := flags.Bool("freeze-all", false, "freeze and stop every explicitly listed local deployment; remain stopped")
	external := flags.Bool("confirm-external-writers-stopped", false, "confirm external MySQL writers are stopped")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
		return 2
	}
	var result any
	runners := func(directory string) operator.Runner { return dockerRunner{directory} }
	var e error
	switch args[0] + " " + args[1] {
	case "backup set-create":
		var items []operator.RecoveryDeployment
		for _, directory := range directories {
			d, r, err := operator.Open(directory)
			if err != nil {
				e = err
				break
			}
			d.Runner = dockerRunner{d.Directory}
			items = append(items, operator.RecoveryDeployment{Deployment: d, Receipt: r})
		}
		if e == nil {
			result, e = operator.BackupSet(ctx, items, *output, *master, *freeze, *external)
		}
	case "backup set-verify":
		result, e = recovery.CheckSet(ctx, *input, *sha)
	case "restore set-check":
		result, e = operator.RestoreSetCheck(ctx, *input, *target, *sha)
	case "restore set-prepare":
		result, e = operator.PrepareRestoreSet(ctx, *input, *target, *sha, *master, *prefix, runners)
	case "restore set-activate":
		result, e = operator.ActivateRestoreSet(ctx, *target, *sha, *master, *offline, runners)
	case "restore set-open":
		result, e = operator.OpenRestoreSet(ctx, *target, *sha, *master, runners)
	case "restore set-apply":
		result, e = operator.RestoreSetCheck(ctx, *input, *target, *sha)
		if e == nil {
			result, e = recovery.ApplySet(ctx, *input, *target, *sha, *master)
		}
	default:
		e = errors.New("unsupported recovery-set command")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
		fmt.Fprintln(os.Stderr, "recovery-set report output failed")
		return 2
	}
	return 0
}
