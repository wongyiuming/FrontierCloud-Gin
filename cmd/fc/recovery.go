package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func recoveryCommand(ctx context.Context, directory string, args []string) int {
	if len(args) < 2 {
		return 2
	}
	if args[1] == "set-create" || args[1] == "set-verify" || args[1] == "set-check" || args[1] == "set-apply" || args[1] == "set-prepare" || args[1] == "set-activate" || args[1] == "set-open" {
		return recoverySetCommand(ctx, args)
	}
	action := args[0] + " " + args[1]
	flags := flag.NewFlagSet("fc "+action, flag.ContinueOnError)
	input := flags.String("file", "", "recovery archive")
	output := flags.String("output", "", "new private archive path")
	target := flags.String("target", "", "absent restoration material directory")
	checksum := flags.String("sha256", "", "expected archive SHA-256")
	confirmation := flags.String("confirm-node-id", "", "exact source NodeID confirmation")
	project := flags.String("project", "", "explicit empty target Compose project")
	prepare := flags.Bool("deployment", false, "prepare restored Compose deployment behind the preserved offline fence")
	sourceOffline := flags.Bool("confirm-source-offline", false, "confirm source identity is no longer running on any host")
	freeze := flags.Bool("freeze", false, "enter native maintenance and stop this deployment's writers; remains stopped after backup")
	external := flags.Bool("confirm-external-writers-stopped", false, "confirm all external MySQL writers are stopped")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
		return 2
	}
	var report recovery.Report
	var err error
	switch action {
	case "backup create":
		var d *operator.Deployment
		var receipt operator.Receipt
		d, receipt, err = operator.Open(directory)
		if err == nil {
			d.Runner = dockerRunner{d.Directory}
			report, err = d.Backup(ctx, receipt, *output, *freeze, *external)
		}
	case "backup verify":
		report, err = recovery.Check(ctx, *input, *checksum)
	case "restore check":
		report, err = operator.RestoreCheck(ctx, *input, *target, *checksum)
	case "restore apply":
		if *target == "" {
			err = errors.New("restore target required")
		} else {
			if *prepare && *project == "" {
				fmt.Fprintln(os.Stderr, "deployment recovery requires an explicit target project")
				return 2
			}
			if _, err = operator.RestoreCheck(ctx, *input, *target, *checksum); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			report, err = recovery.Apply(ctx, *input, *target, *checksum, *confirmation)
			if err == nil && *prepare {
				_, _, err = operator.PrepareRestore(ctx, *target, *project, report, dockerRunner{Directory: filepath.Join(*target, "deployment")})
			}
		}
	case "restore activate", "restore open":
		d, r, e := operator.Open(directory)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		d.Runner = dockerRunner{d.Directory}
		var state operator.RestoreState
		if action == "restore activate" {
			state, err = d.ActivateRestore(ctx, r, *confirmation, *sourceOffline)
		} else {
			state, err = d.OpenRestore(ctx, r, *confirmation)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return 0
	default:
		err = errors.New("unsupported recovery command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return 0
}
