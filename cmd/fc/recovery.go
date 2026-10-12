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

func recoveryCommand(ctx context.Context, directory string, args []string) int {
	if len(args) < 2 {
		return 2
	}
	action := args[0] + " " + args[1]
	flags := flag.NewFlagSet("fc "+action, flag.ContinueOnError)
	input := flags.String("file", "", "recovery archive")
	output := flags.String("output", "", "new private archive path")
	target := flags.String("target", "", "absent restoration material directory")
	checksum := flags.String("sha256", "", "expected archive SHA-256")
	confirmation := flags.String("confirm-node-id", "", "exact source NodeID confirmation")
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
		report, err = recovery.Check(ctx, *input, *checksum)
		if err == nil {
			if *target == "" {
				err = errors.New("restore target required")
			} else if _, e := os.Lstat(*target); !errors.Is(e, os.ErrNotExist) {
				err = errors.New("restore target must not exist; check does not overwrite or create it")
			}
		}
	case "restore apply":
		if *target == "" {
			err = errors.New("restore target required")
		} else {
			report, err = recovery.Apply(ctx, *input, *target, *checksum, *confirmation)
		}
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
