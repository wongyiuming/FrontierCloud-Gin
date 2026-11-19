package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func recoveryCommand(ctx context.Context, directory string, args []string) int {
	return recoveryCommandOutput(ctx, directory, args, os.Stdout, os.Stderr)
}

func recoveryCommandOutput(ctx context.Context, directory string, args []string, outputWriter, errorWriter io.Writer) int {
	if len(args) < 2 {
		return 2
	}
	if args[0] == "restore" {
		switch args[1] {
		case "prepare-business-state":
			return prepareBusinessStateCommand(ctx, directory, args[2:], outputWriter, errorWriter)
		case "import-business-state":
			return importBusinessStateCommand(ctx, directory, args[2:], outputWriter, errorWriter)
		case "activate-business-state":
			return activateBusinessStateCommand(ctx, directory, args[2:], outputWriter, errorWriter)
		}
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
	full := flags.Bool("include-business-files", false, "explicit full disaster-recovery archive including media, lyrics and recordings")
	stateLoss := flags.Bool("confirm-state-loss", false, "accept loss of database/configuration changes since the selected state backup")
	recoveryDirectory := flags.String("recovery-directory", "", "new private failed-state retention and restoration directory")
	approval := flags.String("approve-plan-sha256", "", "exact digest returned by state restoration for separate opening")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
		return 2
	}
	if *full && action != "backup plan" && action != "backup create" {
		return 2
	}
	if action == "backup plan" {
		d, r, e := operator.Open(directory)
		if e != nil {
			fmt.Fprintln(errorWriter, e)
			return 2
		}
		d.Runner = dockerRunner{d.Directory}
		capacity := d.UpgradeBackupCapacity
		if *full {
			capacity = d.BackupCapacity
		}
		plan, e := capacity(ctx, r, *output)
		if e != nil {
			fmt.Fprintln(errorWriter, e)
			return 2
		}
		if e = json.NewEncoder(outputWriter).Encode(plan); e != nil {
			return 2
		}
		if !plan.Fits {
			return 2
		}
		return 0
	}
	var report recovery.Report
	var err error
	switch action {
	case "restore state-check", "restore state", "restore state-open":
		d, r, e := operator.Open(directory)
		if e != nil {
			err = e
			break
		}
		d.Runner = dockerRunner{d.Directory}
		if action == "restore state-check" {
			report, _, err = d.StateRestoreCheck(ctx, r, *input, *checksum)
		} else {
			var state operator.UpgradeState
			if action == "restore state-open" {
				state, err = d.OpenUpgrade(ctx, r, *approval, *confirmation)
			} else {
				state, err = d.RestoreState(ctx, r, *input, *checksum, *confirmation, *recoveryDirectory, *sourceOffline, *stateLoss, *freeze, *external)
			}
			if err != nil {
				fmt.Fprintln(errorWriter, err)
				return 2
			}
			return encodeRecoveryOutput(outputWriter, errorWriter, state)
		}
	case "backup create":
		var d *operator.Deployment
		var receipt operator.Receipt
		d, receipt, err = operator.Open(directory)
		if err == nil {
			d.Runner = dockerRunner{d.Directory}
			backup := d.BackupState
			if *full {
				backup = d.Backup
			}
			report, err = backup(ctx, receipt, *output, *freeze, *external)
		}
	case "backup verify":
		if *checksum == "" {
			if d, _, openErr := operator.Open(directory); openErr == nil {
				var matched bool
				report, matched, err = d.VerifyRecordedUpgradeBackup(ctx, *input)
				if matched {
					break
				}
			}
		}
		report, err = recovery.Check(ctx, *input, *checksum)
		if err != nil && *checksum != "" {
			report, err = recovery.CheckTreeArchiveAuthenticated(ctx, *input, *checksum)
		}
	case "restore check":
		report, err = operator.RestoreCheck(ctx, *input, *target, *checksum)
	case "restore prepare":
		if *target == "" || *project == "" || *checksum == "" || *confirmation == "" {
			err = errors.New("restore prepare requires existing material, source archive/checksum, original NodeID and target project")
			break
		}
		report, err = recovery.Check(ctx, *input, *checksum)
		if err != nil {
			break
		}
		if report.Manifest.NodeID != *confirmation {
			err = errors.New("restore preparation NodeID mismatch")
			break
		}
		if len(report.Manifest.Missing) != 0 {
			err = errors.New("incomplete related-node recovery requires a verified coordinated recovery set")
			break
		}
		deployment := filepath.Join(*target, "deployment")
		check := recovery.CheckMaterial
		if _, e := os.Lstat(filepath.Join(deployment, operator.RestoreJournal)); e == nil {
			check = recovery.CheckPreparingMaterial
		} else if !os.IsNotExist(e) {
			err = e
			break
		}
		if err = check(ctx, *target, report); err != nil {
			break
		}
		_, _, err = operator.PrepareRestore(ctx, *target, *project, report, dockerRunner{Directory: deployment})
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
		return encodeRecoveryOutput(outputWriter, errorWriter, state)
	default:
		err = errors.New("unsupported recovery command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return encodeRecoveryOutput(outputWriter, errorWriter, report)
}

func prepareBusinessStateCommand(ctx context.Context, directory string, args []string, output, diagnostic io.Writer) int {
	if !filepath.IsAbs(directory) {
		fmt.Fprintln(diagnostic, "business state preparation requires an explicit absolute --directory")
		return 2
	}
	flags := flag.NewFlagSet("fc restore prepare-business-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterID := flags.String("target-master-id", "", "exact destination Master ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !node.ValidIdentifier(*masterID) {
		fmt.Fprintln(diagnostic, "business state preparation requires an exact --target-master-id")
		return 2
	}
	d, receipt, err := openSelectedBusinessStateDeployment(directory)
	if err != nil {
		fmt.Fprintln(diagnostic, "cannot open the selected Master deployment")
		return 2
	}
	report, err := d.PrepareBusinessState(ctx, receipt, *masterID)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	return encodeRecoveryOutput(output, diagnostic, report)
}

func importBusinessStateCommand(ctx context.Context, directory string, args []string, output, diagnostic io.Writer) int {
	if !filepath.IsAbs(directory) {
		fmt.Fprintln(diagnostic, "business state import requires an explicit absolute --directory")
		return 2
	}
	flags := flag.NewFlagSet("fc restore import-business-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("file", "", "absolute path of the private v2 business state artifact")
	generation := flags.Int64("generation", 0, "recorded v2 artifact generation")
	checksum := flags.String("sha256", "", "independently recorded artifact SHA-256")
	size := flags.Int64("bytes", 0, "recorded artifact length")
	masterID := flags.String("target-master-id", "", "exact prepared destination Master ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(diagnostic, "business state import accepts --file, --generation, --sha256, --bytes and --target-master-id")
		return 2
	}
	if !filepath.IsAbs(*input) || *generation <= 0 || !validBusinessStateChecksum(*checksum) ||
		*size <= 0 || *size > backup.MaxBusinessStateBytes || !node.ValidIdentifier(*masterID) {
		fmt.Fprintln(diagnostic, "business state import requires an absolute --file, exact artifact --generation, --sha256, --bytes and --target-master-id")
		return 2
	}
	d, receipt, err := openSelectedBusinessStateDeployment(directory)
	if err != nil {
		fmt.Fprintln(diagnostic, "cannot open the selected prepared Master deployment")
		return 2
	}
	expected := backup.Expectation{Generation: *generation, Checksum: *checksum, Bytes: *size}
	report, err := d.ImportBusinessState(ctx, receipt, *input, expected, *masterID)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	return encodeRecoveryOutput(output, diagnostic, report)
}

func activateBusinessStateCommand(ctx context.Context, directory string, args []string, output, diagnostic io.Writer) int {
	if !filepath.IsAbs(directory) {
		fmt.Fprintln(diagnostic, "business state activation requires an explicit absolute --directory")
		return 2
	}
	flags := flag.NewFlagSet("fc restore activate-business-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	masterID := flags.String("target-master-id", "", "exact prepared destination Master ID")
	sourceSHA := flags.String("source-sha256", "", "independently recorded source artifact SHA-256")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !node.ValidIdentifier(*masterID) || !validBusinessStateChecksum(*sourceSHA) {
		fmt.Fprintln(diagnostic, "business state activation requires an exact --target-master-id and --source-sha256")
		return 2
	}
	d, receipt, err := openSelectedBusinessStateDeployment(directory)
	if err != nil {
		fmt.Fprintln(diagnostic, "cannot open the selected prepared Master deployment")
		return 2
	}
	report, err := d.ActivateBusinessState(ctx, receipt, *masterID, *sourceSHA)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	return encodeRecoveryOutput(output, diagnostic, report)
}

func validBusinessStateChecksum(checksum string) bool {
	if len(checksum) != 64 || checksum != strings.ToLower(checksum) {
		return false
	}
	_, err := hex.DecodeString(checksum)
	return err == nil
}

func openSelectedBusinessStateDeployment(directory string) (*operator.Deployment, operator.Receipt, error) {
	if info, err := os.Lstat(filepath.Clean(directory)); err != nil || !info.IsDir() {
		return nil, operator.Receipt{}, recovery.ErrUnsafe
	}
	d, receipt, err := operator.Open(directory)
	if err != nil {
		return nil, receipt, err
	}
	d.Runner = dockerRunner{d.Directory}
	return d, receipt, nil
}

func encodeRecoveryOutput(output, diagnostic io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		fmt.Fprintln(diagnostic, "recovery operation output could not be written; preserve its recorded state and recovery material")
		return 2
	}
	return 0
}
