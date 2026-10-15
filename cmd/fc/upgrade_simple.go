package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

func upgradeConsent(ctx context.Context, input io.Reader, output io.Writer, yes, external bool, p operator.UpgradePreview) (operator.UpgradeConsent, error) {
	if e := ctx.Err(); e != nil {
		return operator.UpgradeConsent{}, e
	}
	if _, e := fmt.Fprintf(output, "Upgrade %s: %s -> %s; database %s generation %d -> %d\n", p.Plan.Project, p.Plan.From, p.Plan.Target, p.Plan.Database, p.Plan.FromGeneration, p.Plan.Generation); e != nil {
		return operator.UpgradeConsent{}, e
	}
	if p.Capacity != nil {
		if _, e := fmt.Fprintf(output, "State backup: at most %d bytes; required free %d; available %d. Media, lyrics and recordings excluded.\n", p.Capacity.ArchiveBytes, p.Capacity.RequiredBytes, p.Capacity.FreeBytes); e != nil {
			return operator.UpgradeConsent{}, e
		}
	} else {
		if _, e := fmt.Fprintf(output, "Continue recorded phase: %s; retain the existing recovery point.\n", p.ResumePhase); e != nil {
			return operator.UpgradeConsent{}, e
		}
	}
	if p.Plan.Database == "mysql" {
		if _, e := fmt.Fprintln(output, "Confirmation also attests that all external MySQL writers are stopped."); e != nil {
			return operator.UpgradeConsent{}, e
		}
		if yes && !external {
			return operator.UpgradeConsent{}, errors.New("noninteractive MySQL upgrade requires --confirm-external-writers-stopped")
		}
	}
	if yes {
		return operator.UpgradeConsent{Approved: true, ExternalWritersStopped: external}, nil
	}
	if _, e := fmt.Fprint(output, "Stop writes, prepare and verify the target, then open traffic? [y/N] "); e != nil {
		return operator.UpgradeConsent{}, e
	}
	type answerLine struct {
		line []byte
		err  error
	}
	answers := make(chan answerLine, 1)
	go func() {
		line, err := bufio.NewReaderSize(input, 4096).ReadSlice('\n')
		answers <- answerLine{line, err}
	}()
	var line []byte
	var e error
	select {
	case <-ctx.Done():
		return operator.UpgradeConsent{}, ctx.Err()
	case answer := <-answers:
		line, e = answer.line, answer.err
	}
	if e != nil {
		return operator.UpgradeConsent{}, errors.New("confirmation unavailable; use --yes only for an explicitly approved noninteractive upgrade")
	}
	answer := strings.ToLower(strings.TrimSpace(string(line)))
	approved := answer == "y" || answer == "yes"
	return operator.UpgradeConsent{Approved: approved, ExternalWritersStopped: approved && p.Plan.Database == "mysql"}, nil
}

func simpleUpgradeCommand(ctx context.Context, directory, revision string, args []string, input io.Reader, out, diagnostic io.Writer, structured bool) int {
	flags := flag.NewFlagSet("foc upgrade", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	yes := flags.Bool("yes", false, "approve the displayed upgrade without interactive input")
	external := flags.Bool("confirm-external-writers-stopped", false, "confirm external MySQL writers are stopped for --yes")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !release.ValidSHA(revision) {
		fmt.Fprintln(diagnostic, "foc upgrade --revision FULL_PUBLISHED_MAIN_SHA [--yes]")
		return 2
	}
	d, r, e := operator.Open(directory)
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		return 2
	}
	d.Runner = dockerRunner{d.Directory}
	raw, e := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		return 2
	}
	verifier, e := hostReleaseVerifier()
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		return 2
	}
	registry := release.NewRegistryClient()
	defer registry.Close()
	result, e := d.Upgrade(ctx, r, revision, operator.Architecture(string(raw)), verifier, registry, func(p operator.UpgradePreview) (operator.UpgradeConsent, error) {
		return upgradeConsent(ctx, input, diagnostic, *yes, *external, p)
	})
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		if result.Phase != "" {
			fmt.Fprintf(diagnostic, "Recorded upgrade phase: %s; inspect foc status and the retained journal.\n", result.Phase)
		}
		return 2
	}
	if structured {
		e = writeOperatorOutput(out, true, result)
	} else {
		_, e = fmt.Fprintf(out, "%s: %s; database generation %d\n", result.Phase, result.Revision, result.Generation)
		if e == nil && result.BackupFile != "" {
			_, e = fmt.Fprintf(out, "Verified state recovery point: %s\n", result.BackupFile)
		}
	}
	if e != nil {
		fmt.Fprintln(diagnostic, "upgrade result output failed; inspect foc status and the retained upgrade journal")
		return 2
	}
	return 0
}
