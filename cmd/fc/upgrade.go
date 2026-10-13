package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

func upgradeCommand(ctx context.Context, directory, revision string, args []string, out, diagnostic io.Writer) int {
	if len(args) < 2 {
		return 2
	}
	flags := flag.NewFlagSet("fc upgrade "+args[1], flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	planFile := flags.String("plan", "", "saved JSON from upgrade plan")
	approval := flags.String("approve-plan-sha256", "", "exact reviewed plan SHA-256")
	node := flags.String("confirm-node-id", "", "exact source NodeID")
	backup := flags.String("backup-output", "", "new private consistent recovery archive path")
	external := flags.Bool("confirm-external-writers-stopped", false, "confirm external MySQL writers are stopped")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
		return 2
	}
	d, r, e := operator.Open(directory)
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		return 2
	}
	d.Runner = dockerRunner{d.Directory}
	var value any
	switch args[1] {
	case "plan", "apply", "resume":
		registry := release.NewRegistryClient()
		defer registry.Close()
		verifier, err := release.NewVerifier(release.DefaultPolicy(), "")
		if err != nil {
			e = err
			break
		}
		if args[1] == "resume" {
			if *planFile != "" || *backup != "" || revision != "" {
				e = errors.New("upgrade resume requires only the recorded plan digest, NodeID and any MySQL external-writer confirmation")
				break
			}
			value, e = d.ResumeUpgrade(ctx, r, *approval, *node, *external, verifier, registry)
		} else if args[1] == "plan" {
			if !release.ValidSHA(revision) || *planFile != "" || *approval != "" || *node != "" || *backup != "" || *external {
				e = errors.New("upgrade plan requires only an explicit --revision; redirect its JSON output to a new plan file")
				break
			}
			raw, err := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
			if err != nil {
				e = err
				break
			}
			value, e = d.PlanUpgrade(ctx, r, revision, operator.Architecture(string(raw)), verifier, registry)
		} else {
			p, err := operator.ReadUpgradePlan(*planFile)
			if err != nil {
				e = err
				break
			}
			if revision != "" && revision != p.Target {
				e = errors.New("explicit revision differs from the approved plan")
				break
			}
			value, e = d.ApplyUpgrade(ctx, r, p, *approval, *node, *backup, *external, verifier, registry)
		}
	case "open":
		if *planFile != "" || *backup != "" || *external || revision != "" {
			e = errors.New("upgrade open accepts only the approved plan digest and NodeID")
			break
		}
		value, e = d.OpenUpgrade(ctx, r, *approval, *node)
	default:
		e = errors.New("upgrade requires plan, apply, resume or open")
	}
	if e != nil {
		fmt.Fprintln(diagnostic, e)
		return 2
	}
	if e = json.NewEncoder(out).Encode(value); e != nil {
		fmt.Fprintln(diagnostic, "upgrade report output failed")
		return 2
	}
	return 0
}
