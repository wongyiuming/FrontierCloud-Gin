package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
)

func migrationPlanCommand(ctx context.Context, args []string, structured bool, input io.Reader, output, diagnostics io.Writer) int {
	action := args[2]
	flags := flag.NewFlagSet("fc node migrate "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	master := flags.String("master", "", "Master HTTPS origin")
	ca := flags.String("ca-file", "", "trusted public CA PEM")
	credential := flags.Bool("credential-stdin", false, "read credential from stdin")
	source := flags.String("from", "", "source NodeID")
	target := flags.String("to", "", "target NodeID")
	id := flags.String("plan", "", "reviewed plan ID")
	review := flags.String("review-sha256", "", "reviewed plan SHA256")
	confirmSource := flags.String("confirm-source-id", "", "exact source NodeID")
	confirmTarget := flags.String("confirm-target-id", "", "exact target NodeID")
	after := flags.String("after", "", "object page cursor")
	if flags.Parse(args[3:]) != nil || flags.NArg() != 0 || !*credential {
		return 2
	}
	if action == "plan" && (*source == "" || *target == "" || *id != "" || *review != "" || *confirmSource != "" || *confirmTarget != "" || *after != "") || action == "plan-status" && (*id == "" || *source != "" || *target != "" || *review != "" || *confirmSource != "" || *confirmTarget != "") || action == "start" && (*id == "" || *review == "" || *confirmSource == "" || *confirmTarget == "" || *source != "" || *target != "" || *after != "") {
		fmt.Fprintln(diagnostics, "plan requires --from/--to; plan-status requires --plan; start requires --plan, --review-sha256 and exact --confirm-source-id/--confirm-target-id")
		return 2
	}
	client, e := loginNodeClient(ctx, *master, *ca, input)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	defer client.Close()
	var v resourcemigration.PlanView
	switch action {
	case "plan":
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e == nil {
			v, e = client.CreateMigrationPlan(ctx, hex.EncodeToString(nonce[:]), *source, *target)
		}
	case "plan-status":
		v, e = client.MigrationPlanStatus(ctx, *id, *after)
	case "start":
		v, e = client.StartMigrationPlan(ctx, *id, *review, *confirmSource, *confirmTarget)
	}
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	if structured {
		if json.NewEncoder(output).Encode(v) != nil {
			return 2
		}
	} else {
		fmt.Fprintf(output, "Plan: %s; state: %q\nSource: %s (%s)\nTarget: %s (%s)\nObjects: %d; complete parent units: %d; bytes: %d\nVerified: %d objects / %d bytes\nTarget used/reserved/free: %d / %d / %d; additional bytes: %d; physical reserve: %d\nReview SHA256: %s\nExpires: %d\n", v.ID, v.State, v.Source.ID, v.Source.Transport, v.Target.ID, v.Target.Transport, v.ObjectCount, v.UnitCount, v.Bytes, v.VerifiedObjects, v.VerifiedBytes, v.Target.Used, v.Target.Reserved, v.TargetFree, v.AdditionalBytes, v.PhysicalReserve, v.ReviewSHA, v.ExpiresAt)
		if v.BlockerCount>0 {fmt.Fprintf(output,"Blockers: %d (up to 64 samples shown)\n",v.BlockerCount)}
		for _, b := range v.Blockers {
			fmt.Fprintf(output, "BLOCK %q: %q\n", b.Code, b.Resource)
		}
		for _, c := range v.Concerns {
			fmt.Fprintf(output, "SOURCE RESIDUAL %q: %d; samples: %q\n", c.Code, c.Count, c.Samples)
		}
		for _, o := range v.Objects {
			fmt.Fprintf(output, "%s %q: %d bytes; parent %q\n", o.ID, o.Path, o.Bytes, o.Parent)
		}
		if v.ErrorCode != "" {
			fmt.Fprintf(output, "Error: %q; stage: %q; regenerate the plan after resolving the cause.\n", v.ErrorCode, v.ErrorStage)
		}
		if !v.Complete {
			fmt.Fprintf(output, "Next object cursor: %s\n", v.Next)
		}
		if v.Task != nil {
			fmt.Fprintf(output, "Durable task: %s; state: %q\n", v.Task.ID, v.Task.State)
		} else {
			fmt.Fprintf(output, "Continue: fc node migrate plan-status --plan %s --master HTTPS_ORIGIN --credential-stdin\n", v.ID)
		}
		fmt.Fprintln(output, "Planning is read-only. Start rechecks native bytes before reserving and draining. Backups and source residuals require separate retirement handling.")
	}
	if v.State == "failed" || v.State == "blocked" || v.State == "expired" {
		return 1
	}
	return 0
}
