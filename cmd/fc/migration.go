package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
)

func migrationCommand(ctx context.Context, args []string, structured bool, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) < 4 {
		fmt.Fprintln(diagnostics, "fc node migrate status|pause|resume|cancel|retry|release-drain TASK_ID --master https://MASTER --credential-stdin")
		return 2
	}
	action, id := args[2], args[3]
	switch action {
	case "status", "pause", "resume", "cancel", "retry", "release-drain":
	default:
		return 2
	}
	validID := func(value string) bool {
		decoded, e := hex.DecodeString(value)
		return e == nil && len(decoded) == 16 && value == strings.ToLower(value)
	}
	if !validID(id) {
		return 2
	}
	flags := flag.NewFlagSet("fc node migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	master := flags.String("master", "", "Master HTTPS origin")
	caFile := flags.String("ca-file", "", "optional trusted public CA PEM")
	credential := flags.Bool("credential-stdin", false, "read credential from stdin")
	revision := flags.Int64("task-revision", 0, "displayed task revision required for control")
	source := flags.String("confirm-source-id", "", "exact source NodeID required for control")
	target := flags.String("confirm-target-id", "", "exact target NodeID required for control")
	after := flags.String("after", "", "logical object cursor for status page")
	if flags.Parse(args[4:]) != nil || flags.NArg() != 0 || !*credential {
		return 2
	}
	if action != "status" && (*revision < 1 || !validID(*source) || !validID(*target) || *source == *target || *after != "") {
		fmt.Fprintln(diagnostics, "control requires current revision and exact source/target NodeIDs")
		return 2
	}
	if *after != "" {
		decoded, e := hex.DecodeString(*after)
		if e != nil || len(decoded) != 32 || *after != strings.ToLower(*after) {
			return 2
		}
	}
	client, e := loginNodeClient(ctx, *master, *caFile, input)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	defer client.Close()
	if action == "status" {
		report, e := client.MigrationStatus(ctx, id, *after)
		if e != nil {
			fmt.Fprintln(diagnostics, e)
			return 2
		}
		if structured {
			if json.NewEncoder(output).Encode(report) != nil {
				return 2
			}
		} else {
			task := report.Task
			fmt.Fprintf(output, "Task: %s; state: %q; revision: %d\nSource: %s\nTarget: %s\nCommitted bytes: %d / %d; objects: %d\nError code: %q\nRetirement ready: false; perform independent retirement checks.\n", task.ID, task.State, task.Revision, task.SourceID, task.TargetID, task.CommittedBytes, task.TotalBytes, task.ObjectCount, task.ErrorCode)
			for _, stage := range report.ObjectStages {
				fmt.Fprintf(output, "Objects %q: %d; verified bytes: %d / %d\n", stage.State, stage.Count, stage.VerifiedBytes, stage.Bytes)
			}
			for _, stage := range report.UnitStages {
				fmt.Fprintf(output, "Units %q: %d; bytes: %d\n", stage.State, stage.Count, stage.Bytes)
			}
			for _, object := range report.Objects {
				fmt.Fprintf(output, "%s %q: %q; verified bytes: %d / %d\n", object.ID, object.Path, object.State, object.VerifiedBytes, object.Bytes)
			}
			if !report.Complete {
				fmt.Fprintf(output, "Next object cursor: %s\n", report.Next)
			}
		}
		return 0
	}
	task, e := client.ControlMigration(ctx, id, action, *revision, *source, *target)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	if structured {
		if json.NewEncoder(output).Encode(task) != nil {
			return 2
		}
	} else {
		fmt.Fprintf(output, "Task: %s; state: %q; revision: %d\n", task.ID, task.State, task.Revision)
		if action == "release-drain" {
			fmt.Fprintln(output, "This task-owned drain was released; other maintenance restrictions remain. This is not node retirement.")
		} else {
			fmt.Fprintln(output, "Committed units keep target ownership. Draining remains until an explicit release.")
		}
	}
	return 0
}
