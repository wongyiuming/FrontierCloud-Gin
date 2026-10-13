package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"io"
	"os"
	"strings"
)

func nodeCommand(ctx context.Context, args []string, structured bool, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) > 1 && args[1] == "migrate" {
		return migrationCommand(ctx, args, structured, input, output, diagnostics)
	}
	if len(args) < 4 || args[1] != "retire" || args[2] != "check" {
		fmt.Fprintln(diagnostics, "supported: fc node retire check NODE_ID --master https://MASTER --credential-stdin")
		return 2
	}
	member := args[3]
	decoded, err := hex.DecodeString(member)
	if err != nil || len(decoded) != 16 || member != strings.ToLower(member) {
		fmt.Fprintln(diagnostics, "invalid node identifier")
		return 2
	}
	flags := flag.NewFlagSet("fc node retire check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	caFile := flags.String("ca-file", "", "optional trusted public CA PEM file; TLS verification remains enabled")
	master := flags.String("master", "", "Master HTTPS origin")
	credentialStdin := flags.Bool("credential-stdin", false, "read Admin or temporary credential from standard input; never a command argument")
	if flags.Parse(args[4:]) != nil || flags.NArg() != 0 || !*credentialStdin {
		return 2
	}
	client, e := loginNodeClient(ctx, *master, *caFile, input)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	defer client.Close()
	report, e := client.RetirementCheck(ctx, member)
	if report.MemberID == member {
		if structured {
			if err := json.NewEncoder(output).Encode(report); err != nil {
				return 2
			}
		} else {
			fmt.Fprintf(output, "Member: %s\nObservation complete: %t\nPreflight only: true; final retirement approval is still required.\nPhysical entries: %d; logical bytes: %d; expected items: %d\n", member, report.ObservationComplete, report.PhysicalEntries, report.LogicalBytes, report.ExpectedItems)
			for _, volume := range report.Volumes {
				fmt.Fprintf(output, "Volume %q: entries=%d retained_native_state=%d logical_bytes=%d filesystem_total=%d filesystem_free=%d in_data_root=%t writable=unverified\n", volume.Scope, volume.Entries, volume.RetainedEntries, volume.LogicalBytes, volume.TotalBytes, volume.FreeBytes, volume.InDataRoot)
			}
			if len(report.Volumes) > 0 {
				fmt.Fprintln(output, "Filesystem free values may share the same disk; do not add them as available capacity.")
				fmt.Fprintln(output, "Retained native state must remain with node history; preflight does not authorize volume deletion.")
			}
			for _, ledger := range []string{"Master", "Storage"} {
				blocks := report.Master.Blockers
				if ledger == "Storage" {
					blocks = report.Peer.Blockers
				}
				for _, block := range blocks {
					fmt.Fprintf(output, "%s %q: %d; next step: %q; samples: %q\n", ledger, block.Code, block.Count, block.NextStep, block.SampleIDs)
				}
			}
			for _, concern := range report.Concerns {
				fmt.Fprintf(output, "%q: %d; samples: %q\n", concern.Code, concern.Count, concern.Samples)
			}
		}
	}
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	return retirementExitCode(report, nil)
}

func retirementExitCode(report noderetirement.Report, err error) int {
	if err != nil || !report.ObservationComplete || !report.PreflightOnly {
		return 2
	}
	if len(report.Concerns) > 0 || len(report.Master.Blockers) > 0 || len(report.Peer.Blockers) > 0 {
		return 1
	}
	return 0
}

func loginNodeClient(ctx context.Context, master, caFile string, input io.Reader) (*operator.NodeClient, error) {
	client, e := operator.NewNodeClient(master)
	if e != nil {
		return nil, e
	}
	failed := true
	defer func() {
		if failed {
			client.Close()
		}
	}()
	if caFile != "" {
		file, e := os.Open(caFile)
		if e != nil {
			return nil, fmt.Errorf("cannot read trusted CA file")
		}
		raw, e := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if e != nil || client.UseCA(raw) != nil {
			return nil, fmt.Errorf("invalid trusted CA file")
		}
	}
	credential, e := io.ReadAll(io.LimitReader(input, 4099))
	if e != nil || len(credential) > 4098 {
		return nil, fmt.Errorf("invalid credential input")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(credential), "\n"), "\r")
	for i := range credential {
		credential[i] = 0
	}
	if e = client.Login(ctx, token); e != nil {
		return nil, e
	}
	failed = false
	return client, nil
}
