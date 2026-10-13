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
	client, e := operator.NewNodeClient(*master)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	defer client.Close()
	if *caFile != "" {
		file, err := os.Open(*caFile)
		if err != nil {
			fmt.Fprintln(diagnostics, "cannot read trusted CA file")
			return 2
		}
		raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if err != nil || client.UseCA(raw) != nil {
			fmt.Fprintln(diagnostics, "invalid trusted CA file")
			return 2
		}
	}
	credential, e := io.ReadAll(io.LimitReader(input, 4098))
	if e != nil || len(credential) > 4097 {
		fmt.Fprintln(diagnostics, "invalid credential input")
		return 2
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(credential), "\n"), "\r")
	for i := range credential {
		credential[i] = 0
	}
	if e = client.Login(ctx, token); e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	report, e := client.RetirementCheck(ctx, member)
	if report.MemberID == member {
		if structured {
			if err := json.NewEncoder(output).Encode(report); err != nil {
				return 2
			}
		} else {
			fmt.Fprintf(output, "Member: %s\nObservation complete: %t\nPreflight only: true; final retirement approval is still required.\nPhysical entries: %d; logical bytes: %d; expected items: %d\n", member, report.ObservationComplete, report.PhysicalEntries, report.LogicalBytes, report.ExpectedItems)
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
