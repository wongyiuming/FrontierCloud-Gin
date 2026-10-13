package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"io"
	"strings"
)

func validNodeCommandID(value string) bool {
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 16 && strings.ToLower(value) == value
}

func retirementApplyCommand(ctx context.Context, args []string, structured bool, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) < 4 {
		return 2
	}
	member := args[3]
	flags := flag.NewFlagSet("fc node retire apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	master := flags.String("master", "", "Master HTTPS origin")
	ca := flags.String("ca-file", "", "trusted public CA PEM")
	credential := flags.Bool("credential-stdin", false, "read credential from stdin")
	confirmation := flags.String("confirm-node-id", "", "confirm exact source NodeID")
	if flags.Parse(args[4:]) != nil || flags.NArg() != 0 || !*credential || !validNodeCommandID(member) || *confirmation != member {
		fmt.Fprintln(diagnostics, "apply requires an exact --confirm-node-id and --credential-stdin")
		return 2
	}
	client, e := loginNodeClient(ctx, *master, *ca, input)
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		return 2
	}
	defer client.Close()
	result, e := client.RetirementApply(ctx, member, *confirmation)
	if result.MemberID != "" {
		if structured {
			if json.NewEncoder(output).Encode(result) != nil {
				return 2
			}
		} else {
			fmt.Fprintf(output, "Member: %s\nFenced at: %d\nRetirement completed at: %d\n", result.MemberID, result.FencedAt, result.CompletedAt)
			fmt.Fprintln(output, "Node identity, history, containers and volumes are retained.")
		}
	}
	if e != nil {
		fmt.Fprintln(diagnostics, e)
		if errors.Is(e, operator.ErrRetirementIncomplete) {
			return 1
		}
		return 2
	}
	return 0
}
