package main

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"testing"
)

func TestOperatorOutputPropagatesWriterFailure(t *testing.T) {
	for _, structured := range []bool{false, true} {
		for _, value := range []any{operator.Report{}, map[string]string{"state": "ready"}} {
			if e := writeOperatorOutput(closedRecoveryOutput{}, structured, value); e == nil {
				t.Fatal("output failure suppressed", structured)
			}
		}
	}
}

func TestRetirementCommandHasOperatorOwnedLifetime(t *testing.T) {
	for _, args := range [][]string{{"node", "retire", "check"}, {"node", "retire", "apply"}, {"node", "list"}} {
		parent, cancel := context.WithCancel(context.Background())
		ctx, stop := commandContext(parent, args)
		_, bounded := ctx.Deadline()
		if bounded == (args[1] == "retire") {
			t.Fatal("incorrect command deadline", args)
		}
		cancel()
		if ctx.Err() != context.Canceled {
			t.Fatal("cancellation lost")
		}
		stop()
	}
}
