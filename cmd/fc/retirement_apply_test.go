package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRetirementApplyCLIRequiresExactConfirmationBeforeCredential(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, tail := range [][]string{
		{"--credential-stdin"},
		{"--confirm-node-id", id},
		{"--credential-stdin", "--confirm-node-id", strings.Repeat("b", 32)},
		{"--credential-stdin", "--confirm-node-id", id, "--force"},
		{"--credential-stdin", "--confirm-node-id", id, "--master", "http://master.test"},
	} {
		args := append([]string{"node", "retire", "apply", id}, tail...)
		var output, diagnostics bytes.Buffer
		if code := nodeCommand(context.Background(), args, true, unreadCredential{t}, &output, &diagnostics); code != 2 || output.Len() != 0 {
			t.Fatal(code, output.String(), diagnostics.String())
		}
	}
}
