package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"strings"
	"testing"
)

type unreadCredential struct{ t *testing.T }

func (r unreadCredential) Read([]byte) (int, error) {
	r.t.Fatal("invalid command read a credential")
	return 0, nil
}
func TestNodeCLIRejectsUnsafeAuthorityBeforeCredentialInput(t *testing.T) {
	for _, args := range [][]string{
		{"node", "retire", "apply", strings.Repeat("1", 32)},
		{"node", "migrate", "plan", strings.Repeat("1", 32)},
		{"node", "migrate", "pause", strings.Repeat("1", 32), "--credential-stdin"},
		{"node", "migrate", "status", strings.Repeat("1", 32), "--credential-stdin", "--after", "private"},
		{"node", "retire", "check", "../private"},
		{"node", "retire", "check", strings.Repeat("1", 32), "--master", "https://user:private@master.test", "--credential-stdin"},
		{"node", "retire", "check", strings.Repeat("1", 32), "--master", "http://master.test", "--credential-stdin"},
		{"node", "retire", "check", strings.Repeat("1", 32), "--master", "https://master.test", "--credential-stdin=private"},
	} {
		var output, diagnostics bytes.Buffer
		if code := nodeCommand(context.Background(), args, true, unreadCredential{t}, &output, &diagnostics); code != 2 || output.Len() != 0 || strings.Contains(diagnostics.String(), "private") {
			t.Fatal(code, output.String(), diagnostics.String())
		}
	}
}
func TestNodeCLIExitCodesDoNotGrantRetirement(t *testing.T) {
	report := noderetirement.Report{PreflightOnly: true, ObservationComplete: true}
	if retirementExitCode(report, nil) != 0 {
		t.Fatal("completed observation")
	}
	report.Concerns = []noderetirement.Concern{{Code: "backup_retention_required", Count: 1}}
	if retirementExitCode(report, nil) != 1 {
		t.Fatal("blocked observation")
	}
	report.ObservationComplete = false
	if retirementExitCode(report, nil) != 2 || retirementExitCode(report, errors.New("offline")) != 2 {
		t.Fatal("incomplete observation")
	}
	report.ObservationComplete = true
	report.PreflightOnly = false
	if retirementExitCode(report, nil) != 2 {
		t.Fatal("unsupported approval accepted")
	}
}
