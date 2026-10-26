package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestPreparedParameterlessRetryReachesConsentWithoutDockerOrReleaseNetwork(t *testing.T) {
	// With no executable search path, a regression to docker info fails before
	// consent; the prepared opening path must not perform that discovery.
	t.Setenv("PATH", t.TempDir())
	for _, phase := range []string{"prepared_fenced", "activating_fenced", "verified_fenced", "opening", "opened"} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			write := func(name string, value any) {
				raw, err := json.Marshal(value)
				if err == nil {
					err = os.WriteFile(filepath.Join(directory, name), raw, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			target := strings.Repeat("b", 40)
			write(operator.ReceiptFile, operator.Receipt{Version: 1, Role: "master", Database: "sqlite", Project: "fixture", Revision: target, State: "upgrade_fenced", Files: []string{"docker-compose.yaml"}})
			plan := operator.UpgradePlan{Version: 1, Target: target, Generation: migrations.Generation, RecoveryScope: "upgrade-state"}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(raw)
			plan.SHA256 = hex.EncodeToString(hash[:])
			write(operator.UpgradeJournal, operator.UpgradeState{Version: 1, Phase: phase, Plan: plan})
			var out, diagnostic bytes.Buffer
			code := simpleUpgradeCommand(context.Background(), directory, "", []string{"upgrade"}, strings.NewReader("n\n"), &out, &diagnostic, false)
			if code != 2 || !strings.Contains(diagnostic.String(), "Continue recorded phase: "+phase) || !strings.Contains(diagnostic.String(), "upgrade cancelled") || out.Len() != 0 {
				t.Fatal(code, out.String(), diagnostic.String())
			}
		})
	}
}

func TestSimpleUpgradeConsentAndMySQLAttestation(t *testing.T) {
	for _, db := range []string{"sqlite", "mysql"} {
		for _, answer := range []string{"yes\n", "no\n", ""} {
			var output bytes.Buffer
			p := operator.UpgradePreview{Plan: operator.UpgradePlan{Database: db}}
			consent, e := upgradeConsent(context.Background(), strings.NewReader(answer), &output, false, false, p)
			if answer == "yes\n" && (e != nil || !consent.Approved || consent.ExternalWritersStopped != (db == "mysql")) {
				t.Fatal(db, consent, e)
			}
			if answer != "yes\n" && consent.Approved {
				t.Fatal("unconfirmed upgrade admitted")
			}
			if db == "mysql" && !strings.Contains(output.String(), "external MySQL writers") {
				t.Fatal("missing MySQL attestation")
			}
		}
	}
	p := operator.UpgradePreview{Plan: operator.UpgradePlan{Database: "mysql"}}
	var output bytes.Buffer
	if _, e := upgradeConsent(context.Background(), strings.NewReader(""), &output, true, false, p); e == nil {
		t.Fatal("--yes implicitly attested external MySQL writers")
	}
	consent, e := upgradeConsent(context.Background(), strings.NewReader(""), &output, true, true, p)
	if e != nil || !consent.Approved || !consent.ExternalWritersStopped {
		t.Fatal(consent, e)
	}
}

func TestConfirmationCancellationDoesNotWaitForInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	prompt := &confirmationPromptWriter{ready: make(chan struct{})}
	go func() {
		_, err := upgradeConsent(ctx, reader, prompt, false, false, operator.UpgradePreview{})
		finished <- err
	}()
	select {
	case <-prompt.ready:
	case <-time.After(time.Second):
		t.Fatal("confirmation prompt was not displayed")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled confirmation is still waiting on stdin")
	}
}

type confirmationPromptWriter struct{ ready chan struct{} }

func (w *confirmationPromptWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("[y/N]")) {
		close(w.ready)
	}
	return len(p), nil
}
