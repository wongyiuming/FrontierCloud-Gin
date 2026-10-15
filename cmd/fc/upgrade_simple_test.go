package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

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
