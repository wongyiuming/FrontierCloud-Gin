package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

// Publication evidence is fixed only in this disposable-daemon test. Image
// proof, cold pulls, the shipping runner, Compose and host guards remain real.
type nativeSelfUpdateEvidence struct{}

type nativeAutomaticUpdateEvidence struct{ nativeSelfUpdateEvidence }

func (nativeAutomaticUpdateEvidence) MainHead(context.Context) (string, error) {
	return "", release.ErrManifest
}
func (nativeAutomaticUpdateEvidence) Publication(context.Context, string) (release.PublicationState, error) {
	return release.PublicationState{}, release.ErrManifest
}
func (nativeAutomaticUpdateEvidence) Relation(context.Context, string, string) (string, error) {
	return "ahead", nil
}

func (nativeSelfUpdateEvidence) Artifact(_ context.Context, target string) (map[string]any, error) {
	return map[string]any{"publishable": true, "sha": target, "ci_sha": target}, nil
}

func TestNativeSelfUpdateDiagnostics(t *testing.T) {
	if os.Getenv("FC_SELF_UPDATE_DISPOSABLE_DAEMON") != "1" {
		t.Skip("isolated development daemon only")
	}
	marker, err := os.ReadFile("/root/foc-native-fixture")
	if err != nil || string(marker) != "disposable-foc-self-update\n" || os.Geteuid() != 0 {
		t.Fatal("disposable fixture marker required")
	}
	const target = "c438232d16a8c95baa94fa81289e9afed980c881"
	const directory = "/root/foc-node"
	d, err := operator.New(directory, "storage", "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	d.Runner = dockerRunner{directory}
	before, err := os.ReadFile(filepath.Join(directory, operator.ReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	images := release.NewRegistryClient()
	defer images.Close()
	apply := func() error { _, e := d.SelfUpdate(ctx, target, "amd64", nativeSelfUpdateEvidence{}, images); return e }
	if err = apply(); err != nil {
		t.Fatal("real cold image pull and Compose install", err)
	}
	checkVersion := func() {
		t.Helper()
		raw, e := exec.CommandContext(ctx, "/usr/local/bin/foc", "version").Output()
		if e != nil || strings.TrimSpace(string(raw)) != target {
			t.Fatal("global version mismatch", e)
		}
	}
	checkVersion()
	var continued, diagnostic bytes.Buffer
	handled, code, err := refreshUpgradeOperator(ctx, strings.Repeat("a", 40), target, nativeAutomaticUpdateEvidence{}, apply, func() int {
		return continueWithUpdatedOperator(ctx, directory, target, []string{"version"}, strings.NewReader(""), &continued, &diagnostic, false)
	})
	if err != nil || !handled || code != 0 || strings.TrimSpace(continued.String()) != target {
		t.Fatal("automatic Compose refresh and real backend continuation", handled, code, err, diagnostic.String())
	}
	t.Log("PASS: automatic refresh invokes actual Compose installer and continues the exact installed backend")
	launcher, err := os.ReadFile("/usr/local/lib/frontiercloud/foc/launcher.current")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/usr/local/bin/foc", []byte("#!/bin/sh\necho foreign\n"), 0755); err != nil {
		t.Fatal(err)
	}
	err = apply()
	if !errors.Is(err, operator.ErrInstallerOwnership) || !strings.Contains(err.Error(), "compose_install") || !strings.Contains(err.Error(), "exit_code=2") {
		t.Fatal("ownership refusal hidden", err)
	}
	t.Log("ownership refusal:", err)
	if err = os.WriteFile("/usr/local/bin/foc", launcher, 0755); err != nil {
		t.Fatal(err)
	}
	const lock = "/usr/local/lib/frontiercloud/foc/.install-lock"
	if err = os.Mkdir(lock, 0700); err != nil {
		t.Fatal(err)
	}
	err = apply()
	if !errors.Is(err, operator.ErrInstallerLock) || !strings.Contains(err.Error(), "exit_code=2") {
		t.Fatal("installation lock hidden", err)
	}
	t.Log("lock refusal:", err)
	if err = os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err = apply(); err != nil {
		t.Fatal("retry failed", err)
	}
	checkVersion()
	after, err := os.ReadFile(filepath.Join(directory, operator.ReceiptFile))
	if err != nil || string(before) != string(after) {
		t.Fatal("business receipt changed", err)
	}
	t.Log("PASS: real cold pull, global Compose installation, ownership/lock diagnostics, retry and unchanged business receipt")
}
