package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func TestRestoreCheckAndApplyNeverCreateTargetForInvalidArchive(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "invalid.tar")
	if e := os.WriteFile(input, []byte("not an archive"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"check", "apply"} {
		target := filepath.Join(root, action)
		code := recoveryCommand(context.Background(), root, []string{"restore", action, "--file", input, "--target", target})
		if code != 2 {
			t.Fatal(code)
		}
		if _, e := os.Stat(target); !os.IsNotExist(e) {
			t.Fatal("invalid archive modified target", e)
		}
	}
}

type closedRecoveryOutput struct{}

func (closedRecoveryOutput) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestRecoveryOutputFailureReturnsNonzero(t *testing.T) {
	var diagnostic bytes.Buffer
	if code := encodeRecoveryOutput(closedRecoveryOutput{}, &diagnostic, recovery.Report{Verified: true}); code != 2 || diagnostic.Len() == 0 {
		t.Fatal(code, diagnostic.String())
	}
}

func TestRestorePrepareRejectsRelatedNodeMissingItemsBeforeMaterialOrDocker(t *testing.T) {
	root := t.TempDir()
	data, secrets := filepath.Join(root, "data"), filepath.Join(root, "secrets")
	if e := os.Mkdir(data, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(secrets, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(secrets, "node-vault.key"), []byte("isolated fixture key"), 0600); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(root, "backup.tar")
	node := strings.Repeat("a", 32)
	m := recovery.Manifest{NodeID: node, Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{"matching recovery state for related node"}, KeyReferences: []string{"runtime_secrets/node-vault.key"}}
	report, e := recovery.Create(context.Background(), archive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: secrets}})
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "not-extracted")
	if e = os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	var diagnostic bytes.Buffer
	code := recoveryCommandOutput(context.Background(), root, []string{"restore", "prepare", "--file", archive, "--sha256", report.SHA256, "--target", target, "--confirm-node-id", node, "--project", "fresh-project"}, io.Discard, &diagnostic)
	if code != 2 {
		t.Fatal("incomplete cluster archive prepared", code)
	}
	entries, e := os.ReadDir(target)
	if e != nil || len(entries) != 0 {
		t.Fatal("incomplete preparation touched target", e)
	}
}
