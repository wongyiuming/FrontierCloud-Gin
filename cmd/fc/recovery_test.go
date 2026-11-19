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

func TestRestoreBusinessImportRequiresExplicitTargetAndArtifactPins(t *testing.T) {
	root := t.TempDir()
	valid := []string{"restore", "import-business-state",
		"--file", filepath.Join(root, "private-backup"), "--generation", "17",
		"--sha256", strings.Repeat("a", 64), "--bytes", "1024", "--target-master-id", strings.Repeat("b", 32)}
	withFlag := func(name, value string) []string {
		args := append([]string(nil), valid...)
		for i := 2; i < len(args); i += 2 {
			if args[i] == name {
				args[i+1] = value
				break
			}
		}
		return args
	}
	for _, test := range []struct {
		name, directory string
		args            []string
		diagnostic      string
	}{
		{"implicit directory", ".", valid, "explicit absolute --directory"},
		{"relative input", root, withFlag("--file", "private-backup"), "requires an absolute --file"},
		{"invalid artifact generation", root, withFlag("--generation", "0"), "requires an absolute --file"},
		{"invalid digest", root, withFlag("--sha256", strings.Repeat("g", 64)), "requires an absolute --file"},
		{"oversized input", root, withFlag("--bytes", "134217729"), "requires an absolute --file"},
		{"missing target ID", root, valid[:len(valid)-2], "requires an absolute --file"},
		{"unrelated restore flags", root, append(append([]string(nil), valid...), "--target=private-fixture"), "accepts --file"},
		{"no prepared receipt", root, valid, "cannot open the selected prepared Master deployment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if code := recoveryCommandOutput(context.Background(), test.directory, test.args, &out, &diagnostic); code != 2 || out.Len() != 0 || !strings.Contains(diagnostic.String(), test.diagnostic) {
				t.Fatalf("code %d, stdout %q, diagnostic %q", code, out.String(), diagnostic.String())
			}
			if strings.Contains(diagnostic.String(), "private-fixture") {
				t.Fatal("diagnostic includes the unrelated private argument")
			}
		})
	}
}

func TestRestoreBusinessPreparationRequiresExplicitMasterWithoutFreeze(t *testing.T) {
	root := t.TempDir()
	valid := []string{"restore", "prepare-business-state", "--target-master-id", strings.Repeat("b", 32)}
	for _, test := range []struct {
		name, directory string
		args            []string
		diagnostic      string
	}{
		{"implicit directory", ".", valid, "explicit absolute --directory"},
		{"relative directory", "relative", valid, "explicit absolute --directory"},
		{"missing target ID", root, valid[:2], "requires an exact --target-master-id"},
		{"invalid target ID", root, append(append([]string(nil), valid[:3]...), "PRIVATE-invalid-target"), "requires an exact --target-master-id"},
		{"unrelated freeze", root, append(append([]string(nil), valid...), "--freeze"), "requires an exact --target-master-id"},
		{"extra input", root, append(append([]string(nil), valid...), "PRIVATE-argument"), "requires an exact --target-master-id"},
		{"no registered receipt", root, valid, "cannot open the selected Master deployment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			code := recoveryCommandOutput(context.Background(), test.directory, test.args, &out, &diagnostic)
			if code != 2 || out.Len() != 0 || !strings.Contains(diagnostic.String(), test.diagnostic) || strings.Contains(diagnostic.String(), "PRIVATE-") {
				t.Fatalf("unexpected output: code %d, stdout %q, diagnostic %q", code, out.String(), diagnostic.String())
			}
		})
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("refused preparation modified its selected directory", err)
	}
}

func TestRestoreBusinessActivationRequiresExplicitMasterAndSourceDigest(t *testing.T) {
	root := t.TempDir()
	valid := []string{"restore", "activate-business-state", "--target-master-id", strings.Repeat("a", 32),
		"--source-sha256", strings.Repeat("b", 64)}
	withDigest := func(value string) []string {
		return append(append([]string(nil), valid[:5]...), value)
	}
	const missingPins = "requires an exact --target-master-id and --source-sha256"
	for _, test := range []struct {
		name, directory string
		args            []string
		diagnostic      string
	}{
		{"implicit directory", ".", valid, "explicit absolute --directory"},
		{"relative directory", "relative", valid, "explicit absolute --directory"},
		{"missing Master ID", root, append(append([]string(nil), valid[:2]...), valid[4:]...), missingPins},
		{"missing source digest", root, valid[:4], missingPins},
		{"short source digest", root, withDigest(strings.Repeat("b", 40)), missingPins},
		{"uppercase source digest", root, withDigest(strings.Repeat("B", 64)), missingPins},
		{"nonhex source digest", root, withDigest(strings.Repeat("g", 64)), missingPins},
		{"unrelated restore flag", root, append(append([]string(nil), valid...), "--file=PRIVATE-argument"), missingPins},
		{"no registered receipt", root, valid, "cannot open the selected prepared Master deployment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			code := recoveryCommandOutput(context.Background(), test.directory, test.args, &out, &diagnostic)
			if code != 2 || out.Len() != 0 || !strings.Contains(diagnostic.String(), test.diagnostic) || strings.Contains(diagnostic.String(), "PRIVATE-") {
				t.Fatalf("unexpected output: code %d, stdout %q, diagnostic %q", code, out.String(), diagnostic.String())
			}
		})
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("refused activation modified its selected directory", err)
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
