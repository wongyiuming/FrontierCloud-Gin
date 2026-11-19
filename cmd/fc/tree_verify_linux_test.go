//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func corruptTreeEvidenceArchive(t *testing.T, source, target string) string {
	t.Helper()
	src, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	reader := tar.NewReader(src)
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for {
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(reader)
		if e != nil {
			t.Fatal(e)
		}
		if h.Name == "manifest.json" {
			var m recovery.Manifest
			if e = json.Unmarshal(raw, &m); e != nil {
				t.Fatal(e)
			}
			var evidence map[string]any
			if e = json.Unmarshal(m.TreeEvidence, &evidence); e != nil {
				t.Fatal(e)
			}
			evidence["RecoveryMAC"] = strings.Repeat("0", 64)
			m.TreeEvidence, e = json.Marshal(evidence)
			if e != nil {
				t.Fatal(e)
			}
			raw, e = json.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			h.Size = int64(len(raw))
		}
		if e = writer.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if _, e = writer.Write(raw); e != nil {
			t.Fatal(e)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(out.Bytes()))
}

func TestBackupVerifyTreeArchiveRequiresTrustedSHAAndStaysNotReady(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	data, keys, archives := filepath.Join(base, "data"), filepath.Join(base, "keys"), filepath.Join(base, "archives")
	for _, p := range []string{data, keys, archives} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db := filepath.Join(data, "db.sqlite")
	if err := os.WriteFile(db, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("x", 32))
	if err := os.WriteFile(filepath.Join(keys, "tree-master.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "node-vault.key"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m := recovery.Manifest{NodeID: strings.Repeat("a", 32), Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Scope: recovery.UpgradeStateScope, Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/tree-master.key"}}
	archive := filepath.Join(archives, "backup.tar")
	report, err := recovery.CreateTreeArchive(ctx, gate, data, db, archive, m, []recovery.Root{{Class: "data", Directory: data, IncludePaths: []string{"db.sqlite"}}, {Class: "runtime_secrets", Directory: keys}}, func(_ context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return func(man recovery.Manifest) (json.RawMessage, error) {
			digest, e := recovery.TreeManifestDigest(man)
			if e != nil {
				return nil, e
			}
			ev := struct {
				Version                                                  int `json:"version"`
				ManifestSHA, NodeID, RootVerifier, MasterBinding, OldTag string
				Device, Inode                                            uint64
				Generation                                               int64
				MAC, RecoveryMAC                                         string
			}{Version: 1, ManifestSHA: digest, NodeID: man.NodeID, Inode: 1, MAC: strings.Repeat("0", 64)}
			raw, e := json.Marshal(ev)
			if e != nil {
				return nil, e
			}
			h := hmac.New(sha256.New, key)
			h.Write([]byte("frontiercloud:tree-fence-recovery-outer:v1\x00"))
			h.Write(raw)
			ev.RecoveryMAC = hex.EncodeToString(h.Sum(nil))
			return json.Marshal(ev)
		}, func() error { return check() }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"backup", "verify", "--file", archive}, {"backup", "verify", "--file", archive, "--sha256", strings.Repeat("f", 64)}} {
		if code := recoveryCommandOutput(ctx, base, args, io.Discard, io.Discard); code == 0 {
			t.Fatal("untrusted checksum accepted", args)
		}
	}
	forged := filepath.Join(archives, "forged.tar")
	forgedSHA := corruptTreeEvidenceArchive(t, archive, forged)
	if code := recoveryCommandOutput(ctx, base, []string{"backup", "verify", "--file", forged, "--sha256", forgedSHA}, io.Discard, io.Discard); code == 0 {
		t.Fatal("forged embedded evidence accepted")
	}
	var output, diagnostic bytes.Buffer
	if code := recoveryCommandOutput(ctx, base, []string{"backup", "verify", "--file", archive, "--sha256", report.SHA256}, &output, &diagnostic); code != 0 {
		t.Fatal("verify", code, diagnostic.String())
	}
	var got recovery.Report
	if err = json.Unmarshal(output.Bytes(), &got); err != nil || !got.Verified || got.RestoreReady || got.BusinessVerified {
		t.Fatal("incorrect readiness", got, err)
	}
	jsonFile := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if name != "" {
			if err = os.WriteFile(filepath.Join(base, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	receipt := operator.Receipt{Version: operator.ConfigurationVersion, Role: "master", Project: "fixture", Database: "sqlite", Revision: m.Revision, State: "ready", Files: []string{"docker-compose.yaml"}}
	plan := operator.UpgradePlan{Version: 1, NodeID: m.NodeID, Project: receipt.Project, Role: receipt.Role, Database: receipt.Database, From: m.Revision, FromGeneration: report.Manifest.SchemaGeneration, RecoveryScope: recovery.UpgradeStateScope, ReceiptSHA: jsonFile(operator.ReceiptFile, receipt)}
	plan.SHA256 = jsonFile("", plan)
	state := operator.UpgradeState{Version: 1, Phase: "backed_up_fenced", Plan: plan, Previous: receipt, BackupFile: archive, BackupSHA: report.SHA256}
	jsonFile(operator.UpgradeJournal, state)
	output.Reset()
	diagnostic.Reset()
	args := []string{"backup", "verify", "--file", archive}
	if code := recoveryCommandOutput(ctx, base, args, &output, &diagnostic); code != 0 || json.Unmarshal(output.Bytes(), &got) != nil || !got.Verified || got.RestoreReady || got.BusinessVerified || got.SHA256 != report.SHA256 {
		t.Fatal("journal-pinned verify", code, diagnostic.String(), got)
	}
	state.BackupSHA = ""
	jsonFile(operator.UpgradeJournal, state)
	if code := recoveryCommandOutput(ctx, base, args, io.Discard, io.Discard); code == 0 {
		t.Fatal("journal archive without a committed checksum was accepted")
	}
	state.BackupSHA = report.SHA256
	jsonFile(operator.UpgradeJournal, state)
	legacyKeys := filepath.Join(base, "legacy-keys")
	if err = os.Mkdir(legacyKeys, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(legacyKeys, "node-vault.key"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	legacy := m
	legacy.KeyReferences = []string{"runtime_secrets/node-vault.key"}
	legacyPath := filepath.Join(archives, "legacy.tar")
	if _, err = recovery.Create(ctx, legacyPath, legacy, []recovery.Root{{Class: "data", Directory: data, IncludePaths: []string{"db.sqlite"}}, {Class: "runtime_secrets", Directory: legacyKeys}}); err != nil {
		t.Fatal(err)
	}
	if code := recoveryCommandOutput(ctx, base, []string{"backup", "verify", "--file", legacyPath}, io.Discard, io.Discard); code != 0 {
		t.Fatal("v1 behavior changed", code)
	}
	if err = os.Rename(legacyPath, archive); err != nil {
		t.Fatal(err)
	}
	if code := recoveryCommandOutput(ctx, base, args, io.Discard, io.Discard); code == 0 {
		t.Fatal("different archive passed at the recorded path")
	}
}
