//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestOpaqueMasterStartupAuthenticatesIndependentSecretsVolume(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	c := config.Config{
		DataRoot: filepath.Join(base, "data"), SecretsDirectory: filepath.Join(base, "runtime-secrets"),
		SQLitePath: filepath.Join(base, "data", "db.sqlite"), DatabaseType: config.DatabaseSQLite, DeploymentMode: config.DeploymentBusiness,
		TLSEnabled: true,
	}
	for _, dir := range []string{c.SecretsDirectory, filepath.Join(c.DataRoot, "media", "music"), filepath.Join(c.DataRoot, "recordings")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.Open(c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(c.SQLitePath, 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.RecordNativeRuntime(ctx, c.DataRoot); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, "UPDATE node_identity SET role='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"DB_TYPE": c.DatabaseType, "SQLITE_PATH": c.SQLitePath, "DATA_ROOT": c.DataRoot,
		"SECRETS_DIR": c.SecretsDirectory, "DEPLOYMENT_MODE": c.DeploymentMode, "TLS_ENABLED": "true",
		"SERVER_NAME": "master.test", "PUBLIC_ORIGIN": "https://master.test", "ADMIN_ORIGIN": "https://master.test",
	} {
		t.Setenv(name, value)
	}
	gate, err := maintenance.Open(c.DataRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	var output bytes.Buffer
	prepare := func() error {
		output.Reset()
		return sealedTreePrepareCommand([]string{identity.ID}, &output)
	}
	mounts, err := inspectRetainedTreeMounts([2]string{c.DataRoot, c.SecretsDirectory})
	if err != nil {
		t.Fatal(err)
	}
	mountProof, err := json.Marshal([2]runtimefacts.TreeBackupMount{mounts.Data, mounts.Secrets})
	if err != nil {
		t.Fatal(err)
	}
	prepareBusiness := func(proof string) error {
		output.Reset()
		return prepareBusinessStateCommand([]string{"--target-master-id", identity.ID, "--mount-proof", proof}, &output)
	}
	if err = prepare(); err == nil {
		t.Fatal("preparation accepted a deployment outside maintenance")
	}
	if err = prepareBusiness(string(mountProof)); err == nil || output.Len() != 0 {
		t.Fatal("business preparation accepted a deployment outside maintenance")
	}
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = prepareSealedS3Control(ctx, c, gate, identity.ID); err == nil {
		t.Fatal("S3 control preparation accepted an absent encrypted tree")
	}
	if _, err = os.Lstat(filepath.Join(c.DataRoot, ".selected-s3-control")); !os.IsNotExist(err) {
		t.Fatal("rejected S3 control preparation created a directory", err)
	}
	if err = sealedTreePrepareCommand([]string{strings.Repeat("f", 32)}, &output); err == nil {
		t.Fatal("preparation accepted an unrelated Master")
	}
	legacy := filepath.Join(c.DataRoot, "media", "music", "legacy.mp3")
	if err = os.WriteFile(legacy, []byte("legacy fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = prepare(); err == nil {
		t.Fatal("preparation accepted existing media")
	}
	if err = prepareBusiness(string(mountProof)); err == nil || output.Len() != 0 {
		t.Fatal("business preparation accepted existing media")
	}
	if data, err := os.ReadFile(legacy); err != nil || string(data) != "legacy fixture" {
		t.Fatal("refusal modified the fixture media", err)
	}
	keyPath := filepath.Join(c.SecretsDirectory, sealedtree.MasterKeyFile)
	if _, err = os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatal("refusal created a key", err)
	}
	if err = os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	if err = prepareBusiness(`[]`); err == nil || output.Len() != 0 {
		t.Fatal("business preparation accepted an invalid mount proof")
	}
	hold := filepath.Join(c.DataRoot, maintenance.OwnerImportHold)
	if err := os.WriteFile(hold, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = prepareBusiness(string(mountProof)); err == nil || output.Len() != 0 {
		t.Fatal("business preparation accepted an existing recovery hold")
	}
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = prepareBusiness(string(mountProof)); err != nil {
			t.Fatal("prepare business with independently mounted secrets", err)
		}
		var result runtimefacts.BusinessPreparationReport
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result != (runtimefacts.BusinessPreparationReport{TargetMasterID: identity.ID, Prepared: true}) {
			t.Fatal("unexpected preparation receipt", output.String(), err)
		}
	}
	controlPath := filepath.Join(c.DataRoot, ".selected-s3-control", "control.lock")
	control, err := os.Lstat(controlPath)
	if err != nil || !control.Mode().IsRegular() || control.Mode().Perm() != 0600 {
		t.Fatal("fresh tree did not prepare the S3 control lock", err)
	}
	if err = prepareSealedS3Control(ctx, c, gate, strings.Repeat("f", 32)); err == nil {
		t.Fatal("S3 control preparation accepted an unrelated Master")
	}
	if err = prepareSealedS3Control(ctx, c, gate, identity.ID); err != nil {
		t.Fatal("S3 control preparation could not be retried", err)
	}
	current, err := os.Lstat(controlPath)
	if err != nil || !os.SameFile(control, current) {
		t.Fatal("S3 control retry replaced the fixed inode", err)
	}
	backupPath := controlPath + ".fixture"
	if err = os.Rename(controlPath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(backupPath, controlPath); err != nil {
		t.Fatal(err)
	}
	if err = prepareSealedS3Control(ctx, c, gate, identity.ID); err == nil {
		t.Fatal("S3 control preparation accepted a replaced lock")
	}
	if err = os.Remove(controlPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(backupPath, controlPath); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err = prepare(); err != nil || output.String() != "{\"prepared\":true}\n" {
		t.Fatal("retry preparation", err)
	}
	again, err := os.ReadFile(keyPath)
	defer clear(again)
	if err != nil || !bytes.Equal(key, again) {
		t.Fatal("retry replaced the tree key", err)
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("preparation released maintenance", err)
	}
	t.Run("ImportBusinessStateOnPreparedMaster", func(t *testing.T) {
		artifact := `{"kind":"header","version":2,"generation":1}
{"kind":"row","table":"ip_permanent_whitelist","value":{"ip_address":"192.0.2.18","created_at":"2026-10-02 12:34:56.123456","created_by_session_hash":null,"note":null}}
{"kind":"end"}
`
		mounts, err := inspectRetainedTreeMounts([2]string{c.DataRoot, c.SecretsDirectory})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := json.Marshal([2]runtimefacts.TreeBackupMount{mounts.Data, mounts.Secrets})
		if err != nil {
			t.Fatal(err)
		}
		args := []string{"--generation", "1", "--sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(artifact))), "--bytes", fmt.Sprint(len(artifact)), "--target-master-id", identity.ID, "--mount-proof", string(proof)}
		wrong := append([]string(nil), args...)
		swapped, err := json.Marshal([2]runtimefacts.TreeBackupMount{mounts.Secrets, mounts.Data})
		if err != nil {
			t.Fatal(err)
		}
		wrong[len(wrong)-1] = string(swapped)
		if err := importBusinessStateCommand(wrong, strings.NewReader(artifact), &bytes.Buffer{}); err == nil {
			t.Fatal("import accepted an invalid mount proof")
		}
		for _, retry := range []bool{false, true} {
			var result bytes.Buffer
			if err := importBusinessStateCommand(args, strings.NewReader(artifact), &result); err != nil {
				t.Fatal(err)
			}
			var report backup.BusinessStateReport
			if err := json.Unmarshal(result.Bytes(), &report); err != nil || report.TargetMasterID != identity.ID || report.RestoreReady || report.AlreadyApplied != retry || report.ImportedRows["ip_permanent_whitelist"] != 1 {
				t.Fatal("unexpected import receipt", result.String(), err)
			}
		}
		manual := filepath.Join(c.DataRoot, sitecontrol.Manual)
		forceOpen := filepath.Join(c.DataRoot, sitecontrol.ForceOpen)
		resume := func(markerProof string) (result bytes.Buffer, err error) {
			err = resumeBusinessStateCommand([]string{"--target-master-id", identity.ID, "--mount-proof", string(proof), "--manual-proof", markerProof}, &result)
			return result, err
		}
		if reply, err := resume("0:1"); err == nil || reply.Len() != 0 {
			t.Fatal("resume accepted a missing manual marker")
		}
		if err := os.WriteFile(manual, []byte("manual\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manual, 0644); err != nil {
			t.Fatal(err)
		}
		manualInfo, err := os.Lstat(manual)
		if err != nil {
			t.Fatal(err)
		}
		stat := manualInfo.Sys().(*syscall.Stat_t)
		manualProof := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		if reply, err := resume(fmt.Sprintf("%d:%d", stat.Dev, stat.Ino+1)); err == nil || reply.Len() != 0 {
			t.Fatal("resume accepted a different manual marker inode")
		}
		if err := os.WriteFile(forceOpen, []byte("release-failure-override\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if reply, err := resume(manualProof); err == nil || reply.Len() != 0 {
			t.Fatal("resume accepted force-open state")
		}
		if err := os.Remove(forceOpen); err != nil {
			t.Fatal(err)
		}
		reply, err := resume(manualProof)
		var resumed runtimefacts.BusinessNativeResumeReport
		if err != nil || json.Unmarshal(reply.Bytes(), &resumed) != nil || resumed != (runtimefacts.BusinessNativeResumeReport{TargetMasterID: identity.ID, Resumed: true}) {
			t.Fatal("resume did not verify the prepared Master", err, reply.String())
		}
		if found, err := os.Lstat(manual); err != nil || !os.SameFile(manualInfo, found) {
			t.Fatal("resume changed public maintenance", err)
		}
		if enabled, err := gate.Enabled(); err != nil || enabled {
			t.Fatal("resume left native maintenance enabled", err)
		}
		if err := importBusinessStateCommand(args, strings.NewReader(artifact), &bytes.Buffer{}); err == nil {
			t.Fatal("import accepted a Master outside maintenance")
		}
		if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		tree, closeTree, err := sealedtree.OpenMasterSQLite(ctx, db.Database(), c.DataRoot, c.SecretsDirectory, identity.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, createErr := tree.EnsureSelectedDirectories(ctx, "music/existing-directory")
		if closeErr := closeTree(); createErr != nil || closeErr != nil {
			t.Fatal(createErr, closeErr)
		}
		if err := importBusinessStateCommand(args, strings.NewReader(artifact), &bytes.Buffer{}); !errors.Is(err, backup.ErrBusinessStateTarget) {
			t.Fatal("import accepted an existing encrypted catalog directory", err)
		}
		if reply, err := resume(manualProof); !errors.Is(err, backup.ErrBusinessStateTarget) || reply.Len() != 0 {
			t.Fatal("resume accepted an occupied reingest target", err)
		}
	})
	if err = db.Initialize(ctx); err == nil {
		t.Fatal("unprepared schema initializer accepted live tree tables")
	}
	reopened, err := sqlitestore.OpenExisting(ctx, c.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = initializeRuntimeSchema(ctx, reopened, c); err != nil {
		t.Fatal("prepared schema could not reopen", err)
	}
	currentIdentity, err := openRuntimeIdentity(ctx, reopened, c)
	if err != nil || currentIdentity.ID != identity.ID || currentIdentity.Role != "Master" {
		t.Fatal("prepared runtime did not reopen the original Master identity", err)
	}
	mediaRoot := filepath.Join(c.DataRoot, "media")
	bindingPath := filepath.Join(mediaRoot, ".opaque-aliases", ".owner-control-binding")
	binding, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, []byte("unauthenticated owner binding"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSealedS3Control(ctx, c, gate, identity.ID); err == nil {
		t.Fatal("S3 control preparation accepted a replaced Owner binding")
	}
	if owner, err := openRuntimeOwner(ctx, c, reopened, currentIdentity); err == nil || owner != nil {
		t.Fatal("prepared runtime accepted a replaced Owner binding", err)
	}
	if err := os.WriteFile(bindingPath, binding, 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := openRuntimeOwner(ctx, c, reopened, currentIdentity)
	if err != nil || owner == nil {
		t.Fatal("prepared runtime could not authenticate its Owner volume", err)
	}
	defer owner.Close()
	opened, closeTree, err := openOpaqueMasterTree(ctx, reopened, c)
	if err != nil {
		t.Fatal(err)
	}
	if legacy, err := media.NewContext(ctx, mediaRoot, reopened.Media(), currentIdentity); err == nil {
		legacy.Close()
		t.Fatal("prepared runtime admitted legacy media startup")
	}
	volume, err := media.NewSealedContext(ctx, mediaRoot, reopened.Media(), currentIdentity, opened)
	if err != nil {
		t.Fatal("prepared runtime could not open the sealed media volume", err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(mediaRoot, "lyrics", "default.lrc")); !os.IsNotExist(err) {
		t.Fatal("sealed media startup created a plaintext default lyric", err)
	}
	lease, err := opened.AcquireReadFence(ctx)
	if err != nil {
		closeTree()
		t.Fatal("retained tree handle cannot acquire a lease", err)
	}
	lease.Release()
	if err = closeTree(); err != nil {
		t.Fatal(err)
	}
	check := func() error { return checkOpaqueMasterTreeLayout(ctx, reopened, c) }
	if err = check(); err != nil {
		t.Fatal("authentic startup state rejected", err)
	}
	for _, name := range append([]string{
		filepath.Join(c.SecretsDirectory, sealedtree.MasterKeyFile),
		filepath.Join(c.SecretsDirectory, "node-vault.key"),
	}, sealedtree.MasterStatePaths()...) {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(c.DataRoot, filepath.FromSlash(path))
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				defer clear(original)
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			})
			tampered := append([]byte(nil), original...)
			tampered[0] ^= 1
			defer clear(tampered)
			if err = os.WriteFile(path, tampered, 0600); err != nil {
				t.Fatal(err)
			}
			if err = check(); err == nil {
				t.Fatal("shape-correct but unrelated startup state accepted")
			}
		})
	}
	if err = check(); err != nil {
		t.Fatal("original state did not authenticate again", err)
	}
	var capacityVerifier string
	if err = db.Database().QueryRowContext(ctx, `SELECT verifier FROM sealed_tree_capacity_meta WHERE singleton=1`).Scan(&capacityVerifier); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, `UPDATE sealed_tree_capacity_meta SET verifier=? WHERE singleton=1`, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if err = check(); err == nil {
		t.Fatal("changed capacity verifier accepted")
	}
	if _, err = db.Database().ExecContext(ctx, `UPDATE sealed_tree_capacity_meta SET verifier=? WHERE singleton=1`, capacityVerifier); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, "UPDATE node_identity SET created_at=created_at+1 WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err = check(); err == nil {
		t.Fatal("modified Master identity accepted")
	}
}
