//go:build linux

package sealedtree

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

// forgeTreeArchive rebuilds the synthetic archive and recomputes its external
// SHA so that embedded evidence, not a stale checksum, must reject tampering.
func forgeTreeArchive(t *testing.T, source, target string, mutate func(*recovery.Manifest)) string {
	t.Helper()
	src, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var out bytes.Buffer
	reader := tar.NewReader(src)
	writer := tar.NewWriter(&out)
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "manifest.json" {
			var m recovery.Manifest
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("manifest")
			}
			mutate(&m)
			raw, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			h.Size = int64(len(raw))
		}
		if err = writer.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write(raw); err != nil {
			t.Fatal(err)
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

// recoverySQLiteFiles captures contents and stable filesystem metadata; atime is
// intentionally excluded because taking the digest itself can update it.
func recoverySQLiteFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, name := range []string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm"} {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result[name] = "absent"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("missing stat")
		}
		result[name] = fmt.Sprintf("%x:%d:%d:%d:%d:%d:%d:%d", sha256.Sum256(raw), info.Size(), info.Mode(), info.ModTime().UnixNano(), st.Dev, st.Ino, st.Ctim.Sec, st.Ctim.Nsec)
	}
	return result
}
func assertRecoverySQLiteFilesUnchanged(t *testing.T, root string, before map[string]string) {
	t.Helper()
	if got := recoverySQLiteFiles(t, root); !reflect.DeepEqual(got, before) {
		t.Fatalf("SQLite/WAL/SHM changed on rejection: before=%v after=%v", before, got)
	}
}

func TestTreeArchiveCompetingWriterProcess(t *testing.T) {
	path := os.Getenv("FC_TEST_TREE_ARCHIVE_DB")
	if path == "" {
		return
	}
	db, err := recoverySQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`UPDATE sealed_tree_meta SET write_fence=write_fence WHERE singleton=1`)
	if os.Getenv("FC_TEST_TREE_ARCHIVE_EXPECT") == "blocked" {
		if err == nil {
			t.Fatal("writer bypassed held SQLite write lock")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "busy") && !strings.Contains(strings.ToLower(err.Error()), "locked") {
			t.Fatal("unexpected writer failure", err)
		}
		return
	}
	if err != nil {
		t.Fatal("writer remained blocked after cancel", err)
	}
}

func runTreeArchiveWriter(t *testing.T, path, expect string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTreeArchiveCompetingWriterProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_TEST_TREE_ARCHIVE_DB="+path, "FC_TEST_TREE_ARCHIVE_EXPECT="+expect)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("competing process %s: %v %s", expect, err, out)
	}
}

// Test the complete existing tree-key/WAL/fence path as an unprivileged
// runtime identity, without changing ownership of any pre-existing files.
func TestTreeUpgradeSelectionRejectsAliasesAndBusinessPaths(t *testing.T) {
	paths := MasterStatePaths()
	if len(paths) != 2 || paths[0] != MasterFenceDirectory+"/"+treeFenceFile || paths[1] != MasterFenceDirectory+"/"+existingMasterBindingFile {
		t.Fatal("Master state paths diverged from the actual fence or binding")
	}
	files := []string{"db.sqlite", "db.sqlite-wal", "tree/tree-write.fence", "tree/tree-master.binding", maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}
	sources := []recovery.Root{{Class: "data", IncludePaths: files}}
	if err := validateTreeUpgradeSelection(sources, files[0], files[2], files[3]); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ db, fence, binding string }{
		{"media/song.blob", files[2], files[3]},
		{"objects/file.db", files[2], files[3]},
		{files[2], files[2], files[3]},
		{files[0], "../fence", files[3]},
	} {
		if err := validateTreeUpgradeSelection(sources, test.db, test.fence, test.binding); err == nil {
			t.Fatalf("unsafe selection accepted: %+v", test)
		}
	}
}

func TestPrivateTreeArchiveRuntimeUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-UID process fixture requires root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestPrivateTreeArchiveWALRebindRestart$", "-test.count=1")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 12345, Gid: 12345, Groups: []uint32{}}}
	cmd.Env = append(os.Environ(), "TMPDIR=/tmp")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runtime UID archive failed: %v: %s", err, output)
	}
}

// Uses the real archive writer/checker/extractor and real key files. No Owner
// data or service activation is implied by successful fence rebinding.
func TestPrivateTreeArchiveWALRebindRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	base := t.TempDir()
	dataDir := filepath.Join(base, "source-data")
	secretDir := filepath.Join(base, "source-secrets")
	archiveDir := filepath.Join(base, "archive")
	for _, dir := range []string{dataDir, secretDir, archiveDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := os.OpenRoot(secretDir)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	master, err := CreateTreeSecretFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	nodeVault, err := vault.Open(secretDir)
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{4}, 32))
	sealed, err := nodeVault.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "db.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := New(master, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := InitializeSQLite(ctx, db, tree, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("b", 32)
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT,created_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?,123)`, node, sealed); err != nil {
		t.Fatal(err)
	}
	fenceDir := filepath.Join(dataDir, MasterFenceDirectory)
	if err = os.Mkdir(fenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	fenceRoot, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer fenceRoot.Close()
	if _, err = InitializeFence(ctx, s, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	if err = s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	binding := existingMasterBinding(tree, s.rootID, node, sealed, 123)
	if err = os.WriteFile(filepath.Join(fenceDir, existingMasterBindingFile), binding, 0600); err != nil {
		t.Fatal(err)
	}
	clear(binding)
	// Keep a read-only SQLite snapshot open, so the committed WAL remains
	// present without leaving an unmanaged writer running during backup.
	reader, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = reader.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&count); err != nil || count != 1 {
		t.Fatal("source WAL", count, err)
	}
	gate, err := maintenance.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A separate process must fail its actual SQLite write while the real
	// tree capture is held; cancelling the capture must release the write lock.
	testCtx, cancelCapture := context.WithCancel(ctx)
	captureErr := gate.InspectSQLite(testCtx, dataDir, dbPath, func(c context.Context, check func() error) error {
		_, end, err := beginOfflineTreeArchive(c, check, dataDir, dbPath, fenceRoot, fenceDir, master, nodeVault, node, "data/"+MasterFenceDirectory+"/"+treeFenceFile, "data/"+MasterFenceDirectory+"/"+existingMasterBindingFile, 0)
		if err != nil {
			return err
		}
		runTreeArchiveWriter(t, dbPath, "blocked")
		cancelCapture()
		if err = end(); err == nil {
			return errors.New("cancelled capture unexpectedly succeeded")
		}
		return c.Err()
	})
	if !errors.Is(captureErr, context.Canceled) && captureErr == nil {
		t.Fatal("cancelled capture was accepted")
	}
	runTreeArchiveWriter(t, dbPath, "unlocked")
	output := filepath.Join(archiveDir, "private.tar")
	manifest := recovery.Manifest{NodeID: node, Role: "Master", Revision: strings.Repeat("d", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/tree-master.key"}}
	sources := []recovery.Root{{Class: "data", Directory: dataDir}, {Class: "runtime_secrets", Directory: secretDir}}
	missingData := filepath.Join(base, "missing-fixed-fence")
	if err = os.Mkdir(missingData, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateMasterTreeBackupStaged(ctx, gate, missingData, filepath.Join(missingData, "db.sqlite"), secretDir, filepath.Join(archiveDir, "missing-fence.tar"), manifest, sources, nil); err == nil {
		t.Fatal("missing fixed Master fence was accepted")
	}
	if _, err = os.Lstat(filepath.Join(missingData, MasterFenceDirectory)); !os.IsNotExist(err) {
		t.Fatal("missing fixed Master fence was created", err)
	}
	if err = os.Symlink(fenceDir, filepath.Join(missingData, MasterFenceDirectory)); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateMasterTreeBackupStaged(ctx, gate, missingData, filepath.Join(missingData, "db.sqlite"), secretDir, filepath.Join(archiveDir, "linked-fence.tar"), manifest, sources, nil); err == nil {
		t.Fatal("symlinked Master fence was accepted")
	}
	missingSecrets := filepath.Join(base, "missing-secret-directory")
	if _, err = CreateMasterTreeBackupStaged(ctx, gate, dataDir, dbPath, missingSecrets, filepath.Join(archiveDir, "missing-secret.tar"), manifest, sources, nil); err == nil {
		t.Fatal("missing Master secrets directory was accepted")
	}
	if _, err = os.Lstat(missingSecrets); !os.IsNotExist(err) {
		t.Fatal("missing Master secrets directory was created", err)
	}
	if err = os.Symlink(secretDir, missingSecrets); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateMasterTreeBackupStaged(ctx, gate, dataDir, dbPath, missingSecrets, filepath.Join(archiveDir, "linked-secret.tar"), manifest, sources, nil); err == nil {
		t.Fatal("symlinked Master secrets directory was accepted")
	}
	emptySecrets := filepath.Join(base, "empty-secrets")
	if err = os.Mkdir(emptySecrets, 0700); err != nil {
		t.Fatal(err)
	}
	emptySources := []recovery.Root{{Class: "data", Directory: dataDir}, {Class: "runtime_secrets", Directory: emptySecrets}}
	if _, err = CreateMasterTreeBackupStaged(ctx, gate, dataDir, dbPath, emptySecrets, filepath.Join(archiveDir, "missing-key.tar"), manifest, emptySources, nil); err == nil {
		t.Fatal("missing Master key was accepted")
	}
	if _, err = os.Lstat(filepath.Join(emptySecrets, MasterKeyFile)); !os.IsNotExist(err) {
		t.Fatal("missing Master key was created", err)
	}
	// Receive a different-UID state class only after the real tree/SQLite
	// write lock is held; preserve its original metadata in the private archive.
	streamStage := filepath.Join(archiveDir, "stream-stage")
	if err = os.Mkdir(streamStage, 0700); err != nil {
		t.Fatal(err)
	}
	streamRoot, err := os.OpenRoot(streamStage)
	if err != nil {
		t.Fatal(err)
	}
	defer streamRoot.Close()
	var streamed bytes.Buffer
	tw := tar.NewWriter(&streamed)
	for _, h := range []*tar.Header{{Name: "deployment", Typeflag: tar.TypeDir, Mode: 0750, Uid: 111, Gid: 222}, {Name: "deployment/.env", Typeflag: tar.TypeReg, Mode: 0640, Uid: 333, Gid: 444, Size: 7}} {
		if err = tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size != 0 {
			if _, err = tw.Write([]byte("fixture")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	streamNonce := strings.Repeat("ab", 32)
	digest := sha256.Sum256(streamed.Bytes())
	nonceBytes, _ := hex.DecodeString(streamNonce)
	streamed.Write(digest[:])
	streamed.Write(nonceBytes)
	stagedOutput := filepath.Join(archiveDir, "with-staged.tar")
	stagedReport, err := CreateMasterTreeBackupStaged(ctx, gate, dataDir, dbPath, secretDir, stagedOutput, manifest, sources, func(c context.Context, check func() error) ([]recovery.Root, error) {
		if check() != nil {
			t.Fatal("maintenance lost before stream")
		}
		runTreeArchiveWriter(t, dbPath, "blocked")
		return recovery.ReceiveCommittedTreeBackupClasses(c, bytes.NewReader(streamed.Bytes()), streamRoot, []string{"deployment"}, 1<<20, streamNonce)
	})
	if err != nil {
		t.Fatal("lease-bound staged backup", err)
	}
	foundStaged := false
	for _, entry := range stagedReport.Manifest.Files {
		if entry.Path == "deployment/.env" {
			foundStaged = entry.UID == 333 && entry.GID == 444 && entry.Mode == 0640
		}
	}
	if !foundStaged {
		t.Fatal("original streamed metadata was lost")
	}
	if _, err = recovery.CheckTreeArchiveAuthenticated(ctx, stagedOutput, stagedReport.SHA256); err != nil {
		t.Fatal("staged backup authentication", err)
	}
	// Upgrade state backups contain the encrypted tree and control state, but
	// deliberately do not duplicate media, lyrics or recording payloads.
	for _, name := range []string{"media/song.blob", "lyrics/song.lrc", "recordings/take.bin"} {
		p := filepath.Join(dataDir, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, []byte("business fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stateManifest := manifest
	stateManifest.Scope = recovery.UpgradeStateScope
	selection := []string{"db.sqlite", "db.sqlite-wal", "db.sqlite-shm", MasterFenceDirectory + "/" + treeFenceFile, MasterFenceDirectory + "/" + existingMasterBindingFile, maintenance.Marker, ".native-runtime.lock", ".native-maintenance-control.lock"}
	stateSources := []recovery.Root{{Class: "data", Directory: dataDir, IncludePaths: selection}, {Class: "runtime_secrets", Directory: secretDir}}
	stateOutput := filepath.Join(archiveDir, "state.tar")
	stateReport, err := CreateMasterTreeBackupStaged(ctx, gate, dataDir, dbPath, secretDir, stateOutput, stateManifest, stateSources, nil)
	if err != nil {
		t.Fatal("create state-only tree backup", err)
	}
	if stateReport.Manifest.Scope != recovery.UpgradeStateScope || stateReport.Manifest.CompleteCluster {
		t.Fatal("state-only backup reported as a complete cluster")
	}
	stateFiles := map[string]int64{}
	for _, entry := range stateReport.Manifest.Files {
		stateFiles[entry.Path] = entry.Bytes
		if strings.HasPrefix(entry.Path, "data/media/") || strings.HasPrefix(entry.Path, "data/lyrics/") || strings.HasPrefix(entry.Path, "data/recordings/") {
			t.Fatalf("business payload entered state archive: %s", entry.Path)
		}
	}
	if stateFiles["data/db.sqlite-wal"] <= 0 || stateFiles["data/"+MasterFenceDirectory+"/"+treeFenceFile] <= 0 || stateFiles["data/"+MasterFenceDirectory+"/"+existingMasterBindingFile] <= 0 || stateFiles["runtime_secrets/tree-master.key"] != 32 {
		t.Fatal("state archive omitted WAL, fence, binding, or tree key")
	}
	unsafeSources := []recovery.Root{{Class: "data", Directory: dataDir, IncludePaths: append(append([]string(nil), selection...), "media/song.blob")}, {Class: "runtime_secrets", Directory: secretDir}}
	if _, err = createOfflineTreeBackup(ctx, gate, dataDir, dbPath, fenceRoot, fenceDir, keys, filepath.Join(archiveDir, "unsafe-state.tar"), stateManifest, unsafeSources); err == nil {
		t.Fatal("state archive accepted media payload selection")
	}
	missingBinding := []recovery.Root{{Class: "data", Directory: dataDir, IncludePaths: []string{"db.sqlite", MasterFenceDirectory + "/" + treeFenceFile}}, {Class: "runtime_secrets", Directory: secretDir}}
	if _, err = createOfflineTreeBackup(ctx, gate, dataDir, dbPath, fenceRoot, fenceDir, keys, filepath.Join(archiveDir, "incomplete-state.tar"), stateManifest, missingBinding); err == nil {
		t.Fatal("state archive accepted missing tree binding")
	}
	stateTarget := filepath.Join(base, "state-restored")
	if _, err = recovery.ApplyTreeStateArchive(ctx, stateOutput, stateTarget, strings.Repeat("0", 64), node); err == nil {
		t.Fatal("state-only restore accepted an incorrect archive digest")
	}
	if _, err = os.Lstat(stateTarget); !os.IsNotExist(err) {
		t.Fatal("failed state-only restore created a target", err)
	}
	if _, err = recovery.ApplyTreeStateArchive(ctx, stateOutput, stateTarget, stateReport.SHA256, node); err != nil {
		t.Fatal("extract state-only tree archive", err)
	}
	for _, name := range []string{"media/song.blob", "lyrics/song.lrc", "recordings/take.bin"} {
		if _, err = os.Lstat(filepath.Join(stateTarget, "data", filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Fatalf("business payload restored: %s: %v", name, err)
		}
	}
	checkRetainedTreeRestore(t, ctx, base, stateTarget, stateOutput, stateReport.SHA256, node, master, entry.ObjectID)
	stateGate, err := maintenance.Open(filepath.Join(stateTarget, "data"))
	if err != nil {
		t.Fatal(err)
	}
	already, err := RebindMasterTreeBackup(ctx, stateGate, stateOutput, stateReport.SHA256, stateTarget, "db.sqlite", node)
	if err != nil || already {
		stateGate.Close()
		t.Fatal("state-only fence rebind", already, err)
	}
	already, err = RebindMasterTreeBackup(ctx, stateGate, stateOutput, stateReport.SHA256, stateTarget, "db.sqlite", node)
	if err != nil || !already {
		stateGate.Close()
		t.Fatal("state-only fence rebind retry", already, err)
	}
	if enabled, err := stateGate.Enabled(); err != nil || !enabled {
		stateGate.Close()
		t.Fatal("state-only restore lost maintenance", enabled, err)
	}
	stateDB, err := recoverySQLite(filepath.Join(stateTarget, "data", "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := OpenSQLiteWithMaster(ctx, stateDB, master)
	if err != nil {
		stateDB.Close()
		t.Fatal("state-only tree reopen", err)
	}
	stateFencePath := filepath.Join(stateTarget, "data", MasterFenceDirectory)
	stateFence, err := os.OpenRoot(stateFencePath)
	if err != nil {
		stateDB.Close()
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, stateStore, stateFence, stateFencePath); err != nil {
		stateFence.Close()
		stateDB.Close()
		t.Fatal("state-only fence reopen", err)
	}
	stateLease, err := stateStore.AcquireReadFence(ctx)
	if err != nil {
		stateFence.Close()
		stateDB.Close()
		t.Fatal(err)
	}
	statePath, err := stateStore.ResolveDirectoryForRecoveryWithLease(ctx, stateLease, entry.ObjectID)
	stateLease.Release()
	stateFence.Close()
	stateDB.Close()
	if err != nil || statePath != "album" {
		t.Fatal("state-only restored tree read", statePath, err)
	}
	stateGate.Close()
	if _, err = recovery.Create(ctx, filepath.Join(archiveDir, "legacy.tar"), manifest, sources); err == nil {
		t.Fatal("v1 accepted declared tree key")
	}
	undeclared := manifest
	undeclared.KeyReferences = []string{"runtime_secrets/node-vault.key"}
	if _, err = recovery.Create(ctx, filepath.Join(archiveDir, "legacy-undeclared.tar"), undeclared, sources); err == nil {
		t.Fatal("v1 silently archived an undeclared tree key")
	}
	report, err := createOfflineTreeBackup(ctx, gate, dataDir, dbPath, fenceRoot, fenceDir, keys, output, manifest, sources)
	if err != nil {
		t.Fatal("create tree backup", err)
	}
	wal := false
	for _, f := range report.Manifest.Files {
		if f.Path == "data/db.sqlite-wal" && f.Bytes > 0 {
			wal = true
		}
	}
	if !wal {
		t.Fatal("fixture did not archive nonempty committed WAL")
	}
	if _, err = recovery.Check(ctx, output, report.SHA256); err == nil {
		t.Fatal("v1 checker accepted v2")
	}
	if _, err = recovery.CheckTreeArchive(ctx, output, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong archive SHA accepted")
	}
	if _, err = recovery.CheckTreeArchiveAuthenticated(ctx, output, report.SHA256); err != nil {
		t.Fatal("authenticated operator preflight", err)
	}
	if _, err = recovery.CheckTreeArchive(ctx, output, report.SHA256); err != nil {
		t.Fatal("v2 checker", err)
	}
	if err = reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// An extracted key different from the verified archive must not produce a
	// recovery intent or perform a fence update.
	badTarget := filepath.Join(base, "bad-restored")
	if _, err = recovery.ApplyTreeArchive(ctx, output, badTarget, report.SHA256, node); err != nil {
		t.Fatal(err)
	}
	badKey := filepath.Join(badTarget, "runtime_secrets", treeKeyFile)
	if err = os.WriteFile(badKey, bytes.Repeat([]byte{42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	badGate, err := maintenance.Open(filepath.Join(badTarget, "data"))
	if err != nil {
		t.Fatal(err)
	}
	badBefore := recoverySQLiteFiles(t, filepath.Join(badTarget, "data"))
	if _, err = rebindVerifiedTreeBackup(ctx, badGate, output, report.SHA256, badTarget, "db.sqlite", MasterFenceDirectory, node); err == nil {
		badGate.Close()
		t.Fatal("tampered restored key accepted")
	}
	assertRecoverySQLiteFilesUnchanged(t, filepath.Join(badTarget, "data"), badBefore)
	if _, err = os.Lstat(filepath.Join(badTarget, "data", treeRebindIntentName)); !os.IsNotExist(err) {
		badGate.Close()
		t.Fatal("tampered key created recovery intent", err)
	}
	badGate.Close()
	target := filepath.Join(base, "restored")
	if _, err = recovery.Apply(ctx, output, target, report.SHA256, node); err == nil {
		t.Fatal("v1 apply accepted v2")
	}
	if _, err = recovery.ApplyTreeArchive(ctx, output, target, report.SHA256, node); err != nil {
		t.Fatal("extract v2", err)
	}
	restoredKeyRoot, err := os.OpenRoot(filepath.Join(target, "runtime_secrets"))
	if err != nil {
		t.Fatal(err)
	}
	restoredKey, err := OpenTreeSecretFile(restoredKeyRoot)
	if err != nil || !bytes.Equal(master, restoredKey) {
		t.Fatal("tree key not restored", err)
	}
	clear(restoredKey)
	restoredKeyRoot.Close()
	restoredData := filepath.Join(target, "data")
	restoreGate, err := maintenance.Open(restoredData)
	if err != nil {
		t.Fatal(err)
	}
	defer restoreGate.Close()
	enabled, err := restoreGate.Enabled()
	if err != nil || !enabled {
		t.Fatal("archive did not retain maintenance", err)
	}
	beforeWrongSHA := recoverySQLiteFiles(t, restoredData)
	if _, err = rebindVerifiedTreeBackup(ctx, restoreGate, output, strings.Repeat("0", 64), target, "db.sqlite", MasterFenceDirectory, node); err == nil {
		t.Fatal("wrong SHA accepted")
	}
	assertRecoverySQLiteFilesUnchanged(t, restoredData, beforeWrongSHA)
	copyPath := filepath.Join(archiveDir, "forged-evidence.tar")
	forgedSHA := forgeTreeArchive(t, output, copyPath, func(m *recovery.Manifest) {
		var ev fenceRecoveryEvidence
		if json.Unmarshal(m.TreeEvidence, &ev) != nil {
			t.Fatal("evidence")
		}
		ev.RecoveryMAC = strings.Repeat("0", 64)
		m.TreeEvidence, _ = json.Marshal(ev)
	})
	if _, err = recovery.CheckTreeArchiveAuthenticated(ctx, copyPath, forgedSHA); err == nil {
		t.Fatal("operator authenticated check accepted forged MAC")
	}
	beforeForged := recoverySQLiteFiles(t, restoredData)
	if _, err = rebindVerifiedTreeBackup(ctx, restoreGate, copyPath, forgedSHA, target, "db.sqlite", MasterFenceDirectory, node); err == nil {
		t.Fatal("forged outer evidence accepted")
	}
	assertRecoverySQLiteFilesUnchanged(t, restoredData, beforeForged)
	if _, err = os.Lstat(filepath.Join(restoredData, treeRebindIntentName)); !os.IsNotExist(err) {
		t.Fatal("forged evidence created intent", err)
	}
	innerTarget := filepath.Join(base, "inner-forgery")
	if _, err = recovery.ApplyTreeArchive(ctx, output, innerTarget, report.SHA256, node); err != nil {
		t.Fatal(err)
	}
	innerGate, err := maintenance.Open(filepath.Join(innerTarget, "data"))
	if err != nil {
		t.Fatal(err)
	}
	innerSHA := forgeTreeArchive(t, output, copyPath, func(m *recovery.Manifest) {
		var ev fenceRecoveryEvidence
		if json.Unmarshal(m.TreeEvidence, &ev) != nil {
			t.Fatal("evidence")
		}
		ev.MAC = strings.Repeat("0", 64)
		ev.RecoveryMAC, err = fenceRecoveryOuterMAC(master, ev)
		if err != nil {
			t.Fatal(err)
		}
		m.TreeEvidence, _ = json.Marshal(ev)
	})
	if _, err = rebindVerifiedTreeBackup(ctx, innerGate, copyPath, innerSHA, innerTarget, "db.sqlite", MasterFenceDirectory, node); err == nil {
		t.Fatal("forged inner MAC accepted")
	}
	if _, err = os.Lstat(filepath.Join(innerTarget, "data", treeRebindIntentName)); !os.IsNotExist(err) {
		t.Fatal("forged inner MAC created intent", err)
	}
	innerGate.Close()
	already, err = rebindVerifiedTreeBackup(ctx, restoreGate, output, report.SHA256, target, "db.sqlite", MasterFenceDirectory, node)
	if err != nil || already {
		t.Fatal("verified rebind", already, err)
	}
	already, err = rebindVerifiedTreeBackup(ctx, restoreGate, output, report.SHA256, target, "db.sqlite", MasterFenceDirectory, node)
	if err != nil || !already {
		t.Fatal("verified retry", already, err)
	}
	restoredDB, err := recoverySQLite(filepath.Join(restoredData, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteWithMaster(ctx, restoredDB, master)
	if err != nil {
		t.Fatal(err)
	}
	restoredFence, err := os.OpenRoot(filepath.Join(restoredData, MasterFenceDirectory))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredFence.Close()
	if _, err = OpenFence(ctx, reopened, restoredFence, filepath.Join(restoredData, MasterFenceDirectory)); err != nil {
		t.Fatal(err)
	}
	lease, err := reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path, err := reopened.ResolveDirectoryForRecoveryWithLease(ctx, lease, entry.ObjectID)
	if err != nil || path != "album" {
		t.Fatal("restarted tree read", path, err)
	}
	lease.Release()
	restoredDB.Close()
	enabled, err = restoreGate.Enabled()
	if err != nil || !enabled {
		t.Fatal("rebind opened maintenance", err)
	}
}
