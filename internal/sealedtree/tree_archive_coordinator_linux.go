//go:build linux

package sealedtree

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func treeArchiveContains(report recovery.Report, path string) bool {
	for _, entry := range report.Manifest.Files {
		if entry.Path == path {
			return true
		}
	}
	return false
}

// createOfflineTreeBackup holds maintenance and SQLite/fence locks while
// authenticating the manifest and rechecking each copied archive entry.
func createOfflineTreeBackup(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, fenceRoot *os.Root, fenceDir string, keyRoot *os.Root, output string, m recovery.Manifest, sources []recovery.Root) (recovery.Report, error) {
	return CreateOfflineTreeBackupStaged(ctx, gate, dataRoot, databasePath, fenceRoot, fenceDir, keyRoot, output, m, sources, nil)
}

// CreateMasterTreeBackupStaged opens only the existing Master key and the
// fixed DATA_ROOT fence directory. A missing or changed path is an error; this
// never initializes a tree, identity, fence, key, or readiness marker. The
// caller must establish receipt-bound mounts and reconcile Owners separately.
func CreateMasterTreeBackupStaged(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath, secretsDir, output string, m recovery.Manifest, sources []recovery.Root, receive func(context.Context, func() error) ([]recovery.Root, error)) (recovery.Report, error) {
	if !filepath.IsAbs(dataRoot) || filepath.Clean(dataRoot) != dataRoot || !filepath.IsAbs(secretsDir) || filepath.Clean(secretsDir) != secretsDir {
		return recovery.Report{}, ErrInvalid
	}
	fenceDir := filepath.Join(dataRoot, MasterFenceDirectory)
	fence, err := openPrivateTreeDirectory(fenceDir)
	if err != nil {
		return recovery.Report{}, err
	}
	defer fence.Close()
	keys, err := openPrivateTreeDirectory(secretsDir)
	if err != nil {
		return recovery.Report{}, err
	}
	defer keys.Close()
	return CreateOfflineTreeBackupStaged(ctx, gate, dataRoot, databasePath, fence, fenceDir, keys, output, m, sources, receive)
}

// CreateOfflineTreeBackupStaged allows the trusted foc parent to stream fixed
// state classes only while this runtime owns the native SQLite/tree lease.
// It does not establish receipt authority, reconcile Owners or open service.
func CreateOfflineTreeBackupStaged(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, fenceRoot *os.Root, fenceDir string, keyRoot *os.Root, output string, m recovery.Manifest, sources []recovery.Root, receive func(context.Context, func() error) ([]recovery.Root, error)) (recovery.Report, error) {
	if ctx == nil || gate == nil || checkPrivateDirectory(keyRoot) != nil || recoveryFenceLocation(dataRoot, fenceRoot, fenceDir) != nil || !lowerHex(m.NodeID, 32) {
		return recovery.Report{}, ErrInvalid
	}
	keyInfo, e := keyRoot.Stat(".")
	if e != nil {
		return recovery.Report{}, ErrInvalid
	}
	matched := false
	for _, source := range sources {
		if source.Class == "runtime_secrets" {
			info, e := os.Lstat(source.Directory)
			if e == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && os.SameFile(info, keyInfo) {
				matched = true
			}
		}
	}
	if !matched {
		return recovery.Report{}, ErrInvalid
	}
	secret, e := OpenTreeSecretFile(keyRoot)
	if e != nil {
		return recovery.Report{}, e
	}
	defer clear(secret)
	nodeVault, e := vault.OpenExisting(keyRoot.Name())
	if e != nil {
		return recovery.Report{}, e
	}
	absolute, e := filepath.Abs(output)
	if e != nil {
		return recovery.Report{}, ErrInvalid
	}
	parent, e := os.OpenRoot(filepath.Dir(absolute))
	if e != nil {
		return recovery.Report{}, e
	}
	defer parent.Close()
	if checkPrivateDirectory(parent) != nil {
		return recovery.Report{}, ErrInvalid
	}
	rel, e := filepath.Rel(dataRoot, fenceDir)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return recovery.Report{}, ErrInvalid
	}
	fencePath := "data/" + filepath.ToSlash(filepath.Join(rel, treeFenceFile))
	bindingPath := "data/" + filepath.ToSlash(filepath.Join(rel, existingMasterBindingFile))
	if m.Scope == recovery.UpgradeStateScope {
		dbRel, err := filepath.Rel(dataRoot, databasePath)
		if err != nil || validateTreeUpgradeSelection(sources, filepath.ToSlash(dbRel), strings.TrimPrefix(fencePath, "data/"), strings.TrimPrefix(bindingPath, "data/")) != nil {
			return recovery.Report{}, ErrInvalid
		}
	}
	return recovery.CreateTreeArchiveStaged(ctx, gate, dataRoot, databasePath, absolute, m, func(c context.Context, check func() error) ([]recovery.Root, error) {
		if receive == nil {
			return sources, nil
		}
		staged, e := receive(c, check)
		if e != nil {
			return nil, e
		}
		combined := append([]recovery.Root(nil), sources...)
		combined = append(combined, staged...)
		return combined, nil
	}, func(c context.Context, check func() error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		return beginOfflineTreeArchive(c, check, dataRoot, databasePath, fenceRoot, fenceDir, secret, nodeVault, m.NodeID, fencePath, bindingPath, m.SchemaGeneration)
	})
}

// State-only captures are an exact file allowlist, never a recursive
// selection of the media tree. The final archive must also contain the DB,
// fence and binding, checked by the existing sealing/manifest path.
func validateTreeUpgradeSelection(sources []recovery.Root, database, fence, binding string) error {
	if fence == binding || database == fence || database == binding || database+"-wal" == fence || database+"-wal" == binding || database+"-shm" == fence || database+"-shm" == binding {
		return ErrInvalid
	}
	for _, name := range []string{database, fence, binding} {
		if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\\x00\r\n") {
			return ErrInvalid
		}
		first := strings.SplitN(name, "/", 2)[0]
		if first == "media" || first == "music" || first == "objects" || first == "lyric" || first == "lyrics" || first == "recording" || first == "recordings" {
			return ErrInvalid
		}
	}
	allowed := map[string]bool{
		maintenance.Marker: true, sitecontrol.Manual: true, sitecontrol.ForceOpen: true,
		".native-runtime.lock": true, ".native-maintenance-control.lock": true,
		sitecontrol.Lock: true, ".native-store": true, ".native-runtime": true,
		"media-keys/media-premaster.key": true,
		database:                         true, database + "-wal": true, database + "-shm": true,
		fence: true, binding: true,
	}
	seen := map[string]bool{}
	found := false
	for _, source := range sources {
		if source.Class != "data" {
			continue
		}
		if found || source.IncludePaths == nil {
			return ErrInvalid
		}
		found = true
		for _, name := range source.IncludePaths {
			if !allowed[name] || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
		}
	}
	if !found || !seen[database] || !seen[fence] || !seen[binding] || !seen[maintenance.Marker] || !seen[".native-runtime.lock"] || !seen[".native-maintenance-control.lock"] {
		return ErrInvalid
	}
	return nil
}

func (s *SQLStore) checkArchiveQuiescence(ctx context.Context, tx treeQuery, generation int) error {
	state, _, err := s.listingBuildState(ctx, tx)
	if err != nil || state != 1 {
		return ErrConflict
	}
	hasCancellations, err := hasSelectedCancellationTable(ctx, tx)
	if err != nil {
		return err
	}
	// Generation zero is used only by the isolated, sealed-only archive
	// primitive. The runtime capture command requires the current schema.
	if generation != 0 {
		var actual int
		if generation != migrations.Generation || !hasCancellations ||
			tx.QueryRowContext(ctx, "SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&actual) != nil || actual != generation {
			return ErrConflict
		}
		var opaquePending int
		if err := tx.QueryRowContext(ctx, store.OpaqueMigrationUnsettledSQL).Scan(&opaquePending); err != nil {
			return err
		}
		if opaquePending != 0 {
			return ErrConflict
		}
	}
	unfinished := []string{
		"SELECT 1 FROM sealed_tree_pending_files LIMIT 1",
		"SELECT 1 FROM sealed_tree_pending_facts LIMIT 1",
		"SELECT 1 FROM sealed_tree_revocations LIMIT 1",
	}
	if hasCancellations {
		if err := s.verifySelectedCancellationRows(ctx, tx); err != nil {
			return err
		}
		unfinished = append(unfinished, `SELECT 1 FROM sealed_tree_operation_ids o
			LEFT JOIN selected_upload_cancellations c ON c.operation_id=o.operation_id
			WHERE o.completed=0 AND c.operation_id IS NULL LIMIT 1`)
	} else {
		unfinished = append(unfinished, "SELECT 1 FROM sealed_tree_operation_ids WHERE completed=0 LIMIT 1")
	}
	if generation != 0 {
		unfinished = append(unfinished,
			"SELECT 1 FROM migration_tasks WHERE state NOT IN ('completed','cancelled') LIMIT 1",
			"SELECT 1 FROM migration_capacity WHERE reserved_bytes<>0 LIMIT 1",
			"SELECT 1 FROM migration_scopes LIMIT 1",
			"SELECT 1 FROM selected_upload_intents WHERE state NOT IN ('completed','cancelled') LIMIT 1",
			"SELECT 1 FROM selected_s3_uploads WHERE state NOT IN ('completed','cancelled') LIMIT 1",
			`SELECT 1 FROM selected_s3_uploads s LEFT JOIN selected_upload_intents i ON i.operation_index=s.operation_index
				WHERE i.operation_index IS NULL OR i.state<>s.state LIMIT 1`,
			`SELECT 1 FROM selected_s3_parts p LEFT JOIN selected_s3_uploads s ON s.operation_index=p.operation_index
				WHERE s.operation_index IS NULL LIMIT 1`)
	}
	for _, query := range unfinished {
		var pending int
		err := tx.QueryRowContext(ctx, query).Scan(&pending)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

func beginOfflineTreeArchive(c context.Context, check func() error, dataRoot, databasePath string, fenceRoot *os.Root, fenceDir string, secret []byte, nodeVault *vault.Vault, nodeID, fencePath, bindingPath string, generation int) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
	if check() != nil || recoveryFenceLocation(dataRoot, fenceRoot, fenceDir) != nil {
		return nil, nil, ErrFenceRequired
	}
	db, e := recoverySQLite(databasePath)
	if e != nil {
		return nil, nil, e
	}
	fail := func(err error) (func(recovery.Manifest) (json.RawMessage, error), func() error, error) {
		db.Close()
		return nil, nil, err
	}
	store, e := OpenSQLiteWithMaster(c, db, secret)
	if e != nil {
		return fail(e)
	}
	fence, e := OpenFence(c, store, fenceRoot, fenceDir)
	if e != nil {
		return fail(e)
	}
	lease, e := store.AcquireReadFence(c)
	if e != nil {
		return fail(e)
	}
	conn, e := db.Conn(c)
	if e != nil {
		lease.Release()
		return fail(e)
	}
	if _, e = conn.ExecContext(c, `BEGIN IMMEDIATE`); e != nil {
		conn.Close()
		lease.Release()
		return fail(e)
	}
	// Revalidate on the very connection holding BEGIN IMMEDIATE. Opening an
	// additional pooled SQLite connection can itself alter WAL metadata.
	checkHeld := func() error {
		if c.Err() != nil || check() != nil {
			return ErrFenceRequired
		}
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.released || lease.file == nil || lease.fence != fence || fence.checkFile(lease.file) != nil {
			return ErrFenceChanged
		}
		var generation int64
		if e := conn.QueryRowContext(c, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); e != nil || generation != lease.generation || fence.checkFile(lease.file) != nil || check() != nil {
			return ErrFenceChanged
		}
		return nil
	}
	end := func() error {
		_, err := conn.ExecContext(context.Background(), `ROLLBACK`)
		conn.Close()
		lease.Release()
		return errors.Join(err, db.Close())
	}
	binding, e := recoveryMasterBinding(c, conn, store, fenceRoot, nodeVault, nodeID)
	if e != nil {
		end()
		return nil, nil, e
	}
	if e = store.checkArchiveQuiescence(c, conn, generation); e != nil {
		_ = end()
		return nil, nil, e
	}
	verifier, e := store.tree.namespaceVerifier(store.rootID)
	if e != nil {
		end()
		return nil, nil, e
	}
	seal := func(manifest recovery.Manifest) (json.RawMessage, error) {
		if checkHeld() != nil || manifest.NodeID != nodeID || !treeArchiveContains(recovery.Report{Manifest: manifest}, fencePath) || !treeArchiveContains(recovery.Report{Manifest: manifest}, bindingPath) {
			return nil, ErrFenceRequired
		}
		digest, e := recovery.TreeManifestDigest(manifest)
		if e != nil {
			return nil, e
		}
		evidence := fenceRecoveryEvidence{Version: 1, ManifestSHA: digest, NodeID: nodeID, RootVerifier: verifier, MasterBinding: binding, OldTag: fence.tag(), Device: fence.device, Inode: fence.inode, Generation: lease.generation}
		evidence.MAC, e = fenceRecoveryMAC(store.tree, evidence)
		if e != nil {
			return nil, e
		}
		evidence.RecoveryMAC, e = fenceRecoveryOuterMAC(secret, evidence)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(evidence)
		if e != nil || checkHeld() != nil {
			return nil, ErrFenceRequired
		}
		return raw, nil
	}
	if e = checkHeld(); e != nil {
		_ = end()
		return nil, nil, e
	}
	return seal, func() error {
		if checkHeld() != nil {
			_ = end()
			return ErrFenceRequired
		}
		return end()
	}, nil
}
