//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// VerifyRetainedMasterRebind observes a completed rebind under the original
// offline maintenance and shared tree leases. The caller opens the tree with
// OpenMasterSQLite against the pinned installed database and node identity.
// The report must come from independently verified archive bytes.
func (s *SQLStore) VerifyRetainedMasterRebind(ctx context.Context, lease *TreeLease, report recovery.Report, data, secrets, databaseRel, nodeID string) error {
	m := report.Manifest
	if !s.valid() || ctx == nil || lease == nil || !hexID(report.SHA256) || !lowerHex(nodeID, 32) || !fs.ValidPath(databaseRel) || databaseRel == "." ||
		m.Format != recovery.Format || m.Version != 2 || m.Scope != recovery.UpgradeStateScope || m.Role != "Master" || m.Database != "sqlite" ||
		m.NodeID != nodeID || m.SchemaGeneration != migrations.Generation || len(m.TreeEvidence) == 0 || len(m.TreeEvidence) > 4096 ||
		checkRetainedTreeRoots(data, secrets) != nil {
		return ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	f := lease.fence
	fencePath := filepath.Join(data, MasterFenceDirectory)
	if f == nil || f.store != s || lease.exclusive || f.directory != fencePath || lease.checkLocked(ctx) != nil {
		return ErrFenceRequired
	}
	var database string
	if s.db.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&database) != nil || database != filepath.Join(data, databaseRel) {
		return ErrFenceRequired
	}
	var evidence fenceRecoveryEvidence
	decoder := json.NewDecoder(bytes.NewReader(m.TreeEvidence))
	decoder.DisallowUnknownFields()
	digest, err := recovery.TreeManifestDigest(m)
	if err != nil || decoder.Decode(&evidence) != nil || decoder.Decode(new(any)) != io.EOF || evidence.Version != 1 || evidence.ManifestSHA != digest || evidence.NodeID != nodeID ||
		evidence.Inode == 0 || evidence.Generation < 0 || evidence.Generation == int64(^uint64(0)>>1) {
		return ErrFenceRequired
	}
	wantGeneration := evidence.Generation
	if f.tag() != evidence.OldTag {
		wantGeneration++
	}
	if lease.generation != wantGeneration {
		return ErrFenceRequired
	}
	keys, err := openPrivateTreeDirectory(secrets)
	if err != nil {
		return err
	}
	defer keys.Close()
	for _, name := range []string{treeKeyFile, "node-vault.key"} {
		if err := verifyArchivedFile(ctx, keys, name, "runtime_secrets/"+name, report); err != nil {
			return err
		}
	}
	secret, err := OpenTreeSecretFile(keys)
	if err != nil {
		return err
	}
	defer clear(secret)
	outer, outerErr := fenceRecoveryOuterMAC(secret, evidence)
	inner, innerErr := fenceRecoveryMAC(s.tree, evidence)
	if outerErr != nil || innerErr != nil || !hmac.Equal([]byte(outer), []byte(evidence.RecoveryMAC)) || !hmac.Equal([]byte(inner), []byte(evidence.MAC)) {
		return ErrFenceRequired
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := checkRetainedTreeDataDirectory(root); err != nil {
		return err
	}
	if err := checkRetainedTreeSQLite(ctx, root, databaseRel, MasterFenceDirectory, report, false); err != nil {
		return err
	}
	dbDevice, dbInode, err := privateInode(root, databaseRel)
	if err != nil {
		return err
	}
	intent := treeRebindIntent{Version: 1, ArchiveSHA: report.SHA256, EvidenceMAC: evidence.MAC, NodeID: nodeID, DatabaseDevice: dbDevice, DatabaseInode: dbInode, FenceDevice: f.device, FenceInode: f.inode}
	intent.MAC, err = treeRebindIntentMAC(secret, intent)
	if err != nil {
		return err
	}
	info, err := root.Lstat(treeRebindIntentName)
	if err != nil || checkTreeRebindIntent(root, info, intent, false) != nil {
		return ErrFenceRequired
	}
	return lease.checkLocked(ctx)
}
