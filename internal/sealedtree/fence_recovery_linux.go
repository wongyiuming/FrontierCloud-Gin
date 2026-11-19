//go:build linux

package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// fenceRecoveryEvidence is internal trusted-backup metadata. The keyed MAC
// uses the existing Master tree key; no extra user key is introduced. The
// manifest digest must be calculated from a verified private archive,
// never supplied as an untrusted authorization claim.
// This primitive neither validates the whole archive nor opens service.
type fenceRecoveryEvidence struct {
	Version                                                  int `json:"version"`
	ManifestSHA, NodeID, RootVerifier, MasterBinding, OldTag string
	Device, Inode                                            uint64
	Generation                                               int64
	MAC                                                      string
	RecoveryMAC                                              string
}

func fenceRecoveryMAC(tree *Tree, v fenceRecoveryEvidence) (string, error) {
	v.MAC = ""
	v.RecoveryMAC = ""
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	m := hmac.New(sha256.New, tree.indexKey[:])
	m.Write([]byte("frontiercloud:tree-fence-recovery:v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// fenceRecoveryOuterMAC authenticates the embedded evidence using the existing tree
// secret before opening SQLite. This prevents forged evidence from triggering
// incidental SQLite/WAL recovery against otherwise untouched material.
func fenceRecoveryOuterMAC(secret []byte, v fenceRecoveryEvidence) (string, error) {
	if len(secret) != 32 {
		return "", ErrInvalid
	}
	v.RecoveryMAC = ""
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("frontiercloud:tree-fence-recovery-outer:v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}
func recoveryFenceLocation(dataRoot string, root *os.Root, directory string) error {
	absolute, err := filepath.Abs(dataRoot)
	if err != nil {
		return ErrFenceRequired
	}
	rel, err := filepath.Rel(absolute, directory)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) || checkFenceDirectory(root, directory) != nil {
		return ErrFenceRequired
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return ErrFenceRequired
	}
	target, err := filepath.EvalSymlinks(directory)
	if err != nil || filepath.Clean(target) != filepath.Join(canonical, rel) {
		return ErrFenceRequired
	}
	return nil
}
func recoverySQLite(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	p := filepath.ToSlash(absolute)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	u.RawQuery = url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(100)"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	return db, nil
}
func recoveryMasterBinding(ctx context.Context, q treeQuery, s *SQLStore, root *os.Root, nodeVault *vault.Vault, expectedNode string) (string, error) {
	var node, role, sealed string
	var created int64
	if q.QueryRowContext(ctx, `SELECT node_id,role,private_key,created_at FROM node_identity WHERE singleton=1`).Scan(&node, &role, &sealed, &created) != nil || node != expectedNode || role != "Master" || sealed == "" || created <= 0 {
		return "", ErrFenceRequired
	}
	if nodeVault == nil {
		return "", ErrFenceRequired
	}
	privateKey, err := nodeVault.Unseal(sealed)
	if err != nil {
		return "", ErrFenceRequired
	}
	if _, err = protocol.PublicKey(privateKey); err != nil {
		return "", ErrFenceRequired
	}
	binding := existingMasterBinding(s.tree, s.rootID, node, sealed, created)
	defer clear(binding)
	if _, err := checkExistingMasterBinding(root, binding); err != nil {
		return "", err
	}
	return hex.EncodeToString(binding), nil
}

// captureFenceEvidenceHeld requires the caller to hold the exact native
// maintenance lease used to create and fsync the verified private archive.
func captureFenceEvidenceHeld(c context.Context, check func() error, dataRoot, databasePath string, root *os.Root, directory string, secret []byte, nodeVault *vault.Vault, nodeID, archiveSHA string) (fenceRecoveryEvidence, error) {
	if check() != nil || recoveryFenceLocation(dataRoot, root, directory) != nil {
		return fenceRecoveryEvidence{}, ErrFenceRequired
	}
	db, e := recoverySQLite(databasePath)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	defer db.Close()
	s, e := OpenSQLiteWithMaster(c, db, secret)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	f, e := OpenFence(c, s, root, directory)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	lease, e := s.AcquireReadFence(c)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	defer lease.Release()
	binding, e := recoveryMasterBinding(c, db, s, root, nodeVault, nodeID)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	verifier, e := s.tree.namespaceVerifier(s.rootID)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	if lease.Check(c) != nil || check() != nil {
		return fenceRecoveryEvidence{}, ErrFenceChanged
	}
	v := fenceRecoveryEvidence{Version: 1, ManifestSHA: archiveSHA, NodeID: nodeID, RootVerifier: verifier, MasterBinding: binding, OldTag: f.tag(), Device: f.device, Inode: f.inode, Generation: lease.generation}
	v.MAC, e = fenceRecoveryMAC(s.tree, v)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	v.RecoveryMAC, e = fenceRecoveryOuterMAC(secret, v)
	if e != nil {
		return fenceRecoveryEvidence{}, e
	}
	if lease.Check(c) != nil || check() != nil {
		return fenceRecoveryEvidence{}, ErrFenceChanged
	}
	return v, nil
}

// rebindOfflineFencePrepared is reached by the verified archive coordinator;
// prepare must validate material/retry intent while the same maintenance lease
// is held. It never opens the product gate or asserts Owner completeness.
func rebindOfflineFencePrepared(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, root *os.Root, directory string, master []byte, nodeVault *vault.Vault, nodeID, archiveSHA string, evidence fenceRecoveryEvidence, prepare, sealIntent func(context.Context, func() error) error) (already bool, err error) {
	if ctx == nil || gate == nil || prepare == nil || sealIntent == nil || nodeVault == nil || len(master) != 32 || !lowerHex(nodeID, 32) || !hexID(archiveSHA) || evidence.Version != 1 || evidence.NodeID != nodeID || evidence.ManifestSHA != archiveSHA || evidence.Inode == 0 || evidence.Generation < 0 || evidence.Generation == int64(^uint64(0)>>1) || recoveryFenceLocation(dataRoot, root, directory) != nil {
		return false, ErrInvalid
	}
	secret := append([]byte(nil), master...)
	defer clear(secret)
	outer, outerErr := fenceRecoveryOuterMAC(secret, evidence)
	if outerErr != nil || !hmac.Equal([]byte(outer), []byte(evidence.RecoveryMAC)) {
		return false, ErrFenceRequired
	}
	err = gate.InspectSQLite(ctx, dataRoot, databasePath, func(c context.Context, check func() error) error {
		if e := prepare(c, check); e != nil {
			return e
		}
		db, e := recoverySQLite(databasePath)
		if e != nil {
			return e
		}
		defer db.Close()
		s, e := OpenSQLiteWithMaster(c, db, secret)
		if e != nil {
			return e
		}
		expectedMAC, e := fenceRecoveryMAC(s.tree, evidence)
		if e != nil || !hmac.Equal([]byte(expectedMAC), []byte(evidence.MAC)) {
			return ErrFenceRequired
		}
		verifier, e := s.tree.namespaceVerifier(s.rootID)
		if e != nil || !hmac.Equal([]byte(verifier), []byte(evidence.RootVerifier)) {
			return ErrFenceRequired
		}
		file, e := root.OpenFile(treeFenceFile, os.O_RDWR, 0)
		if e != nil {
			return ErrFenceRequired
		}
		defer file.Close()
		if e = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
			return ErrFenceRequired
		}
		defer unlockFenceFile(file)
		info, e := file.Stat()
		if e != nil {
			return ErrFenceRequired
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrFenceRequired
		}
		f := &TreeFence{store: s, root: root, directory: directory, device: uint64(stat.Dev), inode: stat.Ino}
		if n, e := file.ReadAt(f.id[:], 0); e != nil || n != len(f.id) {
			return ErrFenceRequired
		}
		if f.checkFile(file) != nil || check() != nil || recoveryFenceLocation(dataRoot, root, directory) != nil {
			return ErrFenceRequired
		}
		original := *f
		original.device = evidence.Device
		original.inode = evidence.Inode
		if !hmac.Equal([]byte(original.tag()), []byte(evidence.OldTag)) {
			return ErrFenceRequired
		}
		conn, e := db.Conn(c)
		if e != nil {
			return e
		}
		defer conn.Close()
		if _, e = conn.ExecContext(c, `BEGIN IMMEDIATE`); e != nil {
			return e
		}
		committed := false
		defer func() {
			if !committed {
				_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
			}
		}()
		if e = s.verifyRoot(c, conn); e != nil {
			return e
		}
		binding, e := recoveryMasterBinding(c, conn, s, root, nodeVault, nodeID)
		if e != nil || !hmac.Equal([]byte(binding), []byte(evidence.MasterBinding)) {
			return ErrFenceRequired
		}
		var tag string
		var gen int64
		if conn.QueryRowContext(c, `SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&tag) != nil || conn.QueryRowContext(c, `SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&gen) != nil {
			return ErrFenceRequired
		}
		currentTag := f.tag()
		oldState := hmac.Equal([]byte(tag), []byte(evidence.OldTag)) && gen == evidence.Generation
		newState := hmac.Equal([]byte(tag), []byte(currentTag)) && gen == evidence.Generation+1
		if !oldState && !newState {
			return ErrFenceRequired
		}
		// The durable intent may be created only after the source proof,
		// restored identity, old fence and exact state have all been verified.
		if e = sealIntent(c, check); e != nil {
			return e
		}
		if newState {
			already = true
		} else if hmac.Equal([]byte(tag), []byte(evidence.OldTag)) && gen == evidence.Generation {
			if currentTag == evidence.OldTag {
				already = true
			} else {
				result, e := conn.ExecContext(c, `UPDATE sealed_tree_fence SET fence_tag=? WHERE singleton=1 AND fence_tag=?`, currentTag, evidence.OldTag)
				if e != nil {
					return e
				}
				if n, e := result.RowsAffected(); e != nil || n != 1 {
					return ErrFenceRequired
				}
				result, e = conn.ExecContext(c, `UPDATE sealed_tree_meta SET write_fence=write_fence+1 WHERE singleton=1 AND write_fence=?`, evidence.Generation)
				if e != nil {
					return e
				}
				if n, e := result.RowsAffected(); e != nil || n != 1 {
					return ErrFenceRequired
				}
			}
		} else {
			return ErrFenceRequired
		}
		if c.Err() != nil || check() != nil || f.checkFile(file) != nil {
			return ErrFenceRequired
		}
		if _, e = conn.ExecContext(c, `COMMIT`); e != nil {
			return e
		}
		committed = true
		if check() != nil || f.checkFile(file) != nil {
			return ErrFenceRequired
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return already, nil
}
