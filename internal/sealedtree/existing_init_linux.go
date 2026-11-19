//go:build linux

package sealedtree

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

const existingMasterBindingFile = "tree-master.binding"

func existingMasterBinding(tree *Tree, rootID, nodeID, nodeKey string, createdAt int64) []byte {
	raw, _ := json.Marshal(struct {
		Root    string `json:"root"`
		ID      string `json:"id"`
		Key     string `json:"sealed_key"`
		Created int64  `json:"created_at"`
	}{rootID, nodeID, nodeKey, createdAt})
	defer clear(raw)
	h := hmac.New(sha256.New, tree.indexKey[:])
	h.Write([]byte("frontiercloud:sealed-tree:existing-master:v1\x00"))
	h.Write(raw)
	return h.Sum(nil)
}

func checkExistingMasterBinding(root *os.Root, expected []byte) (os.FileInfo, error) {
	info, err := root.Lstat(existingMasterBindingFile)
	if err != nil || !privateBindingFile(info) || info.Size() != int64(len(expected)) {
		return nil, ErrFenceRequired
	}
	f, err := root.Open(existingMasterBindingFile)
	if err != nil {
		return nil, ErrFenceRequired
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !privateBindingFile(opened) || !os.SameFile(info, opened) {
		return nil, ErrFenceRequired
	}
	raw := make([]byte, len(expected))
	defer clear(raw)
	if n, err := io.ReadFull(f, raw); err != nil || n != len(raw) || !hmac.Equal(raw, expected) {
		return nil, ErrFenceRequired
	}
	current, err := root.Lstat(existingMasterBindingFile)
	if err != nil || !privateBindingFile(current) || !os.SameFile(opened, current) {
		return nil, ErrFenceRequired
	}
	return opened, nil
}

func privateBindingFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0600 != 0600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid())
}

func readPrivateTreeVault(root *os.Root) (os.FileInfo, []byte, error) {
	const name = "node-vault.key"
	named, err := root.Lstat(name)
	if err != nil || !privateBindingFile(named) || named.Size() < 1 || named.Size() > 128 {
		return nil, nil, ErrFenceRequired
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, ErrFenceRequired
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !privateBindingFile(opened) || !os.SameFile(named, opened) {
		return nil, nil, ErrFenceRequired
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	current, pathErr := root.Lstat(name)
	if err != nil || int64(len(raw)) != named.Size() || pathErr != nil || !privateBindingFile(current) || !os.SameFile(named, current) {
		clear(raw)
		return nil, nil, ErrFenceRequired
	}
	return named, raw, nil
}

// InitializeExistingSQLiteOffline remains fail-closed until every legacy
// writer and offline worker enforces the durable marker across restarts.
func InitializeExistingSQLiteOffline(context.Context, config.Config, *maintenance.Gate, *Tree, string, string) error {
	return ErrLegacyWritersUnfenced
}

// initializeExistingSQLiteOffline is an isolated maintenance primitive.
// It never creates or selects the business database, never removes old data,
// and does not authorize import or activate the product tree. The already
// existing deployment binding, maintenance marker, caller-supplied tree key,
// and private fence directory are all mandatory. Only cooperating local native
// processes are fenced; direct SQL and another host remain outside its proof.
// A partial or damaged fence is retained and fails closed for operator review.
func initializeExistingSQLiteOffline(ctx context.Context, c config.Config, gate *maintenance.Gate, tree *Tree, rootID, fenceDir string) error {
	if tree == nil {
		return ErrInvalid
	}
	return initializeSQLiteOffline(ctx, c, gate, fenceDir, false, func(context.Context, *sql.Conn, *os.Root, string, bool) (*Tree, string, error) {
		return tree, rootID, nil
	})
}

func initializeSQLiteOffline(ctx context.Context, c config.Config, gate *maintenance.Gate, fenceDir string, preparedOwner bool, prepare func(context.Context, *sql.Conn, *os.Root, string, bool) (*Tree, string, error)) error {
	if ctx == nil || c.DatabaseType != config.DatabaseSQLite || gate == nil || !filepath.IsAbs(fenceDir) || filepath.Clean(fenceDir) != fenceDir {
		return ErrInvalid
	}
	rootPath, err := filepath.Abs(c.DataRoot)
	if err != nil {
		return ErrInvalid
	}
	rel, err := filepath.Rel(rootPath, fenceDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ErrFenceRequired
	}
	return gate.InspectSQLite(ctx, c.DataRoot, c.SQLitePath, func(held context.Context, recheckSQLite func() error) error {
		bindingPath := filepath.Join(c.DataRoot, deployment.Binding)
		bindingInfo, err := os.Lstat(bindingPath)
		if err != nil || !privateBindingFile(bindingInfo) {
			return ErrFenceRequired
		}
		if _, err = deployment.ReadRetainedBinding(c); err != nil {
			return ErrFenceRequired
		}
		secretDir, err := filepath.Abs(c.SecretsDirectory)
		if err != nil || c.SecretsDirectory == "" {
			return ErrFenceRequired
		}
		// Compose mounts the existing private runtime_secrets volume
		// independently of DATA_ROOT. Pin that configured directory and vault.
		secretRoot, err := openPrivateTreeDirectory(secretDir)
		if err != nil {
			return err
		}
		defer secretRoot.Close()
		vaultInfo, vaultRaw, err := readPrivateTreeVault(secretRoot)
		if err != nil {
			return ErrFenceRequired
		}
		vaultHash := sha256.Sum256(vaultRaw)
		masterVault, err := vault.New(string(vaultRaw))
		clear(vaultRaw)
		if err != nil {
			return ErrFenceRequired
		}
		checkBinding := func() error {
			current, err := os.Lstat(bindingPath)
			if err != nil || !privateBindingFile(current) || !os.SameFile(bindingInfo, current) {
				return ErrFenceRequired
			}
			if _, err = deployment.ReadRetainedBinding(c); err != nil {
				return ErrFenceRequired
			}
			named, err := os.Lstat(secretDir)
			opened, rootErr := secretRoot.Stat(".")
			if err != nil || rootErr != nil || !named.IsDir() || !os.SameFile(named, opened) || checkPrivateDirectory(secretRoot) != nil {
				return ErrFenceRequired
			}
			currentVault, raw, err := readPrivateTreeVault(secretRoot)
			if err != nil {
				return ErrFenceRequired
			}
			currentHash := sha256.Sum256(raw)
			clear(raw)
			if !os.SameFile(vaultInfo, currentVault) || subtle.ConstantTimeCompare(vaultHash[:], currentHash[:]) != 1 {
				return ErrFenceRequired
			}
			return nil
		}
		absolute, err := filepath.Abs(c.SQLitePath)
		if err != nil {
			return ErrInvalid
		}
		databaseURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
		values := databaseURL.Query()
		values.Set("mode", "rw") // never create an absent business database
		values.Add("_pragma", "busy_timeout(5000)")
		databaseURL.RawQuery = values.Encode()
		db, err := sql.Open("sqlite", databaseURL.String())
		if err != nil {
			return err
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		conn, err := db.Conn(held)
		if err != nil {
			return err
		}
		defer conn.Close()
		var selected string
		if err = conn.QueryRowContext(held, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&selected); err != nil || filepath.Clean(selected) != filepath.Clean(absolute) {
			return ErrInvalid
		}
		if _, err = conn.ExecContext(held, `BEGIN IMMEDIATE`); err != nil {
			return err
		}
		transactionOpen := true
		defer func() {
			if transactionOpen {
				rollback, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = conn.ExecContext(rollback, `ROLLBACK`)
			}
		}()
		if err = schema.ValidateSQLiteTree(held, conn, false); err != nil {
			return err
		}
		var nodeID, role, nodeKey string
		var createdAt int64
		if err = conn.QueryRowContext(held, "SELECT node_id,`role`,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&nodeID, &role, &nodeKey, &createdAt); err != nil || len(nodeID) != 32 || strings.ToLower(nodeID) != nodeID || role != "Master" || createdAt <= 0 {
			return ErrInvalid
		}
		if _, err = hex.DecodeString(nodeID); err != nil {
			return ErrInvalid
		}
		// Maintenance drains cooperative processes, not durable work. An old
		// unfinished session or recovery journal could otherwise resume after
		// the tree root is installed. Refuse; never mutate or delete it here.
		for _, query := range []string{
			`SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'`,
			`SELECT COUNT(*) FROM cluster_upload_sessions WHERE state NOT IN ('complete','cancelled')`,
			`SELECT COUNT(*) FROM global_media_objects WHERE state<>'active'`,
			`SELECT COUNT(*) FROM karaoke_recordings WHERE state NOT IN ('ready','deleted')`,
			`SELECT COUNT(*) FROM karaoke_users WHERE status NOT IN ('active','banned','deleted')`,
			`SELECT COUNT(*) FROM cluster_storage_members WHERE reserved_bytes<>0`,
			`SELECT COUNT(*) FROM cluster_business_backups WHERE state NOT IN ('ready','failed')`,
			`SELECT COUNT(*) FROM cluster_worker_jobs WHERE state NOT IN ('queued','complete')`,
			`SELECT COUNT(*) FROM migration_tasks WHERE state NOT IN ('completed','cancelled')`,
			`SELECT COUNT(*) FROM migration_capacity WHERE reserved_bytes<>0`,
			`SELECT COUNT(*) FROM migration_scopes`,
			`SELECT COUNT(*) FROM migration_storage_journal WHERE state NOT IN ('published','deleted','aborted')`,
			`SELECT COUNT(*) FROM migration_peer_bindings b LEFT JOIN migration_storage_journal j ON b.task_id=j.task_id AND b.logical_id=j.logical_id WHERE j.task_id IS NULL`,
			store.OpaqueMigrationUnsettledSQL,
			`SELECT COUNT(*) FROM s3_uploads WHERE state NOT IN ('published','aborted') OR create_uncertain<>0`,
			`SELECT COUNT(*) FROM s3_upload_parts p LEFT JOIN s3_uploads u ON u.upload_id=p.upload_id WHERE u.upload_id IS NULL`,
			`SELECT COUNT(*) FROM s3_probe_journal WHERE state<>'settled'`,
			`SELECT COUNT(*) FROM s3_objects WHERE state NOT IN ('active','deleted')`,
			`SELECT COUNT(*) FROM s3_members WHERE cleanup_only<>0`,
		} {
			var pending int64
			if err = conn.QueryRowContext(held, query).Scan(&pending); err != nil || pending != 0 {
				return ErrConflict
			}
		}
		encoded, err := masterVault.Unseal(nodeKey)
		if err != nil {
			return ErrInvalid
		}
		seed, err := protocol.Decode(encoded)
		if err != nil || len(seed) != ed25519.SeedSize {
			clear(seed)
			return ErrInvalid
		}
		clear(seed)
		checkMaster := func(q interface {
			QueryRowContext(context.Context, string, ...any) *sql.Row
		}) error {
			var currentID, currentRole, currentKey string
			var currentCreated int64
			if q.QueryRowContext(held, "SELECT node_id,`role`,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&currentID, &currentRole, &currentKey, &currentCreated) != nil || currentID != nodeID || currentRole != role || currentKey != nodeKey || currentCreated != createdAt {
				return ErrInvalid
			}
			return nil
		}
		var count int
		if err = conn.QueryRowContext(held, `SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&count); err != nil || count > 1 {
			return ErrInvalid
		}
		fresh := count == 0
		if fresh {
			if preparedOwner {
				err = schema.ValidateEmptySQLiteTreeWithOwner(held, conn)
			} else {
				err = schema.ValidateSQLiteTree(held, conn, true)
			}
			if err != nil {
				return err
			}
		}
		if recheckSQLite() != nil || checkBinding() != nil || checkMaster(conn) != nil {
			return ErrFenceRequired
		}
		tree, rootID, err := prepare(held, conn, secretRoot, nodeID, fresh)
		if err != nil {
			return err
		}
		fenceRoot, err := openPrivateTreeDirectory(fenceDir)
		if err != nil {
			return err
		}
		defer fenceRoot.Close()
		if err = recoveryFenceLocation(c.DataRoot, fenceRoot, fenceDir); err != nil {
			return err
		}
		if fresh {
			if _, e := fenceRoot.Lstat(treeFenceFile); !errors.Is(e, os.ErrNotExist) {
				return ErrFenceRequired
			}
			if _, e := fenceRoot.Lstat(existingMasterBindingFile); !errors.Is(e, os.ErrNotExist) {
				return ErrFenceRequired
			}
			verifier, e := tree.namespaceVerifier(rootID)
			if e != nil {
				return e
			}
			sealed, e := tree.SealRoot(rootID)
			if e != nil {
				return e
			}
			id, e := rootEncryptionID(sealed)
			if e != nil {
				return e
			}
			if _, e = reserveID(held, conn, id); e != nil {
				return e
			}
			if _, e = conn.ExecContext(held, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, verifier, tree.salt[:], id, sealed); e != nil {
				return e
			}
			temporary := &SQLStore{db: db, tree: tree, rootID: rootID}
			if e = temporary.initListing(held, conn); e != nil {
				return e
			}
		}
		if err = held.Err(); err != nil {
			return err
		}
		if recheckSQLite() != nil || checkBinding() != nil || checkMaster(conn) != nil {
			return ErrFenceRequired
		}
		if _, err = conn.ExecContext(held, `COMMIT`); err != nil {
			return err
		}
		transactionOpen = false
		if err = conn.Close(); err != nil {
			return err
		}
		store, err := OpenSQLite(held, db, tree, rootID)
		if err != nil {
			return err
		}
		if recheckSQLite() != nil || checkBinding() != nil || checkMaster(db) != nil {
			return ErrFenceRequired
		}
		masterBinding := existingMasterBinding(tree, rootID, nodeID, nodeKey, createdAt)
		defer clear(masterBinding)
		if fresh {
			file, e := fenceRoot.OpenFile(existingMasterBindingFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return ErrFenceRequired
			}
			n, writeErr := file.Write(masterBinding)
			syncErr := file.Sync()
			closeErr := file.Close()
			if n != len(masterBinding) || writeErr != nil || syncErr != nil || closeErr != nil || syncRootDir(fenceRoot, ".") != nil {
				return ErrFenceRequired
			}
		}
		markerInfo, err := checkExistingMasterBinding(fenceRoot, masterBinding)
		if err != nil {
			return err
		}
		_, statErr := fenceRoot.Lstat(treeFenceFile)
		if errors.Is(statErr, os.ErrNotExist) {
			// An existing root with a missing fence may be a damaged tree. Do
			// not recreate it, even if its records happen to be empty.
			if !fresh {
				return ErrFenceRequired
			}
			if _, err = InitializeFence(held, store, fenceRoot, fenceDir); err != nil {
				return err
			}
		} else if statErr != nil {
			return ErrFenceRequired
		} else if _, err = OpenFence(held, store, fenceRoot, fenceDir); err != nil {
			return err
		}
		if _, err = store.Check(held); err != nil {
			return err
		}
		markerAfter, markerErr := checkExistingMasterBinding(fenceRoot, masterBinding)
		if markerErr != nil || !os.SameFile(markerInfo, markerAfter) || recheckSQLite() != nil || checkBinding() != nil || checkMaster(db) != nil {
			return ErrFenceRequired
		}
		return held.Err()
	})
}
