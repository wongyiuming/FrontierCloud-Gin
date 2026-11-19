//go:build linux

package sealedtree

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"golang.org/x/sys/unix"
)

// PrepareEmptyMasterSQLite initializes a fresh namespace for future uploads.
// The existing native database, Master identity, private vault and maintenance
// lease are required. Legacy user media must be cleared using business APIs
// before preparation. This command never imports or deletes content.
func PrepareEmptyMasterSQLite(ctx context.Context, c config.Config, gate *maintenance.Gate, expectedMaster string) error {
	if c.DeploymentMode != config.DeploymentBusiness || !lowerHex(expectedMaster, 32) || !filepath.IsAbs(c.DataRoot) || filepath.Clean(c.DataRoot) != c.DataRoot {
		return ErrInvalid
	}
	fenceDir := filepath.Join(c.DataRoot, MasterFenceDirectory)
	return initializeSQLiteOffline(ctx, c, gate, fenceDir, true, func(ctx context.Context, q *sql.Conn, keys *os.Root, nodeID string, fresh bool) (*Tree, string, error) {
		if nodeID != expectedMaster {
			return nil, "", ErrInvalid
		}
		if !fresh {
			if err := prepareMediaPremaster(ctx, q, c.DataRoot, false); err != nil {
				return nil, "", err
			}
			secret, err := OpenTreeSecretFile(keys)
			if err != nil {
				return nil, "", err
			}
			defer clear(secret)
			var salt, sealed []byte
			if err = q.QueryRowContext(ctx, `SELECT salt,root_sealed FROM sealed_tree_meta WHERE singleton=1 AND version=1`).Scan(&salt, &sealed); err != nil {
				return nil, "", err
			}
			tree, err := New(secret, salt)
			if err != nil {
				return nil, "", err
			}
			var verifier string
			if err = q.QueryRowContext(ctx, `SELECT verifier FROM sealed_tree_capacity_meta WHERE singleton=1`).Scan(&verifier); err != nil ||
				subtle.ConstantTimeCompare([]byte(verifier), []byte(opaqueledger.Verifier(tree.capacityKey[:]))) != 1 {
				return nil, "", ErrFenceRequired
			}
			rootID, err := tree.OpenRoot(sealed)
			return tree, rootID, err
		}

		for _, query := range []string{
			`SELECT EXISTS(SELECT 1 FROM media_objects WHERE NOT (object_kind='lyric' AND media_path='lyrics/default.lrc'))`,
			`SELECT EXISTS(SELECT 1 FROM global_media_objects WHERE state<>'deleted')`,
			`SELECT EXISTS(SELECT 1 FROM karaoke_recordings WHERE state<>'deleted')`,
			`SELECT EXISTS(SELECT 1 FROM s3_objects WHERE state<>'deleted')`,
		} {
			var hasContent bool
			if err := q.QueryRowContext(ctx, query).Scan(&hasContent); err != nil || hasContent {
				return nil, "", ErrConflict
			}
		}
		data, err := os.OpenRoot(c.DataRoot)
		if err != nil {
			return nil, "", err
		}
		defer data.Close()
		if err = checkEmptyMediaDestination(data, true); err != nil {
			return nil, "", err
		}
		if err := prepareMediaPremaster(ctx, q, c.DataRoot, true); err != nil {
			return nil, "", err
		}
		if err = data.Mkdir(MasterFenceDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
		fence, err := openPrivateTreeDirectory(fenceDir)
		if err != nil {
			return nil, "", err
		}
		defer fence.Close()
		if err = recoveryFenceLocation(c.DataRoot, fence, fenceDir); err != nil {
			return nil, "", err
		}
		for _, name := range []string{treeFenceFile, existingMasterBindingFile} {
			if _, err = fence.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return nil, "", ErrFenceRequired
			}
		}
		if err = syncRootDir(data, "."); err != nil {
			return nil, "", err
		}
		secret, err := OpenTreeSecretFile(keys)
		if err != nil {
			if _, state := keys.Lstat(MasterKeyFile); !errors.Is(state, os.ErrNotExist) {
				return nil, "", err
			}
			secret, err = CreateTreeSecretFile(keys)
			if err != nil {
				return nil, "", err
			}
		}
		defer clear(secret)
		salt, err := NewSalt()
		if err != nil {
			return nil, "", err
		}
		tree, err := New(secret, salt)
		if err != nil {
			return nil, "", err
		}
		if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_meta(singleton,verifier) VALUES(1,?)`, opaqueledger.Verifier(tree.capacityKey[:])); err != nil {
			return nil, "", err
		}
		id, err := NewBlobID()
		return tree, id, err
	})
}

// The media premaster is distinct from the tree and node keys. Its verifier
// must exist before the new tree starts and fences legacy writers.
func prepareMediaPremaster(ctx context.Context, q *sql.Conn, dataRoot string, fresh bool) error {
	var expected string
	err := q.QueryRowContext(ctx, `SELECT key_id FROM media_crypto_keys WHERE singleton=1`).Scan(&expected)
	if errors.Is(err, sql.ErrNoRows) && fresh {
		var encrypted bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM media_encryption WHERE descriptor_json IS NOT NULL)`).Scan(&encrypted); err != nil || encrypted {
			return mediacrypto.ErrPremaster
		}
	} else if err != nil || !lowerHex(expected, 64) {
		return mediacrypto.ErrPremaster
	}
	key, err := mediacrypto.OpenForData(filepath.Join(dataRoot, "media-keys"), expected != "")
	if err != nil {
		return err
	}
	if expected != "" {
		if key.KeyID() != expected {
			return mediacrypto.ErrPremaster
		}
		return nil
	}
	_, err = q.ExecContext(ctx, `INSERT INTO media_crypto_keys(singleton,key_id,created_at) VALUES(1,?,?)`, key.KeyID(), time.Now().Unix())
	return err
}

// CheckEmptyStorageDestination permits only the standard bootstrap files and
// its cooperative media lock. It must be called while maintenance is held.
func CheckEmptyStorageDestination(data *os.Root) error {
	return checkEmptyMediaDestination(data, true)
}

func checkEmptyMediaDestination(data *os.Root, allowPreparedOwner bool) error {
	// Known bootstrap directories and the exact internal fallback lyric can
	// already exist on a fresh Master. Refuse all other physical entries.
	for _, directory := range []string{"media", "media/music", "media/vido", "media/lyrics", "recordings"} {
		info, err := data.Lstat(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() {
			return ErrConflict
		}
		dir, err := data.Open(directory)
		if err != nil {
			return ErrConflict
		}
		opened, statErr := dir.Stat()
		entries, readErr := dir.ReadDir(7)
		dir.Close()
		if statErr != nil || !os.SameFile(info, opened) || readErr != nil && readErr != io.EOF || len(entries) >= 7 {
			return ErrConflict
		}
		for _, entry := range entries {
			name := entry.Name()
			if directory == "media" && entry.IsDir() && (name == "music" || name == "vido" || name == "lyrics") {
				continue
			}
			if allowPreparedOwner && directory == "media" && name == ".opaque-aliases" && entry.IsDir() {
				aliasDir, err := data.Open("media/.opaque-aliases")
				if err != nil {
					return ErrConflict
				}
				original, statErr := entry.Info()
				opened, openErr := aliasDir.Stat()
				items, readErr := aliasDir.ReadDir(3)
				aliasDir.Close()
				if statErr != nil || openErr != nil || !os.SameFile(original, opened) || opened.Mode().Perm()&0077 != 0 || (readErr != nil && readErr != io.EOF) || len(items) != 2 {
					return ErrConflict
				}
				for _, item := range items {
					if item.Name() != ".owner-control-binding" && item.Name() != ".owner-control-lock" {
						return ErrConflict
					}
					file, e := data.Open("media/.opaque-aliases/" + item.Name())
					if e != nil {
						return ErrConflict
					}
					before, a := item.Info()
					after, b := file.Stat()
					file.Close()
					if a != nil || b != nil || !privateBindingFile(after) || !os.SameFile(before, after) {
						return ErrConflict
					}
				}
				continue
			}
			if allowPreparedOwner && (directory == "media" && (name == ".media-mutation.lock" || name == ".node-control.lock") || directory == "recordings" && name == ".recordings-mutation.lock") && entry.Type().IsRegular() {
				lock, err := data.Open(directory + "/" + name)
				if err != nil {
					return ErrConflict
				}
				original, e := entry.Info()
				opened, f := lock.Stat()
				valid := e == nil && f == nil && privateBindingFile(opened) && os.SameFile(original, opened) && (name != ".node-control.lock" || opened.Size() == 0)
				if valid && name == ".node-control.lock" {
					// Maintenance excludes cooperative native writers; also refuse
					// an existing independent holder of this exact control inode.
					valid = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
					if valid {
						valid = unix.Flock(int(lock.Fd()), unix.LOCK_UN) == nil
					}
				}
				lock.Close()
				if valid {
					continue
				}
				return ErrConflict
			}
			if directory == "media/lyrics" && name == "default.lrc" && entry.Type().IsRegular() {
				file, err := data.Open("media/lyrics/default.lrc")
				if err != nil {
					return ErrConflict
				}
				original, statErr := entry.Info()
				opened, fileErr := file.Stat()
				raw, readErr := io.ReadAll(io.LimitReader(file, int64(len(sourceauth.DefaultLyricContent))+1))
				file.Close()
				if statErr == nil && fileErr == nil && os.SameFile(original, opened) && readErr == nil && string(raw) == sourceauth.DefaultLyricContent {
					continue
				}
			}
			return ErrConflict
		}
	}
	return nil
}
