package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func recoveryVerifyCommand(output io.Writer) error {
	c, e := config.Load()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := openExistingStore(ctx, c)
	if e != nil {
		return e
	}
	defer db.Close()
	identity, e := node.OpenExisting(ctx, db.Nodes(), c.SecretsDirectory)
	if e != nil {
		return e
	}
	snapshot, e := db.Maintenance().InspectMaintenance(ctx)
	if e != nil || !snapshot.LogicalIdle {
		return errors.New("recovery has unresolved resource transactions")
	}
	repo, ok := db.Maintenance().(store.RecoveryRepository)
	if !ok {
		return errors.New("recovery resource inspection unsupported")
	}
	samples, e := repo.RecoverySamples(ctx, 16)
	if e != nil {
		return e
	}
	root, e := os.OpenRoot(filepath.Join(c.DataRoot, "media"))
	if e != nil {
		return e
	}
	defer root.Close()
	proofs := []map[string]any{}
	for _, sample := range samples {
		if !fs.ValidPath(sample.Path) {
			return errors.New("invalid recovered resource path")
		}
		before, e := root.Lstat(sample.Path)
		if e != nil || !before.Mode().IsRegular() {
			return errors.New("recovered managed resource is missing or unsafe")
		}
		if sample.Encryption != nil && (sample.Encryption.Validate() != nil || sample.Encryption.CiphertextSize != before.Size()) {
			return errors.New("recovered ciphertext differs from its descriptor")
		}
		file, e := root.Open(sample.Path)
		if e != nil {
			return e
		}
		info, e := file.Stat()
		if e != nil || !os.SameFile(before, info) {
			file.Close()
			return errors.New("recovered resource changed while opening")
		}
		// Exercise actual random access near both ends without payload-sized memory.
		buffer := make([]byte, 4096)
		size := min(info.Size(), int64(len(buffer)))
		_, e = file.ReadAt(buffer[:size], 0)
		if e != nil && e != io.EOF {
			file.Close()
			return e
		}
		sum := sha256.Sum256(buffer[:size])
		if info.Size() > size {
			if _, e = file.ReadAt(buffer[:size], info.Size()-size); e != nil && e != io.EOF {
				file.Close()
				return e
			}
		}
		file.Close()
		proofs = append(proofs, map[string]any{"media_id": sample.ID, "size_bytes": info.Size(), "sample_sha256": hex.EncodeToString(sum[:])})
	}
	return json.NewEncoder(output).Encode(map[string]any{"node_id": identity.ID, "schema_generation": snapshot.SchemaGeneration, "managed_read_samples": proofs, "sample_limit": 16, "whole_archive_validation_required": true})
}
