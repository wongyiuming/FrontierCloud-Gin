package business_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestColdBackupFilesPayloadRetentionReplayCorruptionAndInterruptedReceive(t *testing.T) {
	db, raw, rel := backupFixture(t)
	configured, ok := db.(interface{ ConfigureFileBackups(string) error })
	if !ok {
		t.Skip("storage appliance is embedded SQLite only")
	}
	dir := t.TempDir()
	if err := configured.ConfigureFileBackups(dir); err != nil {
		t.Fatal(err)
	}
	ctx, repo := context.Background(), db.Backups()
	payload := bytes.Repeat([]byte("cold-file-bytes"), 20_000)
	checksum := backupChecksum(payload)
	write := func(gen int64) {
		t.Helper()
		if err := repo.BeginBackup(ctx, rel.ID, gen, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		for offset, index := 0, 0; offset < len(payload); index++ {
			end := min(len(payload), offset+store.MaxBackupChunk)
			part := payload[offset:end]
			if err := repo.AppendBackup(ctx, rel.ID, gen, index, part); err != nil {
				t.Fatal(err)
			}
			if err := repo.AppendBackup(ctx, rel.ID, gen, index, part); err != nil {
				t.Fatal("lost acknowledgement replay", err)
			}
			offset = end
		}
		var sqlBytes int64
		if err := raw.QueryRow("SELECT COALESCE(SUM(LENGTH(payload)),0) FROM cluster_business_backup_chunks WHERE master_id=? AND generation=?", rel.PeerID, gen).Scan(&sqlBytes); err != nil || sqlBytes > 128 {
			t.Fatal("recovery payload stored in SQL", sqlBytes, err)
		}
		if _, err := repo.CommitBackup(ctx, rel.ID, gen, checksum, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CommitBackup(ctx, rel.ID, gen, checksum, store.NodeAudit{}); err != nil {
			t.Fatal("commit replay", err)
		}
	}
	write(100)
	_, err := repo.ReadReadyBackup(ctx, rel.PeerID, 100, func(_ store.BackupManifest, r io.Reader) error {
		first := make([]byte, 1)
		if _, err := io.ReadFull(r, first); err != nil {
			return err
		}
		write(101)
		write(102) // Open immutable inode survives retention/unlink.
		rest, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if !bytes.Equal(append(first, rest...), payload) {
			t.Fatal("cold snapshot mixed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := 0
	for _, entry := range entries {
		if entry.Name() != ".lock" {
			artifacts++
		}
	}
	if artifacts != 2 {
		t.Fatal("physical retention must contain exactly two complete artifacts", artifacts)
	}
	if _, err := repo.ReadReadyBackup(ctx, rel.PeerID, 102, func(store.BackupManifest, io.Reader) error { return nil }); err == nil {
		t.Fatal("prefix accepted as full proof")
	}
	if err := repo.BeginBackup(ctx, rel.ID, 103, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendBackup(ctx, rel.ID, 103, 0, []byte("interrupted")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AbortBackups(ctx, rel.ID, 103, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	var databasePath string
	if err := raw.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&databasePath); err != nil {
		t.Fatal(err)
	}
	readOnly, err := sqlitestore.OpenReadOnly(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := readOnly.OpenFileBackupsReadOnly(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.Backups().ReadReadyBackup(ctx, rel.PeerID, 102, func(_ store.BackupManifest, r io.Reader) error {
		got, err := io.ReadAll(r)
		if !bytes.Equal(got, payload) {
			t.Fatal("read-only recovery payload changed")
		}
		return err
	}); err != nil {
		t.Fatal("read-only cold proof failed", err)
	}
	if err := readOnly.Backups().BeginBackup(ctx, rel.ID, 104, store.NodeAudit{}); err == nil {
		t.Fatal("read-only cold store admitted a writer")
	}
	name := filepath.Join(dir, fmt.Sprintf("artifact.%s.102.%s", rel.PeerID, checksum))
	if err := os.WriteFile(name, bytes.Repeat([]byte("x"), len(payload)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReadReadyBackup(ctx, rel.PeerID, 102, func(_ store.BackupManifest, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}
