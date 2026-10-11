package media

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestBrowserDownloadPlanChecksAllFilesInBoundedBatches(t *testing.T) {
	root, db, svc := deleteFixture(t)
	ctx := context.Background()
	const directory = "music/large"
	if err := os.Mkdir(filepath.Join(root, directory), 0755); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 5001)
	for i := range paths {
		paths[i] = fmt.Sprintf("%s/%04d.mp3", directory, i)
		if err := os.WriteFile(filepath.Join(root, paths[i]), []byte("ID3plain"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Media().SetHidden(ctx, []string{directory}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Media()
	counter := &adminTreeEncryptionCounter{MediaRepository: repo, EncryptionRepository: repo.(store.EncryptionRepository), EncryptionBatchRepository: repo.(store.EncryptionBatchRepository)}
	svc.repository = counter
	plan := func(selected []string, limit int) ([]DownloadEntry, error) {
		t.Helper()
		counter.reset()
		d, err := svc.Download(ctx, selected)
		if err != nil {
			return nil, err
		}
		defer d.Close()
		return d.BrowserPlan(limit)
	}
	entries, err := plan([]string{directory, paths[0]}, 5000)
	if err != nil || len(entries) != 0 {
		t.Fatal("large all-plaintext Admin selection did not use the legacy archive", len(entries), err)
	}
	checkBatches := func(expected int) {
		t.Helper()
		seen := map[string]bool{}
		for _, batch := range counter.batches {
			if len(batch) > 500 {
				t.Fatal("metadata batch was unbounded", len(batch))
			}
			for _, id := range batch {
				if seen[id] {
					t.Fatal("directory/file overlap was not deduplicated", id)
				}
				seen[id] = true
			}
		}
		if len(seen) != expected || counter.single != 0 {
			t.Fatal("selection was sampled or used per-file descriptor reads", len(seen), expected, counter.single)
		}
	}
	checkBatches(5001)
	meta, payload := encryptedFixtureBytes(t, "ID3encrypted-last")
	last := paths[5000]
	if err := os.WriteFile(filepath.Join(root, last), payload, 0644); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteUpload(ctx, store.MediaObject{Path: last, Kind: "audio", Encryption: &meta}, strings.Repeat("1", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	// Explicit files preserve ordering: the descriptor beyond the first 5000
	// must prevent the plaintext fallback, even though those 5000 are all plain.
	entries, err = plan(paths, 5000)
	if !errors.Is(err, ErrUploadSize) || entries != nil {
		t.Fatal("encrypted 5001st file was treated as plaintext", len(entries), err)
	}
	checkBatches(5001)
	ids, err := repo.EnsureObjects(ctx, []store.MediaObject{{Path: last, Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[last]); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(paths, 5000); !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("corrupt 5001st descriptor became a plaintext fallback or size-only error", err)
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json=? WHERE object_kind='media' AND object_id=?", string(encoded), ids[last]); err != nil {
		t.Fatal(err)
	}
	entries, err = plan(paths[1:], 5000)
	if err != nil || len(entries) != 5000 || entries[4999].Encryption == nil || *entries[4999].Encryption != meta || entries[4999].Snapshot == "" {
		t.Fatal("maximum mixed plan lost its identity or descriptor", len(entries), err)
	}
	checkBatches(5000)
	// Finding an encrypted file does not permit skipping later corrupt metadata.
	otherMeta, _ := encryptedFixtureBytes(t, "ID3other")
	if err := repo.CompleteUpload(ctx, store.MediaObject{Path: paths[0], Kind: "audio", Encryption: &otherMeta}, strings.Repeat("2", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	ids, err = repo.EnsureObjects(ctx, []store.MediaObject{{Path: paths[0], Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json='{}' WHERE object_kind='media' AND object_id=?", ids[paths[0]]); err != nil {
		t.Fatal(err)
	}
	_, err = plan([]string{last, paths[0]}, 1)
	if !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("corrupt descriptor after ciphertext became a fallback or size-only error", err)
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET descriptor_json=NULL WHERE object_kind='media' AND object_id=?", ids[paths[0]]); err != nil {
		t.Fatal(err)
	}
	entries, err = plan([]string{paths[0]}, 1)
	if err != nil || len(entries) != 1 || entries[0].Encryption != nil {
		t.Fatal("retired descriptor was revived", entries, err)
	}
}

type missingBrowserPlanIdentity struct{ store.MediaRepository }

func (r missingBrowserPlanIdentity) EnsureObjects(context.Context, []store.MediaObject) (map[string]string, error) {
	return map[string]string{}, nil
}

func TestBrowserDownloadPlanRejectsMissingIdentityAndKeepsItsLease(t *testing.T) {
	_, _, svc := deleteFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := svc.Download(ctx, []string{"music/artist/song.mp3"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	waiting := make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		close(waiting)
		_, err := svc.Delete(ctx, []string{"music/artist/song.mp3"}, store.AdminAudit{})
		writer <- err
	}()
	<-waiting
	select {
	case err := <-writer:
		t.Fatal("writer bypassed download lease", err)
	case <-time.After(50 * time.Millisecond):
	}
	planned := make(chan error, 1)
	go func() { _, err := d.BrowserPlan(1); planned <- err }()
	select {
	case err := <-planned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		d.Close()
		t.Fatal("plan did not complete under its existing mutation lease")
	}
	d.Close()
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Download(ctx, []string{"music/artist/song.mp3"}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted source was admitted", err)
	}
	svc.repository = missingBrowserPlanIdentity{svc.repository}
	d, err = svc.Download(ctx, []string{"music/other/song.mp3"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err = d.BrowserPlan(1); !errors.Is(err, mediacrypto.ErrMetadata) {
		t.Fatal("missing identity was treated as plaintext", err)
	}
}

func TestBrowserDownloadPlanUsesLogicalGlobalIDAndRejectsMissingLocalBytes(t *testing.T) {
	root, db, svc := masterFixture(t)
	ctx := context.Background()
	name := "music/artist/song.mp3"
	rows, err := db.Pool().Resources(ctx, name, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	// The global logical ID is independent from the storage object's ID.
	meta, payload := encryptedFixtureBytes(t, "ID3payload")
	if err := os.WriteFile(filepath.Join(root, name), payload, 0644); err != nil {
		t.Fatal(err)
	}
	if err := db.Media().CompleteUpload(ctx, store.MediaObject{Path: name, Kind: "audio", Encryption: &meta}, strings.Repeat("3", 32), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	logicalID := strings.Repeat("f", 64)
	if _, err := db.Database().Exec("UPDATE global_media_objects SET media_id=?,size_bytes=? WHERE media_id=?", logicalID, len(payload), rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE media_encryption SET object_id=? WHERE object_kind='media' AND object_id=?", logicalID, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	d, err := svc.Download(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Media()
	counter := &adminTreeEncryptionCounter{MediaRepository: repo, EncryptionRepository: repo.(store.EncryptionRepository), EncryptionBatchRepository: repo.(store.EncryptionBatchRepository)}
	svc.repository = counter
	for _, invalid := range []string{"", "not-a-logical-id"} {
		d.globals[0].ID = invalid
		if _, err := d.BrowserPlan(1); !errors.Is(err, mediacrypto.ErrMetadata) || counter.ensure != 0 || len(counter.batches) != 0 {
			t.Fatal("invalid global identity was converted into a local/plain object", invalid, err)
		}
	}
	d.globals[0].ID = logicalID
	entries, err := d.BrowserPlan(1)
	d.Close()
	if err != nil || len(entries) != 1 || entries[0].MediaID != logicalID || entries[0].Encryption == nil || *entries[0].Encryption != meta || counter.ensure != 0 || counter.single != 0 {
		t.Fatal("descriptor was indexed by owner object ID", entries, err)
	}
	if err := os.Remove(filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	d, err = svc.Download(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.BrowserPlan(1); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing global local bytes became a plaintext fallback", err)
	}
	d.Close()
	if _, err := db.Database().Exec("DELETE FROM global_media_objects WHERE media_id=?", logicalID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Download(ctx, []string{name}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted global object was admitted", err)
	}
}
