package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type markerReader struct {
	once func() error
}

func TestRecordingRetainedMigrationReceiverRejectsTreeMarker(t *testing.T) {
	s, db, user, node := storageFixture(t)
	ctx := context.Background()
	if _, err := db.Database().ExecContext(ctx, "UPDATE node_identity SET `role`='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	receiver, err := s.MigrationReceiver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 32)
	payload := []byte("abc")
	sum := sha256.Sum256(payload)
	spec := migrationdata.Spec{TaskID: strings.Repeat("d", 32), MasterID: strings.Repeat("e", 32), SourceID: strings.Repeat("f", 32), TargetID: node, LogicalID: id, ObjectID: id, Resource: "recording", TargetPath: strings.Repeat("1", 32) + "/" + user.ID + "/" + id + ".bin", SourceVersion: strings.Repeat("2", 64), Bytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	if _, err = receiver.Begin(ctx, spec); err != nil {
		t.Fatal("begin", err)
	}
	if _, err = receiver.Append(ctx, spec, 0, payload, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal("append", err)
	}
	entries, err := os.ReadDir(s.root.Name())
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".migration-data-") {
			b, e := os.ReadFile(filepath.Join(s.root.Name(), entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			before[entry.Name()] = string(b)
		}
	}
	if len(before) < 2 {
		t.Fatal("missing stage or journal", before)
	}
	_, err = db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = receiver.Abort(ctx, spec, func() error { t.Error("admission called"); return nil }); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("retained receiver", err)
	}
	if _, err = s.MigrationReceiver(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("new receiver", err)
	}
	for name, content := range before {
		got, e := os.ReadFile(filepath.Join(s.root.Name(), name))
		if e != nil || string(got) != content {
			t.Fatal("migration state changed", name, e)
		}
	}
}

func (r *markerReader) Read(p []byte) (int, error) {
	if r.once == nil {
		return 0, io.EOF
	}
	err := r.once()
	r.once = nil
	if err != nil {
		return 0, err
	}
	p[0] = 'x'
	return 1, nil
}

func TestLegacyRecordingPhysicalGatePreservesUnknownState(t *testing.T) {
	s, db, user, relationship := storageFixture(t)
	ctx := context.Background()
	id := strings.Repeat("c", 32)
	v := reserve(t, s, db, user.ID, id, 1)
	files := map[string]string{".recording-" + id + ".part": "unknown stage", ".recording-" + id + ".json": "unknown journal"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(s.root.Name(), name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewContext(ctx, s.root, db.Recordings(), db.Nodes()); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("reopen", err)
	}
	if err = s.Recover(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("recovery", err)
	}
	if _, err = s.Lock(id); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("lease", err)
	}
	if _, err = s.Upload(ctx, relationship, v, strings.NewReader("x"), store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("upload", err)
	}
	if err = s.Delete(ctx, relationship, user.ID, id, store.KaraokeAudit{}, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("delete", err)
	}
	for name, content := range files {
		got, readErr := os.ReadFile(filepath.Join(s.root.Name(), name))
		if readErr != nil || string(got) != content {
			t.Fatal("unknown state changed", name, readErr)
		}
	}
}

func TestLegacyRecordingPreservesStageWhenTreeAppearsDuringUpload(t *testing.T) {
	s, db, user, relationship := storageFixture(t)
	ctx := context.Background()
	id := strings.Repeat("d", 32)
	v := reserve(t, s, db, user.ID, id, 1)
	reader := &markerReader{once: func() error {
		_, err := db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1})
		return err
	}}
	if _, err := s.Upload(ctx, relationship, v, reader, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("upload", err)
	}
	stage := filepath.Join(s.root.Name(), ".recording-"+id+".part")
	got, err := os.ReadFile(stage)
	if err != nil || string(got) != "x" {
		t.Fatal("stage not preserved", err)
	}
	if _, err := os.Stat(filepath.Join(s.root.Name(), ".recording-"+id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected journal", err)
	}
}
