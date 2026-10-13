package recovery_test

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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func fixture(t *testing.T) (string, string, recovery.Manifest, []recovery.Root) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	secrets := filepath.Join(root, "secrets")
	for _, dir := range []string{data, secrets, filepath.Join(data, "media", "music", "album"), filepath.Join(data, "empty")} {
		if e := os.MkdirAll(dir, 0750); e != nil {
			t.Fatal(e)
		}
	}
	m := recovery.Manifest{NodeID: strings.Repeat("a", 32), Role: "Standalone", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key"}}
	if e := os.WriteFile(filepath.Join(secrets, "node-vault.key"), []byte("isolated-fixture-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(data, "media", "music", "album", "track.mp3"), []byte("ID3-real-backup-bytes"), 0640); e != nil {
		t.Fatal(e)
	}
	return root, filepath.Join(root, "backup.tar"), m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: secrets}}
}

func TestArchivePublicationNeverReplacesExistingOutputAndIgnoresInterruptedTemporary(t *testing.T) {
	_, archive, m, sources := fixture(t)
	ctx := context.Background()
	interrupted := archive + ".next-interrupted"
	if e := os.WriteFile(interrupted, []byte("partial unpublished tar"), 0600); e != nil {
		t.Fatal(e)
	}
	report, e := recovery.Create(ctx, archive, m, sources)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := recovery.Check(ctx, archive, report.SHA256); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(archive)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := recovery.Create(ctx, archive, m, sources); e == nil {
		t.Fatal("existing archive overwritten")
	}
	current, e := os.ReadFile(archive)
	if e != nil || string(current) != string(original) {
		t.Fatal("prior verified archive changed", e)
	}
	siblings, e := filepath.Glob(archive + ".next-*")
	if e != nil || len(siblings) != 1 || siblings[0] != interrupted {
		t.Fatal("temporary leak", siblings, e)
	}
}
func TestArchiveRoundTripVerifiesRealBytesAndRefusesOccupiedTarget(t *testing.T) {
	root, archive, m, sources := fixture(t)
	ctx := context.Background()
	created, e := recovery.Create(ctx, archive, m, sources)
	if e != nil {
		t.Fatal(e)
	}
	checked, e := recovery.Check(ctx, archive, created.SHA256)
	if e != nil || !checked.Verified || checked.RestoreReady || checked.BusinessVerified {
		t.Fatal(checked, e)
	}
	target := filepath.Join(root, "restored")
	if _, e = recovery.Apply(ctx, archive, target, created.SHA256, m.NodeID); e != nil {
		t.Fatal(e)
	}
	actual, e := os.ReadFile(filepath.Join(target, "data", "media", "music", "album", "track.mp3"))
	if e != nil || string(actual) != "ID3-real-backup-bytes" {
		t.Fatal(string(actual), e)
	}
	info, e := os.Stat(filepath.Join(target, "data", "empty"))
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0750 {
		t.Fatal("empty directory or mode lost", info, e)
	}
	if _, e = recovery.Apply(ctx, archive, target, created.SHA256, m.NodeID); e == nil {
		t.Fatal("existing target overwritten")
	}
	info, e = os.Stat(archive)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("archive is not private", info, e)
	}
}
func TestArchiveRejectsLinksMissingKeysCorruptionAndWrongIdentity(t *testing.T) {
	for _, kind := range []string{"link", "missing-key", "corruption", "wrong-node", "wrong-hash", "mysql-no-dump", "output-in-data"} {
		t.Run(kind, func(t *testing.T) {
			root, archive, m, sources := fixture(t)
			switch kind {
			case "link":
				if e := os.Symlink("../../secrets/node-vault.key", filepath.Join(sources[0].Directory, "unsafe")); e != nil {
					t.Skip("links unavailable")
				}
			case "missing-key":
				m.KeyReferences = []string{"runtime_secrets/absent"}
			case "mysql-no-dump":
				m.Database = "mysql"
			case "output-in-data":
				archive = filepath.Join(sources[0].Directory, "backup.tar")
			}
			r, e := recovery.Create(context.Background(), archive, m, sources)
			if kind == "link" || kind == "missing-key" || kind == "mysql-no-dump" || kind == "output-in-data" {
				if e == nil {
					t.Fatal("unsafe backup accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if kind == "corruption" {
				f, e := os.OpenFile(archive, os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteAt([]byte("CORRUPTION"), 3000)
				f.Close()
				if e != nil {
					t.Fatal(e)
				}
				if _, e = recovery.Check(context.Background(), archive, r.SHA256); e == nil {
					t.Fatal("corruption accepted")
				}
				return
			}
			confirmation := m.NodeID
			expected := r.SHA256
			if kind == "wrong-node" {
				confirmation = strings.Repeat("c", 32)
			} else {
				expected = strings.Repeat("d", 64)
			}
			if _, e = recovery.Apply(context.Background(), archive, filepath.Join(root, "target"), expected, confirmation); e == nil {
				t.Fatal("unconfirmed restore accepted")
			}
		})
	}
}
func TestActualSQLiteBackupRestorePreservesIdentityAndBusinessReads(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "source-data")
	secrets := filepath.Join(root, "source-secrets")
	mediaRoot := filepath.Join(data, "media")
	if e := os.MkdirAll(filepath.Join(mediaRoot, "music", "album"), 0750); e != nil {
		t.Fatal(e)
	}
	db, e := sqlite.Open(filepath.Join(data, "frontiercloud.db"))
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	identity, e := node.Initialize(ctx, db.Nodes(), secrets)
	if e != nil {
		t.Fatal(e)
	}
	name := "music/album/track.mp3"
	payload := []byte("ID3-isolated-restored-business-read")
	if e = os.WriteFile(filepath.Join(mediaRoot, filepath.FromSlash(name)), payload, 0640); e != nil {
		t.Fatal(e)
	}
	ids, e := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if e != nil {
		t.Fatal(e)
	}
	id := ids[name]
	if _, e = db.Media().SetPreference(ctx, store.MediaObject{ID: id, Path: name, Kind: "audio"}, 42, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	m := recovery.Manifest{NodeID: identity.ID, Role: "Standalone", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", KeyReferences: []string{"runtime_secrets/node-vault.key"}}
	archive := filepath.Join(root, "recovery.tar")
	created, e := recovery.Create(ctx, archive, m, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: secrets}})
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "restore")
	if _, e = recovery.Apply(ctx, archive, target, created.SHA256, identity.ID); e != nil {
		t.Fatal(e)
	}
	restored, e := sqlite.OpenReadOnly(ctx, filepath.Join(target, "data", "frontiercloud.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	got, e := node.OpenExisting(ctx, restored.Nodes(), filepath.Join(target, "runtime_secrets"))
	if e != nil || got.ID != identity.ID {
		t.Fatal("identity changed", e)
	}
	object, e := restored.Media().ObjectByID(ctx, id)
	if e != nil || object == nil || object.Path != name {
		t.Fatal(object, e)
	}
	stats, e := restored.Media().Stats(ctx, []string{id})
	if e != nil || stats[id].Preference != 42 {
		t.Fatal(stats, e)
	}
	service, e := media.New(filepath.Join(target, "data", "media"), restored.Media(), got)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	// The restored business resolver reads the original stable media identity.
	stream, e := service.OwnedStream(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	defer stream.File.Close()
	sum := sha256.Sum256(payload)
	actual, e := io.ReadAll(stream.File)
	if e != nil {
		t.Fatal(e)
	}
	restoredSum := sha256.Sum256(actual)
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(restoredSum[:]) {
		t.Fatal("restored business bytes changed")
	}
}
func TestCancelledCaptureDoesNotPublishPartialArchive(t *testing.T) {
	_, archive, m, sources := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := recovery.Create(ctx, archive, m, sources); e == nil {
		t.Fatal("cancelled capture accepted")
	}
	if _, e := os.Stat(archive); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("partial archive published", e)
	}
}
