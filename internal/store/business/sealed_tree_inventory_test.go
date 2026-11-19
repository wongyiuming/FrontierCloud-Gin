package business_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSealedTreeInventoryReadsMasterFactsWithoutExposingOrMutatingNames(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	master := strings.Repeat("a", 32)
	name := "music/私密专辑/私密曲目.mp3"
	sum := sha256.Sum256([]byte(name))
	derived := hex.EncodeToString(sum[:])
	lyricName := "lyrics/私密/歌词.lrc"
	lyricSum := sha256.Sum256([]byte(lyricName))
	lyricID := hex.EncodeToString(lyricSum[:])
	metadata, err := mediacrypto.NewMetadata(12)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','sealed',123)`, []any{master}},
		{`INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,1000,40,5,800,'online',1,123)`, []any{master}},
		{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?,'2026-01-01','2026-01-01')`, []any{derived, name, derived}},
		{`INSERT INTO media_visibility(relative_path,hidden,updated_at) VALUES(?,1,'2026-01-01')`, []any{"music/私密专辑"}},
		{`INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,?,?,?,'2026-01-01','2026-01-01')`, []any{derived, name, lyricID, lyricName}},
		{`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media',?,?,?,1)`, []any{derived, metadata.FileID, string(descriptor)}},
		{`INSERT INTO node_audit(audit_id,action,relationship_id,actor,detail,created_at) VALUES(?,'fixture',NULL,'fixture',?,1)`, []any{strings.Repeat("b", 32), `{"path":"music/私密专辑/私密曲目.mp3"}`}},
	} {
		if _, err = raw.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	repo, ok := db.Media().(store.SealedTreeInventoryRepository)
	if !ok {
		t.Fatal("business repository does not expose inventory")
	}
	got, err := repo.SealedTreeInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DatabaseSnapshotOnly || got.RuntimeReady || got.LocalTreePreflightFailed || got.LocalTreePreflightNodes != 3 || got.LocalObjectRows != 1 || got.VisibilityRows != 1 || got.LyricLinkRows != 1 || got.LyricMissingTargetRows != 1 || got.LyricInvalidTrackRows != 0 || got.PathDerivedLyricIDValues != 1 || got.PathDerivedMediaIDValues != 1 || got.UnkeyedPathLocatorValues != 1 || got.EncryptedDescriptorRows != 1 || got.InvalidDescriptorRows != 0 || got.StorageMemberRows != 1 || got.InvalidQuotaValues != 0 || got.UnsettledIndicators == 0 || got.NodeAuditRows != 1 {
		t.Fatalf("unexpected aggregate inventory: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{name, "私密专辑", lyricName, lyricID, derived, master, metadata.FileID} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("inventory disclosed a name, ID or hash")
		}
	}
	var still string
	if err = raw.QueryRow(`SELECT media_path FROM media_objects WHERE media_id=?`, derived).Scan(&still); err != nil || still != name {
		t.Fatal("source metadata changed", err)
	}
	var count int
	if err = raw.QueryRow(`SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&count); err != nil || count != 0 {
		t.Fatal("inventory initialized tree", err)
	}
}

func TestSealedTreeInventoryRejectsFollowerAndReportsMalformedValues(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	var err error
	if _, err = raw.Exec(`INSERT INTO node_identity VALUES(1,?,'Follower','https://node.test','sealed',123)`, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	repo := db.Media().(store.SealedTreeInventoryRepository)
	if _, err = repo.SealedTreeInventory(ctx); err == nil {
		t.Fatal("follower inventory admitted")
	}
	if _, err = raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('old-id','audio','music//bad.mp3','not-a-hash','2026-01-01','2026-01-01')`); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media','old-id',?,'{}',1)`, strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media','retired',?,NULL,1)`, strings.Repeat("e", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,?,?,'audio',1,'fixture','active',1,1)`, strings.Repeat("b", 64), strings.Repeat("c", 32), strings.Repeat("d", 64), "music/album/song.mp3", strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	got, err := repo.SealedTreeInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LocalTreePreflightFailed || got.LocalTreePreflightNodes != 0 || got.NonCanonicalPathValues != 1 || got.UnsupportedMediaIDValues != 1 || got.OtherPathLocatorValues != 2 || got.InvalidDescriptorRows != 1 || got.EncryptionTombstoneRows != 1 || got.GlobalMissingOwnerRows != 1 || got.RuntimeReady {
		t.Fatalf("malformed facts not counted: %+v", got)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if value, err := repo.SealedTreeInventory(cancelled); err == nil || value.DatabaseSnapshotOnly {
		t.Fatal("cancelled inventory returned a usable partial report")
	}
}

func TestSealedTreeInventoryFlagsLocalFileParentCollision(t *testing.T) {
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := raw.Exec(`INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','sealed',123)`, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, path, locator string }{
		{strings.Repeat("b", 64), "sensitive", strings.Repeat("c", 64)},
		{strings.Repeat("d", 64), "sensitive/child.mp3", strings.Repeat("e", 64)},
	} {
		if _, err := raw.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?,'2026-01-01','2026-01-01')`, row.id, row.path, row.locator); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.Media().(store.SealedTreeInventoryRepository).SealedTreeInventory(context.Background())
	if err != nil || !got.LocalTreePreflightFailed || got.LocalTreePreflightNodes != 0 || got.LocalObjectRows != 2 || got.RuntimeReady {
		t.Fatalf("local conflict was not safely reported: %+v %v", got, err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), "sensitive") {
		t.Fatal("inventory disclosed a path", err)
	}
}
