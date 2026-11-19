//go:build linux

package business_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestMediaSourceSnapshotSignsCompleteReadOnlyFacts(t *testing.T) {
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil { t.Fatal(err) }
	seed := protocol.Encode(bytes.Repeat([]byte{8}, 32))
	sealed, err := v.Seal(seed)
	if err != nil { t.Fatal(err) }
	source := strings.Repeat("a", 32)
	target := strings.Repeat("b", 32)
	id := strings.Repeat("1", 64)
	lyric := strings.Repeat("2", 64)
	queries := []struct{ query string; args []any }{
		{`INSERT INTO node_identity VALUES(1,?,'Master','https://source.test',?,123)`, []any{source, sealed}},
		{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'lyric','lyrics/专辑/歌词.lrc',?,'2026-01-01','2026-01-01')`, []any{lyric, lyric}},
		{`INSERT INTO global_media_objects(media_id,storage_member_id,object_id,media_path,path_locator,object_kind,size_bytes,etag,state,created_at,updated_at) VALUES(?,?,?,'music/专辑/歌曲.mp3',?,'audio',9,'etag','active',1,2)`, []any{id, source, id, id}},
		{`INSERT INTO media_visibility(relative_path,hidden,updated_at) VALUES('music/专辑',1,'2026-01-01')`, nil},
		{`INSERT INTO media_playback_stats(media_id,media_path,preference,play_score,created_at,updated_at) VALUES(?,'music/专辑/歌曲.mp3',1,7,'2026-01-01','2026-01-01')`, []any{id}},
		{`INSERT INTO media_lyric_links(media_id,media_path,lyric_id,lyric_path,created_at,updated_at) VALUES(?,'music/专辑/歌曲.mp3',?,'lyrics/专辑/歌词.lrc','2026-01-01','2026-01-01')`, []any{id, lyric}},
		{`INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES('media',?,?,?,1)`, []any{id, strings.Repeat("3", 32), `{"file_id":"synthetic"}`}},
		{`INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,1000,40,5,800,'online',1,123)`, []any{source}},
		{`INSERT INTO node_relationships(relationship_id,peer_id,peer_endpoint,peer_key,credential,direction,mode,state,status,last_heartbeat,rtt_ms,failures,recoveries,peer_version,protocol,summary,created_at) VALUES(?,?, 'https://peer.test','synthetic-key','synthetic-secret','downstream','Direct','active','online',1,0,0,0,'x',2,'{}',1)`, []any{strings.Repeat("c",32), strings.Repeat("d",32)}},
		{`INSERT INTO media_crypto_keys(singleton,key_id,created_at) VALUES(1,?,1)`, []any{strings.Repeat("4", 64)}},
	}
	for _, q := range queries {
		if _, err = raw.Exec(q.query, q.args...); err != nil { t.Fatal(err) }
	}
	repo := db.Media().(interface { ExportMediaSourceSnapshot(context.Context, *vault.Vault, string, []byte, string) (store.EncryptedMediaSourceSnapshot, error) })
	receiver, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil { t.Fatal(err) }
	if _, err = repo.ExportMediaSourceSnapshot(context.Background(), v, target, receiver.PublicKey().Bytes(), strings.Repeat("5", 64)); err == nil { t.Fatal("unbounded read accepted") }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = repo.ExportMediaSourceSnapshot(ctx, v, target, receiver.PublicKey().Bytes(), strings.Repeat("5", 64)); err == nil { t.Fatal("unconfigured source identity fence accepted") }
	dir := t.TempDir()
	if err = os.Chmod(dir, 0o700); err != nil { t.Fatal(err) }
	if err = os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0o700); err != nil { t.Fatal(err) }
	root, err := os.OpenRoot(dir)
	if err != nil { t.Fatal(err) }
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, ownerFixtureCodec{})
	if err != nil { t.Fatal(err) }
	config := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
	})
	if err = config.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) { return fence.Acquire(ctx, exclusive) }); err != nil { t.Fatal(err) }
	if err = config.InitializeOwnerControlMarker(ctx); err != nil { t.Fatal(err) }
	envelope, err := repo.ExportMediaSourceSnapshot(ctx, v, target, receiver.PublicKey().Bytes(), strings.Repeat("5", 64))
	if err != nil { t.Fatal(err) }
	encodedEnvelope, err := json.Marshal(envelope)
	if err != nil || bytes.Contains(encodedEnvelope, []byte("专辑")) { t.Fatal("plaintext path leaked in envelope", err) }
	signed, err := snapshotcrypt.Open(envelope, receiver)
	if err != nil { t.Fatal(err) }
	if signed.Snapshot.SourceNode != source || len(signed.Snapshot.Sections) != 9 { t.Fatal("incomplete source facts") }
	for _, section := range signed.Snapshot.Sections {
		if len(section.Rows) != 1 { t.Fatalf("missing source section %s", section.Name) }
	}
	contents, err := json.Marshal(signed.Snapshot)
	if err != nil { t.Fatal(err) }
	if bytes.Contains(contents, []byte("synthetic-secret")) { t.Fatal("relationship credential exported") }
	digest := sha256.Sum256(contents)
	payload := map[string]any{"kind":"frontiercloud-preprod-media-source-v1", "sha256":hex.EncodeToString(digest[:]), "source_node":source, "target_node":target, "challenge":strings.Repeat("5", 64)}
	public, err := protocol.PublicKey(seed)
	if err != nil || signed.Snapshot.SourcePublic != public || protocol.Verify(public, payload, signed.Signature) != nil { t.Fatal("source signature invalid", err) }
	contents[0] ^= 1
	tampered := sha256.Sum256(contents)
	payload["sha256"] = hex.EncodeToString(tampered[:])
	if protocol.Verify(public, payload, signed.Signature) == nil { t.Fatal("modified snapshot accepted") }
	var after int
	if err = raw.QueryRow(`SELECT COUNT(*) FROM media_visibility WHERE hidden=1`).Scan(&after); err != nil || after != 1 { t.Fatal("source changed", err) }
}
