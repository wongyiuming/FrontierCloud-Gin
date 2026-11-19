package business

// Unregistered, bounded source-side building block. It reads only the media
// facts in one SQL snapshot, signs them on the current Master and never reads
// or exports the media premaster. It is not an import or deployment endpoint.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var errSourceSnapshot = errors.New("media source snapshot unavailable")

type sourceSnapshotQuery struct {
	name, query string
	columns     []string
}

var sourceSnapshotQueries = []sourceSnapshotQuery{
	{"objects", "SELECT media_id,object_kind,media_path,path_locator,created_at,updated_at FROM media_objects ORDER BY media_id", []string{"media_id", "object_kind", "media_path", "path_locator", "created_at", "updated_at"}},
	{"placements", "SELECT media_id,storage_member_id,object_id,media_path,object_kind,size_bytes,etag,state,created_at,updated_at FROM global_media_objects ORDER BY media_id", []string{"media_id", "storage_member_id", "object_id", "media_path", "object_kind", "size_bytes", "etag", "state", "created_at", "updated_at"}},
	{"visibility", "SELECT relative_path,hidden,updated_at FROM media_visibility ORDER BY relative_path", []string{"relative_path", "hidden", "updated_at"}},
	{"playback", "SELECT media_id,media_path,preference,play_score,created_at,updated_at FROM media_playback_stats ORDER BY media_id", []string{"media_id", "media_path", "preference", "play_score", "created_at", "updated_at"}},
	{"lyric_links", "SELECT media_id,media_path,lyric_id,lyric_path,created_at,updated_at FROM media_lyric_links ORDER BY media_id", []string{"media_id", "media_path", "lyric_id", "lyric_path", "created_at", "updated_at"}},
	{"encryption", "SELECT object_kind,object_id,file_id,descriptor_json,created_at FROM media_encryption WHERE object_kind='media' ORDER BY object_kind,object_id", []string{"object_kind", "object_id", "file_id", "descriptor_json", "created_at"}},
	{"members", "SELECT member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at FROM cluster_storage_members ORDER BY member_id", []string{"member_id", "relationship_id", "member_kind", "transport", "storage_enabled", "allocated_bytes", "used_bytes", "reserved_bytes", "physical_free_bytes", "health", "writable", "updated_at"}},
	{"relationships", "SELECT relationship_id,peer_id,peer_endpoint,peer_key,direction,mode,state,created_at FROM node_relationships ORDER BY relationship_id", []string{"relationship_id", "peer_id", "peer_endpoint", "peer_key", "direction", "mode", "state", "created_at"}},
	{"crypto_key_id", "SELECT singleton,key_id,created_at FROM media_crypto_keys ORDER BY singleton", []string{"singleton", "key_id", "created_at"}},
}

// ExportMediaSourceSnapshot requires a bounded context. The caller must be an
// independently authorized source-side operator; this method has no route and
// does not itself prove ownership of targetNode or targetReceiver.
func (r *Repository) ExportMediaSourceSnapshot(ctx context.Context, v *vault.Vault, targetNode string, targetReceiver []byte, challenge string) (store.EncryptedMediaSourceSnapshot, error) {
	return r.exportMediaSourceSnapshot(ctx, v, targetNode, targetReceiver, challenge, nil)
}

func (r *Repository) exportMediaSourceSnapshot(ctx context.Context, v *vault.Vault, targetNode string, targetReceiver []byte, challenge string, afterSnapshot func() error) (store.EncryptedMediaSourceSnapshot, error) {
	var empty store.EncryptedMediaSourceSnapshot
	if ctx == nil {
		return empty, errSourceSnapshot
	}
	deadline, ok := ctx.Deadline()
	if v == nil || !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second || !nodeIDPattern.MatchString(targetNode) || len(targetReceiver) != 32 || !nodeHashPattern.MatchString(challenge) {
		return empty, errSourceSnapshot
	}
	var nonzero byte
	for _, b := range targetReceiver {
		nonzero |= b
	}
	if nonzero == 0 {
		return empty, errSourceSnapshot
	}
	// This fence is pre-existing and independently initialized. Acquisition
	// only reads its persisted marker; it must never initialize production.
	identityLease, err := r.AcquireOwnerControlShared(ctx)
	if err != nil || identityLease == nil {
		return empty, errSourceSnapshot
	}
	defer identityLease.Release()
	if identityLease.Check(ctx) != nil {
		return empty, errSourceSnapshot
	}
	isolation := sql.LevelSerializable
	if r.backend == "mysql" {
		isolation = sql.LevelRepeatableRead
	} else if r.backend != "sqlite" {
		return empty, errSourceSnapshot
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: isolation, ReadOnly: true})
	if err != nil {
		return empty, errSourceSnapshot
	}
	defer tx.Rollback()
	identity, err := readNode(ctx, tx, "")
	if err != nil || identity.Role != "Master" || !nodeIDPattern.MatchString(identity.ID) || identity.ID == targetNode {
		return empty, errSourceSnapshot
	}
	private, err := v.Unseal(identity.PrivateKey)
	if err != nil {
		return empty, errSourceSnapshot
	}
	public, err := protocol.PublicKey(private)
	if err != nil {
		return empty, errSourceSnapshot
	}
	now := time.Now().UTC()
	s := store.MediaSourceSnapshot{Version: 1, AuthorityKind: "source-node-v1", SourceNode: identity.ID, SourcePublic: public, TargetNode: targetNode, TargetReceiver: append([]byte(nil), targetReceiver...), Challenge: challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
	remaining := 25000
	byteCount := 0
	for _, spec := range sourceSnapshotQueries {
		// SQL bounds every cell before the driver allocates it. Oversized
		// values fail closed below rather than being silently truncated.
		from := strings.Index(spec.query, " FROM ")
		if from < 0 { return empty, errSourceSnapshot }
		bounded := make([]string, len(spec.columns))
		for i, column := range spec.columns {
			bounded[i] = "SUBSTR(" + column + ",1,65537)"
		}
		rows, e := tx.QueryContext(ctx, "SELECT "+strings.Join(bounded, ",")+spec.query[from:]+" LIMIT ?", remaining+1)
		if e != nil {
			return empty, errSourceSnapshot
		}
		section := store.MediaSourceSection{Name: spec.name, Columns: append([]string(nil), spec.columns...), Rows: make([][]*string, 0)}
		for rows.Next() {
			if remaining == 0 {
				rows.Close()
				return empty, errSourceSnapshot
			}
			remaining--
			values := make([]sql.NullString, len(spec.columns))
			args := make([]any, len(values))
			for i := range values {
				args[i] = &values[i]
			}
			if rows.Scan(args...) != nil {
				rows.Close()
				return empty, errSourceSnapshot
			}
			cells := make([]*string, len(values))
			for i, value := range values {
				if value.Valid {
					if len(value.String) > 65536 || !utf8.ValidString(value.String) {
						rows.Close()
						return empty, errSourceSnapshot
					}
					byteCount += len(value.String)
					if byteCount > 16*1024*1024 {
						rows.Close()
						return empty, errSourceSnapshot
					}
					cell := value.String
					cells[i] = &cell
				}
			}
			section.Rows = append(section.Rows, cells)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return empty, errSourceSnapshot
		}
		s.Sections = append(s.Sections, section)
	}
	if tx.Commit() != nil || ctx.Err() != nil || identityLease.Check(ctx) != nil {
		return empty, errSourceSnapshot
	}
	if afterSnapshot != nil {
		if afterSnapshot() != nil || identityLease.Check(ctx) != nil {
			return empty, errSourceSnapshot
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024 {
		return empty, errSourceSnapshot
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	payload := map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(digest[:]), "source_node": s.SourceNode, "target_node": s.TargetNode, "challenge": s.Challenge}
	signature, err := protocol.Sign(private, payload)
	if err != nil || ctx.Err() != nil || identityLease.Check(ctx) != nil || time.Now().Unix() >= s.ExpiresUnix {
		return empty, errSourceSnapshot
	}
	envelope, err := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: s, Signature: signature}, targetReceiver)
	if err != nil || ctx.Err() != nil || identityLease.Check(ctx) != nil || time.Now().Unix() >= s.ExpiresUnix {
		return empty, errSourceSnapshot
	}
	return envelope, nil
}
