package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func backupS3Proof(raw string) (store.S3ObjectProof, error) {
	var proof store.S3ObjectProof
	if len(raw) == 0 || len(raw) > 16384 {
		return proof, store.ErrBackupState
	}
	if _, err := strictJSON([]byte(raw)); err != nil {
		return proof, store.ErrBackupState
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil {
		return proof, store.ErrBackupState
	}
	if _, err := decoder.Token(); err != io.EOF {
		return proof, store.ErrBackupState
	}
	if !hexID(proof.SessionID, 32) || !hexID(proof.ObjectID, 64) || !hexID(proof.MemberID, 32) || !hexID(proof.MediaID, 64) || proof.Bytes < 1 || proof.Bytes > store.S3MaxObjectBytes || len(proof.Key) < 1 || len(proof.Key) > 768 || len(proof.ETag) < 1 || len(proof.ETag) > 128 || len(proof.VersionID) > 1024 || strings.ContainsAny(proof.ETag+proof.VersionID, "\r\n\x00") {
		return proof, store.ErrBackupState
	}
	index := strings.LastIndexByte(proof.CompositeSHA256, '-')
	if index < 1 {
		return proof, store.ErrBackupState
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(proof.CompositeSHA256[:index])
	parts, numberErr := strconv.ParseInt(proof.CompositeSHA256[index+1:], 10, 32)
	if err != nil || len(digest) != 32 || numberErr != nil || parts != (proof.Bytes+store.S3PartBytes-1)/store.S3PartBytes || strconv.FormatInt(parts, 10) != proof.CompositeSHA256[index+1:] {
		return proof, store.ErrBackupState
	}
	return proof, nil
}

func backupS3Configuration(row map[string]any) (s3store.Config, error) {
	text := func(key string) string { value, _ := row[key].(string); return value }
	value := s3store.Config{Endpoint: text("endpoint"), Bucket: text("bucket"), Region: text("region"), Prefix: text("prefix"), AddressStyle: text("address_style")}
	normalized, err := s3store.Normalize(value)
	if err != nil || normalized != value {
		return s3store.Config{}, store.ErrBackupState
	}
	namespace, err := normalized.Namespace()
	if err != nil || text("namespace_key") != namespace.Origin+"\n"+namespace.Bucket {
		return s3store.Config{}, store.ErrBackupState
	}
	return normalized, nil
}

func checkS3BackupRow(table string, row map[string]any) error {
	text := func(key string) string { value, _ := row[key].(string); return value }
	num := func(key string) int64 { value, _ := row[key].(int64); return value }
	if num("revision") <= 0 || num("created_at") <= 0 || num("updated_at") < num("created_at") {
		return store.ErrBackupState
	}
	if len(text("error_code")) > 64 || strings.ContainsAny(text("error_code"), "\r\n\x00:/") {
		return store.ErrBackupState
	}
	switch table {
	case "s3_members":
		if _, err := backupS3Configuration(row); err != nil {
			return err
		}
		if utf8.RuneCountInString(text("name")) < 1 || utf8.RuneCountInString(text("name")) > 128 || text("sealed_credentials") != "" || num("credential_expires_at") != 0 || num("credential_revision") <= 0 || num("probe_revision") != 0 || text("probe_state") != "unchecked" || num("cleanup_only") != 0 {
			return store.ErrBackupState
		}
	case "s3_objects":
		proof, err := backupS3Proof(text("proof_json"))
		if err != nil || text("state") != "active" || proof.Key != text("object_key") || proof.ObjectID != text("object_id") || proof.MemberID != text("member_id") || proof.MediaID != text("media_id") || num("grant_until") < 0 || num("grant_until") > time.Now().Unix() {
			return store.ErrBackupState
		}
	default:
		return store.ErrBackupState
	}
	return nil
}

func checkS3BackupReferences(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		"SELECT EXISTS(SELECT 1 FROM s3_members m LEFT JOIN cluster_storage_members s ON s.member_id=m.member_id WHERE s.member_id IS NULL OR s.member_kind<>'S3' OR s.transport<>'S3' OR s.relationship_id IS NOT NULL)",
		"SELECT EXISTS(SELECT 1 FROM cluster_storage_members s LEFT JOIN s3_members m ON m.member_id=s.member_id WHERE s.member_kind='S3' AND m.member_id IS NULL)",
		"SELECT EXISTS(SELECT 1 FROM s3_objects o LEFT JOIN global_media_objects g ON g.media_id=o.media_id LEFT JOIN s3_members m ON m.member_id=o.member_id WHERE g.media_id IS NULL OR m.member_id IS NULL OR g.storage_member_id<>o.member_id OR g.object_id<>o.object_id OR g.state<>'active')",
		"SELECT EXISTS(SELECT 1 FROM global_media_objects g JOIN cluster_storage_members s ON s.member_id=g.storage_member_id LEFT JOIN s3_objects o ON o.media_id=g.media_id WHERE s.member_kind='S3' AND o.media_id IS NULL)",
		"SELECT EXISTS(SELECT 1 FROM karaoke_recordings r JOIN cluster_storage_members s ON s.member_id=r.storage_member_id WHERE s.member_kind='S3')",
		"SELECT EXISTS(SELECT 1 FROM cluster_compute_members c JOIN cluster_storage_members s ON s.member_id=c.member_id WHERE s.member_kind='S3')",
		"SELECT EXISTS(SELECT 1 FROM cluster_backup_members c JOIN cluster_storage_members s ON s.member_id=c.member_id WHERE s.member_kind='S3')",
		"SELECT EXISTS(SELECT 1 FROM s3_members a JOIN s3_members b ON a.member_id<b.member_id AND a.namespace_key=b.namespace_key WHERE a.prefix='' OR b.prefix='' OR a.prefix=b.prefix OR substr(a.prefix,1,length(b.prefix)+1)=b.prefix||'/' OR substr(b.prefix,1,length(a.prefix)+1)=a.prefix||'/')",
	} {
		var invalid bool
		if err := tx.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
			return fmt.Errorf("%w: S3 references unreadable", store.ErrBackupState)
		}
		if invalid {
			return fmt.Errorf("%w: S3 ownership or namespace", store.ErrBackupState)
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT o.object_key,o.object_id,o.proof_json,g.size_bytes,g.etag,m.endpoint,m.bucket,m.region,m.prefix,m.address_style FROM s3_objects o JOIN global_media_objects g ON g.media_id=o.media_id JOIN s3_members m ON m.member_id=o.member_id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, object, raw, etag string
		var size int64
		var location s3store.Config
		if err := rows.Scan(&key, &object, &raw, &size, &etag, &location.Endpoint, &location.Bucket, &location.Region, &location.Prefix, &location.AddressStyle); err != nil {
			return err
		}
		proof, err := backupS3Proof(raw)
		if err != nil || proof.Key != key || proof.ObjectID != object || proof.Bytes != size || proof.ETag != etag {
			return store.ErrBackupState
		}
		if _, err := location.ProviderKey(key); err != nil {
			return store.ErrBackupState
		}
	}
	return rows.Err()
}
