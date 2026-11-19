package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Exercises the actual v2 business exporter and current preflight on a
// synthetic, stable S3 row. Logical restore remains independently gated.
func TestS3BusinessExportPreservesOpaqueMetadataProof(t *testing.T) {
	db, raw, member, id := s3BackupDatabase(t, true)
	physical := strings.Repeat("4", 64)
	key := "objects/44/44/" + physical + ".blob"
	proof := store.S3ObjectProof{MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: strings.Repeat("5", 64), Key: key, SessionID: strings.Repeat("3", 32), ObjectID: id, MemberID: member, MediaID: id, Bytes: 128, ETag: "opaque", VersionID: "version1", CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec("UPDATE s3_objects SET object_key=?,proof_json=? WHERE media_id=?", key, string(encoded), id); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	out := json.NewEncoder(&artifact)
	const generation int64 = 1790000000000000123
	if err = out.Encode(map[string]any{"kind": "header", "version": 2, "generation": generation}); err != nil {
		t.Fatal(err)
	}
	found := false
	err = db.Backups().ExportBusinessSnapshot(context.Background(), func(table string, row map[string]any) error {
		if table == "s3_objects" {
			var restored store.S3ObjectProof
			if e := json.Unmarshal([]byte(row["proof_json"].(string)), &restored); e != nil {
				return e
			}
			if restored != proof {
				t.Fatal("export altered complete S3 proof")
			}
			found = true
		}
		return out.Encode(map[string]any{"kind": "row", "table": table, "value": row})
	})
	if err != nil || !found {
		t.Fatal("S3 backup export", err)
	}
	if err = out.Encode(map[string]any{"kind": "end"}); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(artifact.Bytes())
	report, err := backup.Preflight(context.Background(), bytes.NewReader(artifact.Bytes()), backup.Expectation{Generation: generation, Checksum: hex.EncodeToString(h[:]), Bytes: int64(artifact.Len())}, t.TempDir())
	if err != nil || !report.LogicalValid || report.RestoreReady {
		t.Fatal("current backup preflight", report, err)
	}
}
