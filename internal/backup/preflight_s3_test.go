package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func s3PreflightRecords(t *testing.T) []map[string]any {
	t.Helper()
	records := preflightRecords()
	id, member := strings.Repeat("2", 64), strings.Repeat("1", 32)
	path := "music/remote/a.mp3"
	hash := sha256.Sum256([]byte(path))
	proof, err := json.Marshal(store.S3ObjectProof{Key: "objects/" + id, SessionID: strings.Repeat("3", 32), ObjectID: id, MemberID: member, MediaID: id, Bytes: 128, ETag: "\"opaque\"", VersionID: "version1", CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"})
	if err != nil {
		t.Fatal(err)
	}
	row := func(table string, value map[string]any) map[string]any {
		return map[string]any{"kind": "row", "table": table, "value": value}
	}
	return append(records[:len(records)-1],
		row("global_media_objects", map[string]any{"media_id": id, "storage_member_id": member, "object_id": id, "media_path": path, "path_locator": hex.EncodeToString(hash[:]), "object_kind": "audio", "size_bytes": 128, "etag": "\"opaque\"", "state": "active", "created_at": 1, "updated_at": 2}),
		row("cluster_storage_members", map[string]any{"member_id": member, "relationship_id": nil, "member_kind": "S3", "transport": "S3", "storage_enabled": 0, "allocated_bytes": store.GiB, "used_bytes": 128, "reserved_bytes": 0, "physical_free_bytes": 0, "health": "offline", "writable": 0, "updated_at": 2}),
		row("s3_members", map[string]any{"member_id": member, "name": "Recovered object store", "endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "backup-s3-fixture", "prefix": "managed", "address_style": "path", "namespace_key": "aws\nbackup-s3-fixture", "sealed_credentials": "", "credential_expires_at": 0, "credential_revision": 1, "revision": 1, "probe_revision": 0, "probe_state": "unchecked", "cleanup_only": 0, "error_code": "credentials_required", "created_at": 1, "updated_at": 2}),
		row("s3_objects", map[string]any{"media_id": id, "member_id": member, "object_key": "objects/" + id, "object_id": id, "proof_json": string(proof), "state": "active", "revision": 1, "grant_until": 0, "error_code": "", "created_at": 1, "updated_at": 2}),
		map[string]any{"kind": "end"})
}

func s3PreflightOwner(records []map[string]any) map[string]any {
	for _, record := range records {
		if record["table"] == "cluster_storage_members" {
			value := record["value"].(map[string]any)
			if value["member_kind"] == "S3" {
				return value
			}
		}
	}
	panic("missing S3 owner")
}

func TestS3BackupProjectionRequiresIndependentCredentialsAndOwnershipProof(t *testing.T) {
	records := s3PreflightRecords(t)
	data := encodedPreflight(records)
	report, err := Preflight(context.Background(), bytes.NewReader(data), expectedPreflight(data), t.TempDir())
	if err != nil || !report.LogicalValid || report.RestoreReady || report.Rows["s3_members"] != 1 || report.Rows["s3_objects"] != 1 || len(report.PendingGates) != 5 || report.PendingGates[4] != "s3-credentials-and-provider-ownership-proof" {
		t.Fatal(report, err)
	}
}

func TestS3BackupRejectsSigningAuthorityAndUnboundProviderFacts(t *testing.T) {
	cases := map[string]func([]map[string]any) []map[string]any{
		"credential": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_members")["sealed_credentials"] = "must-not-transfer"
			return r
		},
		"enabled":  func(r []map[string]any) []map[string]any { s3PreflightOwner(r)["storage_enabled"] = 1; return r },
		"writable": func(r []map[string]any) []map[string]any { s3PreflightOwner(r)["writable"] = 1; return r },
		"native-relationship": func(r []map[string]any) []map[string]any {
			s3PreflightOwner(r)["relationship_id"] = strings.Repeat("4", 32)
			return r
		},
		"probe": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_members")["probe_revision"] = 1
			return r
		},
		"cleanup": func(r []map[string]any) []map[string]any { preflightRow(r, "s3_members")["cleanup_only"] = 1; return r },
		"namespace": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_members")["namespace_key"] = "foreign"
			return r
		},
		"future-read-grant": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_objects")["grant_until"] = time.Now().Unix() + 300
			return r
		},
		"delete-intent": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_objects")["state"] = "deleting"
			return r
		},
		"object-key": func(r []map[string]any) []map[string]any {
			preflightRow(r, "s3_objects")["object_key"] = "other"
			return r
		},
		"wrong-member-proof": func(r []map[string]any) []map[string]any {
			o := preflightRow(r, "s3_objects")
			o["proof_json"] = strings.Replace(o["proof_json"].(string), strings.Repeat("1", 32), strings.Repeat("4", 32), 1)
			return r
		},
		"wrong-size-proof": func(r []map[string]any) []map[string]any {
			o := preflightRow(r, "s3_objects")
			o["proof_json"] = strings.Replace(o["proof_json"].(string), `"size_bytes":128`, `"size_bytes":129`, 1)
			return r
		},
		"duplicate-proof-field": func(r []map[string]any) []map[string]any {
			o := preflightRow(r, "s3_objects")
			o["proof_json"] = strings.Replace(o["proof_json"].(string), `"size_bytes":128`, `"size_bytes":128,"size_bytes":128`, 1)
			return r
		},
		"missing-object": func(r []map[string]any) []map[string]any {
			var out []map[string]any
			for _, item := range r {
				if item["table"] != "s3_objects" {
					out = append(out, item)
				}
			}
			return out
		},
		"runtime-journal": func(r []map[string]any) []map[string]any {
			return append(r[:len(r)-1], map[string]any{"kind": "row", "table": "s3_uploads", "value": map[string]any{}}, r[len(r)-1])
		},
		"recording-owner": func(r []map[string]any) []map[string]any {
			preflightRow(r, "karaoke_recordings")["storage_member_id"] = strings.Repeat("1", 32)
			return r
		},
		"alias-prefix-overlap": func(r []map[string]any) []map[string]any {
			member := map[string]any{}
			for k, v := range preflightRow(r, "s3_members") {
				member[k] = v
			}
			member["member_id"] = strings.Repeat("4", 32)
			member["prefix"] = "managed/child"
			owner := map[string]any{}
			for k, v := range s3PreflightOwner(r) {
				owner[k] = v
			}
			owner["member_id"] = member["member_id"]
			owner["used_bytes"] = 0
			return append(r[:len(r)-1], map[string]any{"kind": "row", "table": "s3_members", "value": member}, map[string]any{"kind": "row", "table": "cluster_storage_members", "value": owner}, r[len(r)-1])
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data := encodedPreflight(mutate(s3PreflightRecords(t)))
			if _, err := Preflight(context.Background(), bytes.NewReader(data), expectedPreflight(data), t.TempDir()); !errors.Is(err, store.ErrBackupState) {
				t.Fatal("unsafe S3 projection accepted", err)
			}
		})
	}
}
