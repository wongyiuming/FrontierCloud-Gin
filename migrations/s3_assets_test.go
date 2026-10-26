package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestS3BackendDDLChecksumAndETagBoundaries(t *testing.T) {
	additive := map[string]string{}
	for _, backend := range []string{"sqlite", "mysql"} {
		var old struct {
			Statements []string `json:"statements"`
		}
		raw, err := assets.ReadFile(backend + "/0007-schema.json")
		if err != nil || json.Unmarshal(raw, &old) != nil {
			t.Fatal("historical schema unreadable", backend, err)
		}
		current, err := Statements(backend)
		if err != nil || len(current) <= len(old.Statements) {
			t.Fatal(backend, err)
		}
		for i, value := range old.Statements {
			if current[i] != value {
				t.Fatal("generation7 statement changed", backend, i)
			}
		}
		additive[backend] = strings.Join(current[len(old.Statements):], "\n")
		if backend == "mysql" {
			for _, spec := range []struct{ name, width string }{{"s3_probe_journal", "512"}, {"s3_upload_parts", "128"}, {"global_media_objects", "128"}} {
				found := false
				for _, statement := range current {
					if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS "+spec.name+" ") {
						found = strings.Contains(statement, "etag VARCHAR("+spec.width+") NOT NULL")
					}
				}
				if !found {
					t.Fatal("ETag schema scope changed", spec.name, spec.width)
				}
			}
		}
	}
	digest := sha256.Sum256([]byte("sqlite\n" + additive["sqlite"] + "\nmysql\n" + additive["mysql"]))
	if hex.EncodeToString(digest[:]) != S3Checksum {
		t.Fatal("generation8 journal does not bind both backend DDLs")
	}
}
