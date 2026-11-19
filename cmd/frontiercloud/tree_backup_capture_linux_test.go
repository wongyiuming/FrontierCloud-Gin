//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestTreeBackupCaptureRejectsUnsafeRequestsAndMissingTree(t *testing.T) {
	base := t.TempDir()
	paths := [3]string{filepath.Join(base, "data"), filepath.Join(base, "secrets"), filepath.Join(base, "tmp")}
	for _, p := range paths {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	request := treeCaptureRequest{Nonce: strings.Repeat("a", 64), DatabaseRelative: "db.sqlite", Classes: []string{"deployment"}, StageLimit: 1024, Manifest: recovery.Manifest{Scope: "deployment", Role: "Master", Database: "sqlite", NodeID: strings.Repeat("b", 32), SchemaGeneration: migrations.Generation}}
	valid, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"duplicate": []byte(`{"nonce":"a","nonce":"b"}` + "\n"),
		"oversize":  []byte(strings.Repeat(" ", 65<<10) + "\n"),
		"truncated": valid,
		"missing":   append(append([]byte(nil), valid...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := treeBackupCapture(context.Background(), bytes.NewReader(body), &out, paths); err == nil {
				t.Fatal("unsafe capture accepted")
			}
			if out.Len() != 0 {
				t.Fatal("readiness reported without an acquired tree lease")
			}
			entries, err := os.ReadDir(paths[2])
			if err != nil || len(entries) != 0 {
				t.Fatalf("generated scratch not cleaned: %v %v", entries, err)
			}
			if _, err := os.Lstat(filepath.Join(paths[0], sealedtree.MasterFenceDirectory)); !os.IsNotExist(err) {
				t.Fatal("capture created or changed tree fence", err)
			}
			if _, err := os.Lstat(filepath.Join(paths[1], sealedtree.MasterKeyFile)); !os.IsNotExist(err) {
				t.Fatal("capture created or changed Master key", err)
			}
		})
	}
}
