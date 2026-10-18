package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

func TestNewGlobalToolRoutesAnotherDeploymentsOldPendingUpgrade(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native development host")
	}
	for _, kind := range []string{"resume", "explicit-conflict", "missing-backend", "wrong-generation", "symlink-backend", "opened", "same-generation"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "operator")
			deployment := filepath.Join(root, "node-b")
			target := strings.Repeat("a", 40)
			if err := os.MkdirAll(filepath.Join(home, "backends", "g7"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(deployment, 0700); err != nil {
				t.Fatal(err)
			}
			write := func(path string, value any) {
				t.Helper()
				raw, err := json.Marshal(value)
				if err == nil {
					err = os.WriteFile(path, raw, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(deployment, operator.ReceiptFile), operator.Receipt{Version: 1, Role: "master", Database: "sqlite", Project: "node-b", Revision: strings.Repeat("b", 40), Files: []string{"docker-compose.yaml"}, State: "upgrade_fenced"})
			phase := "prepared_fenced"
			if kind == "opened" {
				phase = "opened"
				write(filepath.Join(deployment, operator.ReceiptFile), operator.Receipt{Version: 1, Role: "master", Database: "sqlite", Project: "node-b", Revision: target, Files: []string{"docker-compose.yaml"}, State: "ready"})
			}
			write(filepath.Join(deployment, operator.UpgradeJournal), map[string]any{"version": 1, "phase": phase, "plan": map[string]any{"target_revision": target, "schema_generation": 7, "unknown_to_newer_tool": "retained unchanged"}})
			if err := os.WriteFile(filepath.Join(home, ".managed"), []byte("frontiercloud-foc-v2\n"), 0600); err != nil {
				t.Fatal(err)
			}
			global := filepath.Join(home, "fc")
			if err := os.WriteFile(global, []byte("new global generation 8 remains unchanged"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, "backends", "g7", "fc")
			gen := "7"
			if kind == "wrong-generation" {
				gen = "8"
			}
			script := "#!/bin/sh\ncase \"$1\" in operator-generation) echo " + gen + "; exit 0;; version) echo " + strings.Repeat("c", 40) + "; exit 0;; esac\nprintf '%s\\n' \"$@\"\nprintf 'retained=%s\\n' \"$FOC_RETAINED_UPGRADE_GENERATION\"\n"
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "missing-backend" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink-backend" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(global, path); err != nil {
					t.Fatal(err)
				}
			}
			requested := ""
			if kind == "explicit-conflict" {
				requested = strings.Repeat("d", 40)
			}
			generation := 8
			if kind == "same-generation" {
				generation = 7
			}
			var out, diagnostic bytes.Buffer
			handled, code := dispatchRetainedUpgrade(context.Background(), deployment, requested, []string{"upgrade"}, strings.NewReader("y\n"), &out, &diagnostic, true, generation, home)
			if kind == "opened" || kind == "same-generation" {
				if handled {
					t.Fatal("unnecessary retained dispatch", diagnostic.String())
				}
				return
			}
			if kind != "resume" {
				if !handled || code != 2 || out.Len() != 0 {
					t.Fatal(kind, handled, code, out.String(), diagnostic.String())
				}
				return
			}
			if !handled || code != 0 || !strings.Contains(out.String(), "--revision\n"+target+"\n--json\nupgrade\nretained=7") {
				t.Fatal(handled, code, out.String(), diagnostic.String())
			}
			raw, err := os.ReadFile(global)
			if err != nil || string(raw) != "new global generation 8 remains unchanged" {
				t.Fatal("global backend replaced", err)
			}
			d, r, err := operator.Open(deployment)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(retainedUpgradeEnvironment, "7")
			if retained, err := retainedUpgradeMode(d, r, target, 7); err != nil || !retained {
				t.Fatal(retained, err)
			}
			if _, err := retainedUpgradeMode(d, r, strings.Repeat("e", 40), 7); err == nil {
				t.Fatal("retained backend escaped pending target")
			}
		})
	}
}
