//go:build linux

package selectedupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSelectedRemovalRejectsWrongDigestAndSymlinks(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-digest", "parent-symlink", "leaf-symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			blob := strings.Repeat("a", 64)
			parent := filepath.Join(dir, "objects", "aa", "aa")
			if err = os.MkdirAll(parent, 0700); err != nil {
				t.Fatal(err)
			}
			content := []byte("synthetic selected ciphertext")
			outside := filepath.Join(dir, "other")
			if err = os.Mkdir(outside, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(parent, blob+".blob")
			if mode == "parent-symlink" {
				if err = os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, parent); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(outside, blob+".blob")
			}
			if mode == "leaf-symlink" {
				target = filepath.Join(outside, "preserve")
				if err = os.Symlink(target, filepath.Join(parent, blob+".blob")); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(target, content, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			digest := hex.EncodeToString(sum[:])
			if mode == "wrong-digest" {
				digest = strings.Repeat("0", 64)
			}
			err = removeOperationPath(context.Background(), root, "objects/aa/aa/"+blob+".blob", digest, int64(len(content)))
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, e := os.Stat(target); !os.IsNotExist(e) {
					t.Fatal("intended file remained", e)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe removal succeeded")
			}
			got, e := os.ReadFile(target)
			if e != nil || string(got) != string(content) {
				t.Fatal("unrelated or mismatched bytes changed", e)
			}
		})
	}
}

func TestSelectedCleanupGuardFailureRetainsTombstoneAndRetries(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: strings.Repeat("8", 64), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 64), Size: 1}
	signed := false
	call := func(guard func(context.Context) error) error {
		return RunOperationCleanupGuarded(context.Background(), &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, guard, func(context.Context) error { signed = true; return nil })
	}
	if err = call(func(context.Context) error { return errOperationLease }); err == nil || signed {
		t.Fatal("failed guard acknowledged cleanup", err)
	}
	if _, err = root.Lstat(".selected-upload-intents/" + claim.OperationID + ".cancelled"); err != nil {
		t.Fatal("missing durable cancellation", err)
	}
	if err = call(func(context.Context) error { return nil }); err != nil || !signed {
		t.Fatal("cancel retry failed", err)
	}
}
