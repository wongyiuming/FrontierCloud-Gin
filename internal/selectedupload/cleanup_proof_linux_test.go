//go:build linux

package selectedupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type fixtureCleanupMediaLease struct {
	root *os.Root
	deny bool
}

func (l fixtureCleanupMediaLease) CheckCleanupRoot(ctx context.Context, root *os.Root) error {
	if l.deny || root != l.root || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}

func TestCleanupBlobProofRejectsReplacementMutationAndClose(t *testing.T) {
	for _, test := range []string{"valid", "mutation", "replacement", "parent-replacement", "closed", "cancelled"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			blob := strings.Repeat("1", 64)
			name, err := sealedtree.BlobPath(blob)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0700); err != nil {
				t.Fatal(err)
			}
			body := []byte("synthetic encrypted object")
			if err = os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			claim := protocol.SelectedStorageUpload{OperationID: strings.Repeat("2", 64), ObjectID: blob, ContentSHA256: hex.EncodeToString(digest[:]), Size: int64(len(body))}
			proof, err := PrepareCleanupBlob(context.Background(), root, claim)
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Close()
			ctx := context.Background()
			switch test {
			case "mutation":
				if err = os.WriteFile(filepath.Join(dir, name), []byte("Synthetic encrypted object"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err = os.Rename(filepath.Join(dir, name), filepath.Join(dir, name)+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-replacement":
				parent := filepath.Join(dir, filepath.Dir(name))
				if err = os.Rename(parent, parent+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err = proof.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = proof.check(ctx, root, claim)
			if (err == nil) != (test == "valid") {
				t.Fatalf("case %s: %v", test, err)
			}
		})
	}
}

func TestCleanupBlobProofGuardedUnlinkAndLostAckRetry(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic ciphertext requiring verified removal")
	digest := sha256.Sum256(body)
	claim := protocol.SelectedStorageUpload{Master: strings.Repeat("1", 32), Owner: strings.Repeat("2", 32), Relationship: strings.Repeat("3", 32), RelationshipBinding: strings.Repeat("4", 64), Generation: strings.Repeat("5", 64), StageID: strings.Repeat("6", 64), ObjectID: strings.Repeat("7", 64), ContentSHA256: hex.EncodeToString(digest[:]), PublishChallenge: strings.Repeat("9", 64), CleanupChallenge: strings.Repeat("a", 64), OperationID: strings.Repeat("c", 64), Size: int64(len(body))}
	if err = persistOwnerIntent(context.Background(), root, v, claim, false, false); err != nil {
		t.Fatal(err)
	}
	name, err := sealedtree.BlobPath(claim.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, "staging"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(filepath.Join(dir, name), filepath.Join(dir, "staging", claim.OperationID+".part")); err != nil {
		t.Fatal(err)
	}
	proof, err := PrepareCleanupBlob(context.Background(), root, claim)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Close()
	call := func(media fixtureCleanupMediaLease, candidate *CleanupBlobProof, sign func(context.Context) error) error {
		return RunOperationCleanupWithProof(context.Background(), &testLease{}, media, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, candidate, func(context.Context) error { return nil }, sign)
	}
	if err = call(fixtureCleanupMediaLease{root: root, deny: true}, proof, func(context.Context) error { t.Fatal("signed without volume guard"); return nil }); err == nil {
		t.Fatal("unheld media guard accepted")
	}
	if _, err = os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatal("guard failure removed blob", err)
	}
	authorizations := 0
	err = RunOperationCleanupWithProof(context.Background(), &testLease{}, fixtureCleanupMediaLease{root: root}, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, root, v, claim, proof, func(context.Context) error {
		authorizations++
		if authorizations == 2 {
			return errors.New("fixture revoked")
		}
		return nil
	}, func(context.Context) error { t.Fatal("revoked cleanup signed"); return nil })
	if err == nil || authorizations != 2 {
		t.Fatal("revoked authorization accepted", err)
	}
	if _, err = os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatal("revoked cleanup removed blob", err)
	}
	if err = call(fixtureCleanupMediaLease{root: root}, proof, func(context.Context) error { return errors.New("fixture lost acknowledgement") }); err == nil {
		t.Fatal("missing signed acknowledgement accepted")
	}
	for _, target := range []string{name, filepath.Join("staging", claim.OperationID+".part")} {
		if _, err = os.Stat(filepath.Join(dir, target)); !os.IsNotExist(err) {
			t.Fatal("removed object survived", err)
		}
	}
	if _, err = root.Lstat(".selected-upload-intents/" + claim.OperationID + ".cancelled"); err != nil {
		t.Fatal("missing durable tombstone", err)
	}
	if err = persistOwnerIntent(context.Background(), root, v, claim, true, false); err == nil {
		t.Fatal("late writer replay accepted")
	}
	signed := false
	if err = call(fixtureCleanupMediaLease{root: root}, nil, func(context.Context) error { signed = true; return nil }); err != nil || !signed {
		t.Fatal("lost acknowledgement retry", err)
	}
}
