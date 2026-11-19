//go:build linux

package preprodimport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSourceCaptureIntentDurabilityAndFailClosed(t *testing.T) {
	data, secrets := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(secrets)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: strings.Repeat("2", 32), TargetNode: strings.Repeat("3", 32), Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(2 * time.Minute).Unix()}
	if err := reserveSourceCaptureIntent(root, v, intent, now, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := reserveSourceCaptureIntent(root, v, intent, now, func() error { return nil }); err == nil {
		t.Fatal("active intent overwritten")
	}
	reopenedVault, err := vault.OpenExisting(secrets)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSourceCaptureIntent(root, reopenedVault)
	if err != nil || got != intent {
		t.Fatal("durable intent failed to reopen", got, err)
	}
	path := filepath.Join(data, sourceCaptureIntentDir, sourceCaptureIntentName)
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(intent.SourceNode)) || bytes.Contains(sealed, []byte(intent.Challenge)) {
		t.Fatal("intent plaintext leaked")
	}
	wrong, err := vault.Open(filepath.Join(t.TempDir(), "other-secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readSourceCaptureIntent(root, wrong); err == nil {
		t.Fatal("wrong Vault authenticated")
	}
	sealed[len(sealed)/2] ^= 1
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readSourceCaptureIntent(root, reopenedVault); err == nil {
		t.Fatal("tampered intent accepted")
	}
}

func TestSourceCaptureIntentLeavesEvidenceOnFenceLoss(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	v, err := vault.Open(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intent := sourceCaptureIntent{Version: 1, Purpose: "frontiercloud:source-capture-intent:v1", CaptureID: strings.Repeat("1", 32), SourceNode: strings.Repeat("2", 32), TargetNode: strings.Repeat("3", 32), Challenge: strings.Repeat("4", 64), ScopeDigest: strings.Repeat("5", 64), SourceKeyID: strings.Repeat("6", 64), Receiver: strings.Repeat("7", 64), IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Minute).Unix()}
	checks := 0
	err = reserveSourceCaptureIntent(root, v, intent, now, func() error {
		checks++
		if checks >= 3 {
			return os.ErrClosed
		}
		return nil
	})
	if err == nil {
		t.Fatal("lost fence accepted")
	}
	if got, e := readSourceCaptureIntent(root, v); e != nil || got != intent {
		t.Fatal("fence loss lost durable evidence", e)
	}
}
