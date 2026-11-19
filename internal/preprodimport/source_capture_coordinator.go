package preprodimport

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// coordinateSourceCapture holds the real offline maintenance fence and the
// same IMMEDIATE SQLite transaction while authenticating the existing Master
// identity, reserving a sealed durable intent, and running an internal source
// capture producer. This is not registered as a command or HTTP route. The
// producer, destination key wrapping, complete streaming receiver, owner fences
// and reconciliation after interruption remain prerequisites for activation.
// It never clears the intent or publishes a successful import.
func coordinateSourceCapture(ctx context.Context, gate *maintenance.Gate, root *os.Root, dataRoot, databasePath string, v *vault.Vault, intent sourceCaptureIntent, expectedPublic string, produce func(context.Context, maintenance.SQLiteSnapshotReader, func(string) (string, error), func() error) error) error {
	if ctx == nil || gate == nil || root == nil || v == nil || produce == nil || expectedPublic == "" || !validSourceCaptureIntent(intent) {
		return invalid("source capture coordinator")
	}
	rootName, err := filepath.Abs(root.Name())
	if err != nil {
		return invalid("source capture root")
	}
	expectedRoot, err := filepath.Abs(dataRoot)
	if err != nil || filepath.Clean(rootName) != filepath.Clean(expectedRoot) {
		return invalid("source capture root")
	}
	openedRoot, err := root.Stat(".")
	currentRoot, currentErr := os.Lstat(expectedRoot)
	if err != nil || currentErr != nil || !openedRoot.IsDir() || !currentRoot.IsDir() || currentRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedRoot, currentRoot) {
		return invalid("source capture root changed")
	}
	return gate.InspectSQLiteImmediate(ctx, dataRoot, databasePath, func(ctx context.Context, reader maintenance.SQLiteSnapshotReader, check func() error) error {
		if err := check(); err != nil {
			return err
		}
		var sourceID, role, encryptedKey string
		if err := reader.QueryRowContext(ctx, `SELECT node_id,role,private_key FROM node_identity WHERE singleton=1`).Scan(&sourceID, &role, &encryptedKey); err != nil || sourceID != intent.SourceNode || role != "Master" {
			return invalid("source capture Master identity")
		}
		var keyID string
		if err := reader.QueryRowContext(ctx, `SELECT key_id FROM media_crypto_keys WHERE singleton=1`).Scan(&keyID); err != nil || subtle.ConstantTimeCompare([]byte(keyID), []byte(intent.SourceKeyID)) != 1 {
			return invalid("source capture media key identity")
		}
		privateKey, err := v.Unseal(encryptedKey)
		if err != nil {
			return invalid("source capture Vault identity")
		}
		public, err := protocol.PublicKey(privateKey)
		if err != nil || subtle.ConstantTimeCompare([]byte(public), []byte(expectedPublic)) != 1 {
			return invalid("source capture pinned key")
		}
		if err = reserveSourceCaptureIntent(root, v, intent, time.Now().UTC(), check); err != nil {
			return err
		}
		var signMu sync.Mutex
		signed := false
		sign := func(digest string) (string, error) {
			signMu.Lock()
			defer signMu.Unlock()
			if signed || !id64.MatchString(digest) || ctx.Err() != nil || check() != nil || time.Now().Unix() >= intent.ExpiresUnix {
				return "", invalid("source capture signing scope")
			}
			payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": intent.CaptureID, "source_node": intent.SourceNode, "target_node": intent.TargetNode, "challenge": intent.Challenge, "scope_sha256": intent.ScopeDigest, "sha256": digest, "expires_unix": intent.ExpiresUnix}
			signature, err := protocol.Sign(privateKey, payload)
			if err != nil || ctx.Err() != nil || check() != nil || time.Now().Unix() >= intent.ExpiresUnix {
				return "", invalid("source capture signing failed")
			}
			signed = true
			return signature, nil
		}
		if err = produce(ctx, reader, sign, check); err != nil {
			return err
		}
		signMu.Lock()
		defer signMu.Unlock()
		if !signed || check() != nil || ctx.Err() != nil {
			return errors.New("source capture did not finish under its fence")
		}
		return nil
	})
}
