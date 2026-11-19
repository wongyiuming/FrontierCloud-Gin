package preprodimport

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// renewCapturedSourceStreamV2 reauthorizes the exact retained capture, without
// overwriting the durable intent or changing its manifest. This is an internal
// primitive, not an import permit: Owner verification and final reconciliation
// remain required. The returned read-only stage FD belongs to the caller.
// The historical signature is accepted only as evidence of the old capture;
// every renewed authorization is freshly signed by the authenticated Master.
func renewCapturedSourceStreamV2(ctx context.Context, gate *maintenance.Gate, root *os.Root, dataRoot, databasePath string, v *vault.Vault, original sourceCaptureIntent, public string, receiver []byte, lifetime time.Duration) (renewed sourceCaptureIntent, signed signedSourceStream, stage *os.File, err error) {
	if ctx == nil || ctx.Err() != nil || gate == nil || root == nil || v == nil || public == "" || !validSourceCaptureIntent(original) || lifetime < time.Second || lifetime > 300*time.Second || lifetime%time.Second != 0 {
		return renewed, signed, nil, invalid("source renewal input")
	}
	rootPath, e := filepath.Abs(root.Name())
	expectedRoot, e2 := filepath.Abs(dataRoot)
	rootInfo, e3 := root.Stat(".")
	pathInfo, e4 := os.Lstat(expectedRoot)
	if e != nil || e2 != nil || e3 != nil || e4 != nil || filepath.Clean(rootPath) != filepath.Clean(expectedRoot) || !rootInfo.IsDir() || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, pathInfo) {
		return renewed, signed, nil, invalid("source renewal root")
	}
	// Potentially large ciphertext hashing is intentionally outside the global
	// write fence; keep the authenticated FD and recheck its identity inside.
	previous, fd, e := reopenCapturedSourceStream(ctx, root, v, original, public, receiver, time.Unix(original.IssuedUnix, 0))
	if e != nil {
		return renewed, signed, nil, e
	}
	keep := false
	defer func() {
		if !keep {
			_ = fd.Close()
		}
	}()
	stageInfo, e := fd.Stat()
	if e != nil {
		return renewed, signed, nil, invalid("source renewal stage")
	}
	checkStage := func() error {
		current, e := root.Lstat(sourceCaptureIntentDir + "/" + original.CaptureID + ".stage")
		opened, e2 := fd.Stat()
		if e != nil || e2 != nil || !privateOwned(current, false) || !privateOwned(opened, false) || !os.SameFile(stageInfo, current) || !os.SameFile(stageInfo, opened) || current.Size() != stageInfo.Size() || opened.Size() != stageInfo.Size() || !current.ModTime().Equal(stageInfo.ModTime()) || !opened.ModTime().Equal(stageInfo.ModTime()) {
			return invalid("source renewal stage changed")
		}
		return nil
	}
	digest, e := sourceStreamManifestDigest(previous.Manifest)
	if e != nil {
		return renewed, signed, nil, e
	}
	e = gate.InspectSQLiteImmediate(ctx, dataRoot, databasePath, func(ctx context.Context, q maintenance.SQLiteSnapshotReader, check func() error) error {
		stored, e := readSourceCaptureIntent(root, v)
		if e != nil || stored != original || check() != nil || checkStage() != nil {
			return invalid("source renewal intent or stage")
		}
		var node, role, encrypted, keyID string
		if e := q.QueryRowContext(ctx, `SELECT node_id,role,private_key FROM node_identity WHERE singleton=1`).Scan(&node, &role, &encrypted); e != nil || node != original.SourceNode || role != "Master" {
			return invalid("source renewal Master identity")
		}
		if e := q.QueryRowContext(ctx, `SELECT key_id FROM media_crypto_keys WHERE singleton=1`).Scan(&keyID); e != nil || subtle.ConstantTimeCompare([]byte(keyID), []byte(original.SourceKeyID)) != 1 {
			return invalid("source renewal media key identity")
		}
		privateKey, e := v.Unseal(encrypted)
		if e != nil {
			return invalid("source renewal Vault identity")
		}
		actualPublic, e := protocol.PublicKey(privateKey)
		if e != nil || subtle.ConstantTimeCompare([]byte(actualPublic), []byte(public)) != 1 {
			return invalid("source renewal pinned key")
		}
		rows, e := scanSourceRowsV2(ctx, q, io.Discard, 128, check)
		if e != nil {
			return e
		}
		if rows.Bytes != previous.Manifest.Header.PlainSize || hex.EncodeToString(rows.SHA256[:]) != previous.Manifest.PlainSHA256 || !reflect.DeepEqual(rows.Sections, previous.Manifest.Sections) {
			return invalid("source renewal source changed")
		}
		if ctx.Err() != nil || check() != nil || checkStage() != nil {
			return invalid("source renewal fence")
		}
		current := time.Now().UTC()
		fresh := original
		fresh.IssuedUnix = current.Unix()
		fresh.ExpiresUnix = fresh.IssuedUnix + int64(lifetime/time.Second)
		payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": fresh.CaptureID, "source_node": fresh.SourceNode, "target_node": fresh.TargetNode, "challenge": fresh.Challenge, "scope_sha256": fresh.ScopeDigest, "sha256": digest, "expires_unix": fresh.ExpiresUnix}
		signature, e := protocol.Sign(privateKey, payload)
		if e != nil {
			return invalid("source renewal signature")
		}
		candidate := signedSourceStream{Manifest: previous.Manifest, Signature: signature}
		if ctx.Err() != nil || check() != nil || checkStage() != nil || verifySourceStreamManifest(candidate, fresh, public, receiver, time.Now().UTC()) != nil {
			return invalid("source renewal final verification")
		}
		renewed, signed = fresh, candidate
		return nil
	})
	if e != nil {
		return sourceCaptureIntent{}, signedSourceStream{}, nil, e
	}
	if ctx.Err() != nil || checkStage() != nil {
		return sourceCaptureIntent{}, signedSourceStream{}, nil, invalid("source renewal final stage")
	}
	keep = true
	return renewed, signed, fd, nil
}
