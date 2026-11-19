package preprodimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type sourceStreamManifest struct {
	Version      int                   `json:"version"`
	Header       sourceStreamHeader    `json:"header"`
	Sections     []sourceSectionDigest `json:"sections"`
	PlainSHA256  string                `json:"plain_sha256"`
	CipherSHA256 string                `json:"cipher_sha256"`
}
type signedSourceStream struct {
	Manifest  sourceStreamManifest `json:"manifest"`
	Signature string               `json:"signature"`
}

func sourceStreamManifestDigest(m sourceStreamManifest) (string, error) {
	if m.Version != 2 || len(m.Sections) != len(sourceRowSpecs) || !id64.MatchString(m.PlainSHA256) || !id64.MatchString(m.CipherSHA256) {
		return "", invalid("source stream manifest")
	}
	if _, err := sourceStreamHeaderDigest(m.Header); err != nil {
		return "", err
	}
	for i, section := range m.Sections {
		if section.Name != sourceRowSpecs[i].name || section.Rows < 0 || !id64.MatchString(section.SHA256) {
			return "", invalid("source stream manifest sections")
		}
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > 1<<20 {
		return "", invalid("source stream manifest bytes")
	}
	defer clear(raw)
	digest := sha256.Sum256(append([]byte("frontiercloud:source-stream-manifest:v2\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

// verifySourceStreamManifest validates scope/signature before an import may
// decrypt a stage. It still does not establish owner proofs or publish rights.
func verifySourceStreamManifest(s signedSourceStream, intent sourceCaptureIntent, public string, receiver []byte, now time.Time) error {
	if !validSourceCaptureIntent(intent) || now.Unix() < intent.IssuedUnix || now.Unix() >= intent.ExpiresUnix || len(receiver) != 32 || intent.Receiver != hex.EncodeToString(receiver) {
		return invalid("source stream manifest authority")
	}
	h := s.Manifest.Header
	if h.CaptureID != intent.CaptureID || h.SourceNode != intent.SourceNode || h.TargetNode != intent.TargetNode || h.SourceKeyID != intent.SourceKeyID || h.Challenge != intent.Challenge || h.ScopeDigest != intent.ScopeDigest || h.Receiver != hex.EncodeToString(receiver) {
		return invalid("source stream manifest scope")
	}
	digest, err := sourceStreamManifestDigest(s.Manifest)
	if err != nil {
		return err
	}
	payload := map[string]any{"kind": "frontiercloud-preprod-source-stream-v2", "capture_id": intent.CaptureID, "source_node": intent.SourceNode, "target_node": intent.TargetNode, "challenge": intent.Challenge, "scope_sha256": intent.ScopeDigest, "sha256": digest, "expires_unix": intent.ExpiresUnix}
	if protocol.Verify(public, payload, s.Signature) != nil {
		return invalid("source stream manifest signature")
	}
	return nil
}

// captureSourceStreamV2 creates only ciphertext in a fresh exclusive private
// stage, under the durable intent and same transaction. It is unregistered.
// A failed operation intentionally retains its encrypted stage and intent for
// explicit reconciliation; no blind cleanup or import publication occurs.
func captureSourceStreamV2(ctx context.Context, gate *maintenance.Gate, root *os.Root, dataRoot, databasePath string, v *vault.Vault, intent sourceCaptureIntent, expectedPublic string, receiver []byte) (result signedSourceStream, err error) {
	if len(receiver) != 32 || hex.EncodeToString(receiver) != intent.Receiver {
		return result, invalid("source stream recipient")
	}
	err = coordinateSourceCapture(ctx, gate, root, dataRoot, databasePath, v, intent, expectedPublic, func(ctx context.Context, q maintenance.SQLiteSnapshotReader, sign func(string) (string, error), check func() error) error {
		first, e := scanSourceRowsV2(ctx, q, io.Discard, 128, check)
		if e != nil {
			return e
		}
		header, ephemeral, e := newSourceStreamHeader(intent, receiver, first.Bytes)
		if e != nil {
			return e
		}
		dir, e := root.OpenRoot(sourceCaptureIntentDir)
		if e != nil {
			return e
		}
		defer dir.Close()
		dirInfo, e := dir.Stat(".")
		if e != nil || !privateOwned(dirInfo, true) {
			return invalid("source stream directory")
		}
		stage, e := dir.OpenFile(intent.CaptureID+".stage", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		stageInfo, e := stage.Stat()
		if e != nil || !privateOwned(stageInfo, false) {
			_ = stage.Close()
			return invalid("source stream stage")
		}
		pipeReader, pipeWriter := io.Pipe()
		type scanResult struct {
			value sourceRowsDigest
			err   error
		}
		done := make(chan scanResult, 1)
		go func() {
			value, e := scanSourceRowsV2(ctx, q, pipeWriter, 128, check)
			_ = pipeWriter.CloseWithError(e)
			done <- scanResult{value, e}
		}()
		plain, cipher, e := sealSourceStreamV2(ctx, header, ephemeral, stage, pipeReader)
		if e != nil {
			_ = pipeReader.CloseWithError(e)
		} else {
			_ = pipeReader.Close()
		}
		second := <-done
		if e != nil || second.err != nil || !reflect.DeepEqual(first, second.value) || first.SHA256 != plain {
			_ = stage.Close()
			return invalid("source stream snapshot changed")
		}
		if e = stage.Sync(); e != nil {
			_ = stage.Close()
			return e
		}
		if e = stage.Close(); e != nil {
			return e
		}
		current, e := dir.Lstat(intent.CaptureID + ".stage")
		if e != nil || !privateOwned(current, false) || !os.SameFile(stageInfo, current) {
			return invalid("source stream stage changed")
		}
		if e = fsutil.SyncDirectory(dir, "."); e != nil {
			return e
		}
		manifest := sourceStreamManifest{Version: 2, Header: header, Sections: first.Sections, PlainSHA256: hex.EncodeToString(plain[:]), CipherSHA256: hex.EncodeToString(cipher[:])}
		digest, e := sourceStreamManifestDigest(manifest)
		if e != nil {
			return e
		}
		signature, e := sign(digest)
		if e != nil {
			return e
		}
		if check() != nil || ctx.Err() != nil {
			return errors.New("source stream fence lost")
		}
		result = signedSourceStream{Manifest: manifest, Signature: signature}
		if e = verifySourceStreamManifest(result, intent, expectedPublic, receiver, time.Now().UTC()); e != nil {
			return e
		}
		if e = persistSourceStreamManifest(root, v, intent, result, check); e != nil {
			return e
		}
		if check() != nil || ctx.Err() != nil {
			return errors.New("source stream fence lost after manifest persistence")
		}
		return nil
	})
	if err != nil {
		return signedSourceStream{}, err
	}
	return result, nil
}
