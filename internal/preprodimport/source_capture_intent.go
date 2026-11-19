package preprodimport

// This is a durable, fail-closed intent primitive for a future source-side
// capture coordinator. It is not an import permit, publication receipt or
// recovery procedure, and is not registered as a command or route.
import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

const sourceCaptureIntentDir = ".source-capture"
const sourceCaptureIntentName = "active.intent"

// This metadata never contains a snapshot key, private key, media path, or
// plaintext media data. A capture key remains ephemeral: after a process crash
// an incomplete encrypted stage must be explicitly reconciled, not resumed.
type sourceCaptureIntent struct {
	Version     int    `json:"version"`
	Purpose     string `json:"purpose"`
	CaptureID   string `json:"capture_id"`
	SourceNode  string `json:"source_node"`
	TargetNode  string `json:"target_node"`
	SourceKeyID string `json:"source_key_id"`
	Receiver    string `json:"receiver_x25519"`
	Challenge   string `json:"challenge"`
	ScopeDigest string `json:"scope_digest"`
	IssuedUnix  int64  `json:"issued_unix"`
	ExpiresUnix int64  `json:"expires_unix"`
}

func validSourceCaptureIntent(i sourceCaptureIntent) bool {
	return i.Version == 1 && i.Purpose == "frontiercloud:source-capture-intent:v1" && id32.MatchString(i.CaptureID) && id32.MatchString(i.SourceNode) && id32.MatchString(i.TargetNode) && i.SourceNode != i.TargetNode && id64.MatchString(i.SourceKeyID) && id64.MatchString(i.Receiver) && id64.MatchString(i.Challenge) && id64.MatchString(i.ScopeDigest) && i.IssuedUnix > 0 && i.ExpiresUnix > i.IssuedUnix && i.ExpiresUnix-i.IssuedUnix <= 300
}

// reserveSourceCaptureIntent runs only while the caller holds its real
// maintenance and SQLite transaction fences. The intent is exclusive and
// durably synced before capture begins. Any error leaves it in place; no
// partially written record is silently erased or interpreted as authority.
func reserveSourceCaptureIntent(root *os.Root, v *vault.Vault, intent sourceCaptureIntent, now time.Time, check func() error) error {
	if root == nil || v == nil || check == nil || !validSourceCaptureIntent(intent) || now.Unix() < intent.IssuedUnix || now.Unix() >= intent.ExpiresUnix || check() != nil {
		return invalid("source capture intent scope")
	}
	if err := root.Mkdir(sourceCaptureIntentDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat(sourceCaptureIntentDir)
	if err != nil || !privateOwned(info, true) {
		return invalid("source capture intent directory")
	}
	dir, err := root.OpenRoot(sourceCaptureIntentDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil || !privateOwned(opened, true) || !os.SameFile(info, opened) {
		return invalid("source capture intent directory changed")
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	defer clear(raw)
	sealed, err := v.Seal(string(raw))
	if err != nil || len(sealed) > 4096 {
		return invalid("source capture intent sealing")
	}
	if check() != nil {
		return invalid("source capture intent fence")
	}
	file, err := dir.OpenFile(sourceCaptureIntentName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fileInfo, statErr := file.Stat()
	current, currentErr := dir.Lstat(sourceCaptureIntentName)
	if statErr != nil || currentErr != nil || !privateOwned(fileInfo, false) || !os.SameFile(fileInfo, current) {
		_ = file.Close()
		return invalid("source capture intent file")
	}
	_, writeErr := io.WriteString(file, sealed)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err = fsutil.SyncDirectory(dir, "."); err != nil {
		return err
	}
	if err = fsutil.SyncDirectory(root, "."); err != nil {
		return err
	}
	if check() != nil {
		return invalid("source capture intent fence")
	}
	return nil
}

func readSourceCaptureIntent(root *os.Root, v *vault.Vault) (sourceCaptureIntent, error) {
	var result sourceCaptureIntent
	if root == nil || v == nil {
		return result, invalid("source capture intent")
	}
	info, err := root.Lstat(sourceCaptureIntentDir)
	if err != nil || !privateOwned(info, true) {
		return result, invalid("source capture intent directory")
	}
	dir, err := root.OpenRoot(sourceCaptureIntentDir)
	if err != nil {
		return result, err
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return result, invalid("source capture intent directory changed")
	}
	entry, err := dir.Lstat(sourceCaptureIntentName)
	if err != nil || !privateOwned(entry, false) || entry.Size() < 1 || entry.Size() > 4096 {
		return result, invalid("source capture intent file")
	}
	file, err := dir.Open(sourceCaptureIntentName)
	if err != nil {
		return result, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !privateOwned(actual, false) || !os.SameFile(entry, actual) {
		return result, invalid("source capture intent changed")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(encoded) > 4096 {
		return result, invalid("source capture intent read")
	}
	plain, err := v.Unseal(string(encoded))
	if err != nil {
		return result, invalid("source capture intent authentication")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || !validSourceCaptureIntent(result) {
		return sourceCaptureIntent{}, invalid("source capture intent body")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return sourceCaptureIntent{}, invalid("source capture intent trailing data")
	}
	return result, nil
}
