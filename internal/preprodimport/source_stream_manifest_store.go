package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// The sealed manifest is published only after ciphertext fsync and source
// signature. Failure never removes the intent or stage. It grants no import or
// owner authority; crash recovery must explicitly reconcile those components.
func persistSourceStreamManifest(root *os.Root, v *vault.Vault, intent sourceCaptureIntent, s signedSourceStream, check func() error) error {
	if root == nil || v == nil || check == nil || !validSourceCaptureIntent(intent) || check() != nil {
		return invalid("source stream manifest persistence")
	}
	if _, err := sourceStreamManifestDigest(s.Manifest); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16384 {
		return invalid("source stream manifest size")
	}
	defer clear(raw)
	sealed, err := v.Seal(string(raw))
	if err != nil || len(sealed) > 32768 {
		return invalid("source stream manifest seal")
	}
	info, err := root.Lstat(sourceCaptureIntentDir)
	if err != nil || !privateOwned(info, true) {
		return invalid("source stream directory")
	}
	dir, err := root.OpenRoot(sourceCaptureIntentDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	actual, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		return invalid("source stream directory changed")
	}
	if check() != nil {
		return invalid("source stream fence")
	}
	name := intent.CaptureID + ".manifest"
	file, err := dir.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	current, entryErr := dir.Lstat(name)
	if err != nil || entryErr != nil || !privateOwned(opened, false) || !os.SameFile(opened, current) {
		_ = file.Close()
		return invalid("source stream manifest file")
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
	if check() != nil {
		return invalid("source stream fence")
	}
	return nil
}

// reopenCapturedSourceStream verifies the authenticated intent, signed sealed
// manifest and full ciphertext digest before handing back a read-only FD. It
// never decrypts or mutates data. Caller owns the returned FD, and must still
// run target authentication, transactional ingestion and owner verification.
func reopenCapturedSourceStream(ctx context.Context, root *os.Root, v *vault.Vault, intent sourceCaptureIntent, public string, receiver []byte, now time.Time) (signedSourceStream, *os.File, error) {
	var empty signedSourceStream
	if ctx == nil || ctx.Err() != nil || root == nil || v == nil {
		return empty, nil, invalid("source stream reopen")
	}
	stored, err := readSourceCaptureIntent(root, v)
	if err != nil || stored != intent {
		return empty, nil, invalid("source stream intent mismatch")
	}
	info, err := root.Lstat(sourceCaptureIntentDir)
	if err != nil || !privateOwned(info, true) {
		return empty, nil, invalid("source stream directory")
	}
	dir, err := root.OpenRoot(sourceCaptureIntentDir)
	if err != nil {
		return empty, nil, err
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return empty, nil, invalid("source stream directory changed")
	}
	manifestName := intent.CaptureID + ".manifest"
	entry, err := dir.Lstat(manifestName)
	if err != nil || !privateOwned(entry, false) || entry.Size() < 1 || entry.Size() > 32768 {
		return empty, nil, invalid("source stream manifest file")
	}
	file, err := dir.Open(manifestName)
	if err != nil {
		return empty, nil, err
	}
	actual, statErr := file.Stat()
	if statErr != nil || !os.SameFile(entry, actual) {
		_ = file.Close()
		return empty, nil, invalid("source stream manifest changed")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, 32769))
	closeErr := file.Close()
	if errors.Join(readErr, closeErr) != nil || len(encoded) > 32768 {
		return empty, nil, invalid("source stream manifest read")
	}
	plain, err := v.Unseal(string(encoded))
	if err != nil {
		return empty, nil, invalid("source stream manifest authentication")
	}
	var signed signedSourceStream
	decoder := json.NewDecoder(bytes.NewBufferString(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&signed); err != nil {
		return empty, nil, invalid("source stream manifest body")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return empty, nil, invalid("source stream manifest trailing data")
	}
	if err = verifySourceStreamManifest(signed, intent, public, receiver, now); err != nil {
		return empty, nil, err
	}
	stageName := intent.CaptureID + ".stage"
	entry, err = dir.Lstat(stageName)
	if err != nil || !privateOwned(entry, false) {
		return empty, nil, invalid("source stream stage file")
	}
	stage, err := dir.Open(stageName)
	if err != nil {
		return empty, nil, err
	}
	valid := false
	defer func() {
		if !valid {
			_ = stage.Close()
		}
	}()
	actual, err = stage.Stat()
	if err != nil || !privateOwned(actual, false) || !os.SameFile(entry, actual) {
		return empty, nil, invalid("source stream stage changed")
	}
	count := (uint64(signed.Manifest.Header.PlainSize)-1)/uint64(sourceStreamChunk) + 1
	if count > uint64((int64(^uint64(0)>>1)-signed.Manifest.Header.PlainSize)/16) || actual.Size() != signed.Manifest.Header.PlainSize+int64(count)*16 {
		return empty, nil, invalid("source stream stage size")
	}
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	defer clear(buf)
	reader := io.NewSectionReader(stage, 0, actual.Size())
	for {
		if ctx.Err() != nil {
			return empty, nil, ctx.Err()
		}
		n, e := reader.Read(buf)
		if n > 0 {
			_, _ = hash.Write(buf[:n])
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return empty, nil, e
		}
	}
	expected, err := hex.DecodeString(signed.Manifest.CipherSHA256)
	if err != nil || subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return empty, nil, invalid("source stream stage digest")
	}
	current, err := dir.Lstat(stageName)
	last, fdErr := stage.Stat()
	if err != nil || fdErr != nil || !os.SameFile(actual, current) || !os.SameFile(actual, last) || current.Size() != actual.Size() || !current.ModTime().Equal(actual.ModTime()) || last.Size() != actual.Size() || !last.ModTime().Equal(actual.ModTime()) {
		return empty, nil, invalid("source stream stage changed")
	}
	valid = true
	return signed, stage, nil
}
