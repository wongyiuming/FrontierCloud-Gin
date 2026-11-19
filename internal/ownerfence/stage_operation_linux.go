//go:build linux

package ownerfence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// StageOperation is an opaque, authenticated operation binding. A caller must
// independently authenticate the Master and its request before using it.
// It is intentionally not installed as a product endpoint.
type StageOperation struct {
	OperationID string `json:"operation_id"`
	BlobID      string `json:"blob_id"`
	ScopeDigest string `json:"scope_digest"`
}

func validStageOperation(s StageOperation) bool {
	for _, v := range []string{s.OperationID, s.BlobID, s.ScopeDigest} {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != v {
			return false
		}
	}
	return s.OperationID != s.BlobID
}

func stageName(kind, id string) string { return directory + "/.stage-" + kind + "-" + id }

// stageRecord reads one immutable, private, vault-authenticated record. A
// missing record is distinguishable only so a stopped node can prepare it.
func (f *Fence) stageRecord(name string) ([]byte, error) {
	file, err := f.root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, _, err = fileIdentity(file); err != nil {
		return nil, ErrUnsafe
	}
	opened, e1 := file.Stat()
	current, e2 := f.root.Lstat(name)
	if e1 != nil || e2 != nil || !os.SameFile(opened, current) {
		return nil, ErrUnsafe
	}
	sealed, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return nil, ErrUnsafe
	}
	raw, err := f.codec.OpenOpaqueOwnerRecord(name, string(sealed))
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return nil, ErrUnsafe
	}
	return raw, nil
}

func (f *Fence) stageWriteOnce(name string, raw []byte) error {
	return f.stageWriteOnceWithHook(name, raw, nil)
}

func (f *Fence) stageVerifyAndSync(name string, raw []byte) error {
	existing, err := f.stageRecord(name)
	if err != nil || !bytes.Equal(existing, raw) {
		return ErrUnsafe
	}
	file, err := f.root.OpenFile(name, os.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafe
	}
	_, _, identityErr := fileIdentity(file)
	opened, e1 := file.Stat()
	current, e2 := f.root.Lstat(name)
	syncErr := file.Sync()
	closeErr := file.Close()
	if identityErr != nil || e1 != nil || e2 != nil || !os.SameFile(opened, current) || syncErr != nil || closeErr != nil || syncDirectory(f.root) != nil {
		return ErrUnsafe
	}
	existing, err = f.stageRecord(name)
	if err != nil || !bytes.Equal(existing, raw) {
		return ErrUnsafe
	}
	return nil
}

// hook is used only by process-exit tests. Durable final records are always
// installed with no-replace rename after the entire temporary file is synced.
func (f *Fence) stageWriteOnceWithHook(name string, raw []byte, hook func(string)) error {
	base := strings.TrimPrefix(name, directory+"/")
	if base == name || base == "" || strings.Contains(base, "/") {
		return ErrUnsafe
	}
	if _, err := f.root.Lstat(name); err == nil {
		return f.stageVerifyAndSync(name, raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafe
	}
	sealed, err := f.codec.SealOpaqueOwnerRecord(name, raw)
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return ErrUnsafe
	}
	dir, err := f.root.Open(directory)
	if err != nil {
		return ErrUnsafe
	}
	defer dir.Close()
	opened, e1 := dir.Stat()
	current, e2 := f.root.Lstat(directory)
	if e1 != nil || e2 != nil || !os.SameFile(opened, current) {
		return ErrUnsafe
	}
	random := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return ErrUnsafe
	}
	// Bind the temporary name to the exact final record for a future
	// operation-scoped recovery; no timer-based deletion is performed.
	temp := ".stage-tmp-" + base + "-" + hex.EncodeToString(random)
	fd, err := unix.Openat(int(dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUnsafe
	}
	defer func() {
		if unix.Unlinkat(int(dir.Fd()), temp, 0) == nil {
			_ = dir.Sync()
		}
	}()
	file := os.NewFile(uintptr(fd), "stage-tmp")
	if file == nil {
		unix.Close(fd)
		return ErrUnsafe
	}
	n, w := file.WriteString(sealed)
	s := file.Sync()
	c := file.Close()
	if w != nil || n != len(sealed) || s != nil || c != nil {
		return ErrUnsafe
	}
	if hook != nil {
		hook("before_rename")
	}
	err = unix.Renameat2(int(dir.Fd()), temp, int(dir.Fd()), base, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		return f.stageVerifyAndSync(name, raw)
	}
	if err != nil {
		return ErrUnsafe
	}
	if hook != nil {
		hook("after_rename")
	}
	current, e2 = f.root.Lstat(directory)
	if e2 != nil || !os.SameFile(opened, current) || dir.Sync() != nil {
		return ErrUnsafe
	}
	return nil
}

func (f *Fence) verifyStage(s StageOperation) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return ErrUnsafe
	}
	for _, name := range []string{stageName("operation", s.OperationID), stageName("blob", s.BlobID)} {
		got, e := f.stageRecord(name)
		if e != nil || !bytes.Equal(got, raw) {
			return ErrUnsafe
		}
	}
	return nil
}

// PrepareStage creates permanent operation and blob claims under the owner
// exclusive fence. Interrupted creation can only resume with the exact scope;
// publication requires both claims. No identifier may be rebound.
func (f *Fence) PrepareStage(ctx context.Context, s StageOperation) error {
	if !validStageOperation(s) {
		return ErrUnsafe
	}
	l, err := f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	defer l.Release()
	if err = l.Check(ctx); err != nil {
		return err
	}
	if _, err = f.root.Lstat(stageName("stopped", s.OperationID)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafe
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return ErrUnsafe
	}
	if err = f.stageWriteOnce(stageName("blob", s.BlobID), raw); err != nil {
		return err
	}
	if err = f.stageWriteOnce(stageName("operation", s.OperationID), raw); err != nil {
		return err
	}
	return l.Check(ctx)
}

// AcquireStagePublish returns a shared lease that must be held throughout all
// publication I/O and checked again immediately before acknowledging success.
func (f *Fence) AcquireStagePublish(ctx context.Context, s StageOperation) (*Lease, error) {
	if !validStageOperation(s) {
		return nil, ErrUnsafe
	}
	l, err := f.Acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	if f.verifyStage(s) != nil {
		l.Release()
		return nil, ErrUnsafe
	}
	if _, err = f.root.Lstat(stageName("stopped", s.OperationID)); err == nil || !errors.Is(err, os.ErrNotExist) {
		l.Release()
		return nil, ErrUnsafe
	}
	if err = l.Check(ctx); err != nil {
		l.Release()
		return nil, err
	}
	return l, nil
}

// StopStageAndAcquireCleanup waits for publishers to drain, durably marks the
// operation stopped, and retains the exclusive fence for the caller to remove
// stage and blob, fsync both directories and sign its independently bound
// receipt. Errors, crashes and failed cleanup never undo the tombstone.
func (f *Fence) StopStageAndAcquireCleanup(ctx context.Context, s StageOperation) (*Lease, error) {
	if !validStageOperation(s) {
		return nil, ErrUnsafe
	}
	l, err := f.Acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	if f.verifyStage(s) != nil || l.Check(ctx) != nil {
		l.Release()
		return nil, ErrUnsafe
	}
	raw, err := json.Marshal(s)
	if err != nil || f.stageWriteOnce(stageName("stopped", s.OperationID), raw) != nil || l.Check(ctx) != nil {
		l.Release()
		return nil, ErrUnsafe
	}
	return l, nil
}
