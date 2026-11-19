//go:build linux

package ownerfence

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixtureCodec struct{}

func (fixtureCodec) SealOpaqueOwnerRecord(name string, raw []byte) (string, error) {
	h := hmac.New(sha256.New, []byte("synthetic-key"))
	h.Write([]byte(name))
	h.Write(raw)
	return base64.StdEncoding.EncodeToString(append(h.Sum(nil), raw...)), nil
}
func (fixtureCodec) OpenOpaqueOwnerRecord(name, sealed string) ([]byte, error) {
	raw, e := base64.StdEncoding.DecodeString(sealed)
	if e != nil || len(raw) < sha256.Size {
		return nil, ErrUnsafe
	}
	h := hmac.New(sha256.New, []byte("synthetic-key"))
	h.Write([]byte(name))
	h.Write(raw[sha256.Size:])
	if !hmac.Equal(raw[:sha256.Size], h.Sum(nil)) {
		return nil, ErrUnsafe
	}
	return raw[sha256.Size:], nil
}

func TestControlFencePersistsAndOrdersReadersWriters(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fence.Acquire(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = other.Acquire(ctx, true)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("writer bypassed held reader", err)
	}
	reader.Release()
	if err := reader.Check(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("released lease accepted", err)
	}
	writer, err := other.Acquire(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	writer.Release()
	if _, err = Create(root, dir, fixtureCodec{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal("existing fence recreated", err)
	}
}

func TestControlFenceRejectsReplacementAndPartialInitialization(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fence.Acquire(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = os.Rename(filepath.Join(dir, lockName), filepath.Join(dir, directory, "old-lock")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, lockName), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err = lease.Check(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced lock accepted", err)
	}
	if _, err = Open(root, dir, fixtureCodec{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced lock reopened", err)
	}
	if _, err = Create(root, dir, fixtureCodec{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal("nonempty registry reinitialized", err)
	}
}

func TestControlFenceRefusesMissingBindingDuringLease(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fence.Acquire(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = os.Remove(filepath.Join(dir, bindingName)); err != nil {
		t.Fatal(err)
	}
	if err = lease.Check(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("missing persistent binding accepted", err)
	}
	if _, err = Open(root, dir, fixtureCodec{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal("missing persistent binding reopened", err)
	}
}
