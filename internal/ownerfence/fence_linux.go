//go:build linux

// Package ownerfence contains the local, cooperative owner-control fence.
// It is not installed in the product and does not fence other hosts or old
// writers. Real destructive operations must remain disabled until every local
// identity/relationship writer and owner operation holds this same fence.
package ownerfence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
)

const directory = ".opaque-aliases"
const lockName = directory + "/.owner-control-lock"
const bindingName = directory + "/.owner-control-binding"

var ErrUnsafe = errors.New("owner control fence unavailable or changed")

// Codec must use the node's durable vault and bind ciphertext to the name.
type Codec interface {
	SealOpaqueOwnerRecord(string, []byte) (string, error)
	OpenOpaqueOwnerRecord(string, string) ([]byte, error)
}

type binding struct {
	Version int    `json:"version"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	ID      string `json:"id"`
}

type Fence struct {
	root     *os.Root
	absolute string
	codec    Codec
	binding  binding
}

type Lease struct {
	mu      sync.Mutex
	fence   *Fence
	file    *os.File
	release func()
}

func sameDirectory(root *os.Root, absolute string) bool {
	if root == nil || !filepath.IsAbs(absolute) || filepath.Clean(absolute) != absolute {
		return false
	}
	pathInfo, e := os.Lstat(absolute)
	rootInfo, f := root.Stat(".")
	if e != nil || f != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, rootInfo) {
		return false
	}
	dirInfo, e := root.Lstat(directory)
	if e != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return false
	}
	st, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	dir, e := root.Open(directory)
	if e != nil {
		return false
	}
	defer dir.Close()
	opened, e := dir.Stat()
	return e == nil && os.SameFile(dirInfo, opened)
}

func fileIdentity(file *os.File) (uint64, uint64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return 0, 0, ErrUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return 0, 0, ErrUnsafe
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func syncDirectory(root *os.Root) error {
	dir, err := root.Open(directory)
	if err != nil {
		return ErrUnsafe
	}
	defer dir.Close()
	return dir.Sync()
}

// Create is only for a new, empty registry while the node is stopped. A failed
// partial initialization is retained and Open cannot silently recreate it.
func Create(root *os.Root, absolute string, codec Codec) (*Fence, error) {
	if codec == nil || !sameDirectory(root, absolute) {
		return nil, ErrUnsafe
	}
	dir, err := root.Open(directory)
	if err != nil {
		return nil, ErrUnsafe
	}
	names, err := dir.Readdirnames(1)
	dir.Close()
	if err != io.EOF || len(names) != 0 {
		return nil, ErrUnsafe
	}
	file, err := root.OpenFile(lockName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrUnsafe
	}
	defer file.Close()
	device, inode, err := fileIdentity(file)
	if err != nil {
		return nil, ErrUnsafe
	}
	id := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, id); err != nil {
		return nil, ErrUnsafe
	}
	defer clear(id)
	if _, err = file.Write(id); err != nil || file.Sync() != nil {
		return nil, ErrUnsafe
	}
	want := binding{1, device, inode, hex.EncodeToString(id)}
	raw, err := json.Marshal(want)
	if err != nil {
		return nil, ErrUnsafe
	}
	sealed, err := codec.SealOpaqueOwnerRecord(bindingName, raw)
	clear(raw)
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return nil, ErrUnsafe
	}
	meta, err := root.OpenFile(bindingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrUnsafe
	}
	n, writeErr := meta.WriteString(sealed)
	syncErr := meta.Sync()
	closeErr := meta.Close()
	if writeErr != nil || n != len(sealed) || syncErr != nil || closeErr != nil || syncDirectory(root) != nil {
		return nil, ErrUnsafe
	}
	return Open(root, absolute, codec)
}

// Open only accepts a previously authenticated binding. The caller must keep
// root and codec alive and ensure this same root is used by all processes.
func Open(root *os.Root, absolute string, codec Codec) (*Fence, error) {
	if codec == nil || !sameDirectory(root, absolute) {
		return nil, ErrUnsafe
	}
	meta, err := root.Open(bindingName)
	if err != nil {
		return nil, ErrUnsafe
	}
	defer meta.Close()
	if _, _, err = fileIdentity(meta); err != nil {
		return nil, ErrUnsafe
	}
	current, err := root.Lstat(bindingName)
	opened, statErr := meta.Stat()
	if err != nil || statErr != nil || !os.SameFile(current, opened) {
		return nil, ErrUnsafe
	}
	sealed, err := io.ReadAll(io.LimitReader(meta, 8193))
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return nil, ErrUnsafe
	}
	raw, err := codec.OpenOpaqueOwnerRecord(bindingName, string(sealed))
	if err != nil {
		return nil, ErrUnsafe
	}
	defer clear(raw)
	var record binding
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&record) != nil || dec.Decode(new(any)) != io.EOF || record.Version != 1 || record.Inode == 0 || len(record.ID) != 64 {
		return nil, ErrUnsafe
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrUnsafe
	}
	if _, err = hex.DecodeString(record.ID); err != nil {
		return nil, ErrUnsafe
	}
	f := &Fence{root: root, absolute: absolute, codec: codec, binding: record}
	file, err := root.OpenFile(lockName, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	defer file.Close()
	if f.check(file) != nil {
		return nil, ErrUnsafe
	}
	return f, nil
}

func (f *Fence) check(file *os.File) error {
	if f == nil || !sameDirectory(f.root, f.absolute) {
		return ErrUnsafe
	}
	meta, err := f.root.Open(bindingName)
	if err != nil {
		return ErrUnsafe
	}
	defer meta.Close()
	if _, _, err = fileIdentity(meta); err != nil {
		return ErrUnsafe
	}
	metaOpened, err := meta.Stat()
	metaCurrent, currentErr := f.root.Lstat(bindingName)
	if err != nil || currentErr != nil || !os.SameFile(metaOpened, metaCurrent) {
		return ErrUnsafe
	}
	sealed, err := io.ReadAll(io.LimitReader(meta, 8193))
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return ErrUnsafe
	}
	raw, err := f.codec.OpenOpaqueOwnerRecord(bindingName, string(sealed))
	if err != nil {
		return ErrUnsafe
	}
	defer clear(raw)
	want, err := json.Marshal(f.binding)
	if err != nil || subtle.ConstantTimeCompare(raw, want) != 1 {
		return ErrUnsafe
	}
	metaCurrent, err = f.root.Lstat(bindingName)
	if err != nil || !os.SameFile(metaOpened, metaCurrent) {
		return ErrUnsafe
	}
	device, inode, err := fileIdentity(file)
	if err != nil || device != f.binding.Device || inode != f.binding.Inode {
		return ErrUnsafe
	}
	opened, err := file.Stat()
	current, e := f.root.Lstat(lockName)
	if err != nil || e != nil || !os.SameFile(opened, current) || opened.Size() != 32 {
		return ErrUnsafe
	}
	id := make([]byte, 32)
	defer clear(id)
	if _, err = file.ReadAt(id, 0); err != nil || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(id)), []byte(f.binding.ID)) != 1 {
		return ErrUnsafe
	}
	return nil
}

// Acquire returns a cooperative local lease. Check must be called immediately
// before irreversible work and before acknowledging; it is not rollback proof.
func (f *Fence) Acquire(ctx context.Context, exclusive bool) (*Lease, error) {
	if f == nil || ctx == nil {
		return nil, ErrUnsafe
	}
	file, err := f.root.OpenFile(lockName, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	if f.check(file) != nil {
		file.Close()
		return nil, ErrUnsafe
	}
	release, err := filelease.Acquire(ctx, file, exclusive)
	if err != nil {
		return nil, err
	}
	if f.check(file) != nil {
		release()
		return nil, ErrUnsafe
	}
	return &Lease{fence: f, file: file, release: release}, nil
}

func (l *Lease) Check(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrUnsafe
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.release == nil || ctx.Err() != nil || l.fence.check(l.file) != nil {
		return ErrUnsafe
	}
	return nil
}

// Binding is a public digest of the authenticated local lock identity, not a
// key or authorization. It is valid only while this lease is held.
func (l *Lease) Binding(ctx context.Context) (string, error) {
	if l == nil || ctx == nil {
		return "", ErrUnsafe
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.release == nil || ctx.Err() != nil || l.fence.check(l.file) != nil {
		return "", ErrUnsafe
	}
	raw, err := json.Marshal(l.fence.binding)
	if err != nil {
		return "", ErrUnsafe
	}
	sum := sha256.Sum256(append([]byte("frontiercloud:owner-control-binding:v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.release != nil {
		l.release()
		l.release = nil
	}
}
