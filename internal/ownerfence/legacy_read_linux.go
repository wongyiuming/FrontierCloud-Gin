//go:build linux

package ownerfence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
)

// This isolated primitive is not installed by production startup. All legacy
// readers and relationship/identity writers must cooperate with this same
// fence; X-Accel streams, older processes, other hosts and storage rollback are
// not fenced by it. A persisted owner receipt and recovery anchor are needed
// before this state can authorize tree activation.
const legacyReadName = directory + "/.legacy-read-state"
const legacyReadEnrollmentName = directory + "/.legacy-read-enrolled"
const legacyReadStreamName = directory + "/.legacy-read-stream"

var legacyID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var legacyDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// MatchesRootAndCodec binds an in-process volume to this exact open directory
// and node vault. It does not attest other hosts or any persistent rollback.
func (f *Fence) MatchesRootAndCodec(root *os.Root, codec Codec) bool {
	if f == nil || root == nil || codec == nil || !sameDirectory(f.root, f.absolute) {
		return false
	}
	a, err := root.Stat(".")
	if err != nil {
		return false
	}
	b, err := f.root.Stat(".")
	if err != nil || !os.SameFile(a, b) {
		return false
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return false
	}
	defer clear(random)
	const domain = directory + "/.legacy-read-codec-check"
	sealed, err := f.codec.SealOpaqueOwnerRecord(domain, random)
	if err != nil {
		return false
	}
	opened, err := codec.OpenOpaqueOwnerRecord(domain, sealed)
	if err != nil {
		return false
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(random, opened) != 1 {
		return false
	}
	sealed, err = codec.SealOpaqueOwnerRecord(domain, random)
	if err != nil {
		return false
	}
	openedOther, err := f.codec.OpenOpaqueOwnerRecord(domain, sealed)
	if err != nil {
		return false
	}
	defer clear(openedOther)
	return subtle.ConstantTimeCompare(random, openedOther) == 1
}

type LegacyReadScope struct {
	MasterID            string `json:"master_id"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	OwnerBinding        string `json:"owner_binding"`
}

func (s LegacyReadScope) valid() bool {
	return legacyID.MatchString(s.MasterID) && legacyID.MatchString(s.OwnerID) && legacyID.MatchString(s.RelationshipID) && legacyDigest.MatchString(s.RelationshipBinding) && legacyDigest.MatchString(s.OwnerBinding)
}

type legacyReadRecord struct {
	Version      int             `json:"version"`
	Scope        LegacyReadScope `json:"scope"`
	FenceBinding string          `json:"fence_binding"`
	State        string          `json:"state"`
	OperationID  string          `json:"operation_id"`
	Challenge    string          `json:"challenge"`
	ExpiresAt    int64           `json:"expires_at"`
	StreamDevice uint64          `json:"stream_device"`
	StreamInode  uint64          `json:"stream_inode"`
	StreamID     string          `json:"stream_id"`
}

func (f *Fence) readLegacyState(ctx context.Context, lease *Lease, scope LegacyReadScope) (legacyReadRecord, error) {
	enrollment, err := f.readLegacyRecord(ctx, lease, scope, legacyReadEnrollmentName)
	if err != nil || enrollment.State != "active" || enrollment.OperationID != "" {
		return legacyReadRecord{}, ErrUnsafe
	}
	record, err := f.readLegacyRecord(ctx, lease, scope, legacyReadName)
	if err != nil || record.StreamDevice != enrollment.StreamDevice || record.StreamInode != enrollment.StreamInode || record.StreamID != enrollment.StreamID {
		return legacyReadRecord{}, ErrUnsafe
	}
	return record, nil
}

func (f *Fence) readLegacyRecord(ctx context.Context, lease *Lease, scope LegacyReadScope, name string) (legacyReadRecord, error) {
	var record legacyReadRecord
	if !scope.valid() || lease == nil || lease.Check(ctx) != nil {
		return record, ErrUnsafe
	}
	file, err := f.root.Open(name)
	if err != nil {
		return record, ErrUnsafe
	}
	defer file.Close()
	if _, _, err = fileIdentity(file); err != nil {
		return record, ErrUnsafe
	}
	opened, err := file.Stat()
	current, pathErr := f.root.Lstat(name)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return record, ErrUnsafe
	}
	sealed, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return record, ErrUnsafe
	}
	raw, err := f.codec.OpenOpaqueOwnerRecord(name, string(sealed))
	if err != nil {
		return record, ErrUnsafe
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return legacyReadRecord{}, ErrUnsafe
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return legacyReadRecord{}, ErrUnsafe
	}
	binding, err := lease.Binding(ctx)
	if err != nil || record.Version != 1 || record.Scope != scope || record.FenceBinding != binding || record.StreamInode == 0 || !legacyDigest.MatchString(record.StreamID) || record.State != "active" && record.State != "draining" && record.State != "revoked" || record.State == "active" && (record.OperationID != "" || record.Challenge != "" || record.ExpiresAt != 0) || record.State != "active" && (!legacyID.MatchString(record.OperationID) || !legacyDigest.MatchString(record.Challenge) || record.ExpiresAt <= 0) {
		return legacyReadRecord{}, ErrUnsafe
	}
	current, err = f.root.Lstat(name)
	if err != nil || !os.SameFile(opened, current) || lease.Check(ctx) != nil {
		return legacyReadRecord{}, ErrUnsafe
	}
	return record, nil
}

func (f *Fence) writeLegacyState(ctx context.Context, lease *Lease, record legacyReadRecord, recordName string, initial bool, syncDir func() error) error {
	if lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return ErrUnsafe
	}
	sealed, err := f.codec.SealOpaqueOwnerRecord(recordName, raw)
	clear(raw)
	if err != nil || len(sealed) == 0 || len(sealed) > 8192 {
		return ErrUnsafe
	}
	name := recordName
	if !initial {
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return ErrUnsafe
		}
		name += ".tmp-" + hex.EncodeToString(random)
	}
	file, err := f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnsafe
	}
	if !initial {
		defer f.root.Remove(name)
	}
	n, writeErr := file.WriteString(sealed)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(sealed) || syncErr != nil || closeErr != nil || lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	if !initial && f.root.Rename(name, recordName) != nil {
		return ErrUnsafe
	}
	if syncDir() != nil || lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	return nil
}

// InitializeLegacyReadState must only be used during an explicitly fenced,
// offline setup after old processes and X-Accel transfers have been drained.
// It creates the state exactly once and never repairs an existing record.
func (f *Fence) InitializeLegacyReadState(ctx context.Context, scope LegacyReadScope) error {
	if !scope.valid() {
		return ErrUnsafe
	}
	lease, err := f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	defer lease.Release()
	// Both must be absent before creating either one. In particular, a lost
	// enrollment must not be recreated around an old surviving state file.
	for _, name := range []string{legacyReadEnrollmentName, legacyReadName, legacyReadStreamName} {
		if _, e := f.root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
			return ErrUnsafe
		}
	}
	binding, err := lease.Binding(ctx)
	if err != nil {
		return ErrUnsafe
	}
	stream, err := f.root.OpenFile(legacyReadStreamName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return ErrUnsafe
	}
	defer stream.Close()
	device, inode, err := fileIdentity(stream)
	if err != nil {
		return ErrUnsafe
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return ErrUnsafe
	}
	defer clear(random)
	if n, e := stream.Write(random); e != nil || n != len(random) || stream.Sync() != nil || syncDirectory(f.root) != nil {
		return ErrUnsafe
	}
	record := legacyReadRecord{Version: 1, Scope: scope, FenceBinding: binding, State: "active", StreamDevice: device, StreamInode: inode, StreamID: hex.EncodeToString(random)}
	// The immutable enrollment is written first and deliberately retained on
	// partial failure. Missing state cannot then be silently initialized again.
	syncDir := func() error { return syncDirectory(f.root) }
	if err = f.writeLegacyState(ctx, lease, record, legacyReadEnrollmentName, true, syncDir); err != nil {
		return err
	}
	if err = f.writeLegacyState(ctx, lease, record, legacyReadName, true, syncDir); err != nil {
		return err
	}
	_, err = f.readLegacyState(ctx, lease, scope)
	return err
}

type legacyStreamLease struct {
	fence   *Fence
	file    *os.File
	release func()
}

func (f *Fence) acquireLegacyStream(ctx context.Context, exclusive bool) (*legacyStreamLease, error) {
	if f == nil || ctx == nil {
		return nil, ErrUnsafe
	}
	file, err := f.root.OpenFile(legacyReadStreamName, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	opened, statErr := file.Stat()
	current, pathErr := f.root.Lstat(legacyReadStreamName)
	_, _, identityErr := fileIdentity(file)
	if statErr != nil || pathErr != nil || identityErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || !sameDirectory(f.root, f.absolute) {
		file.Close()
		return nil, ErrUnsafe
	}
	release, err := filelease.Acquire(ctx, file, exclusive)
	if err != nil {
		return nil, err
	}
	return &legacyStreamLease{fence: f, file: file, release: release}, nil
}

func (l *legacyStreamLease) check(record legacyReadRecord) error {
	if l == nil || l.release == nil || !sameDirectory(l.fence.root, l.fence.absolute) {
		return ErrUnsafe
	}
	device, inode, err := fileIdentity(l.file)
	if err != nil || device != record.StreamDevice || inode != record.StreamInode {
		return ErrUnsafe
	}
	opened, err := l.file.Stat()
	current, pathErr := l.fence.root.Lstat(legacyReadStreamName)
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Size() != 32 {
		return ErrUnsafe
	}
	id := make([]byte, 32)
	defer clear(id)
	if _, err = l.file.ReadAt(id, 0); err != nil || hex.EncodeToString(id) != record.StreamID {
		return ErrUnsafe
	}
	return nil
}

func (l *legacyStreamLease) Release() {
	if l != nil && l.release != nil {
		l.release()
		l.release = nil
	}
}

// LegacyReadLease retains only the shared stream lock during an admitted Go
// stream. Its owner lock is short-lived and used solely for admission.
type LegacyReadLease struct {
	mu     sync.Mutex
	fence  *Fence
	lease  *legacyStreamLease
	scope  LegacyReadScope
	users  int
	closed bool
}

func (l *LegacyReadLease) begin() (*legacyStreamLease, error) {
	if l == nil {
		return nil, ErrUnsafe
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fence == nil || l.lease == nil || l.closed {
		return nil, ErrUnsafe
	}
	l.users++
	return l.lease, nil
}

func (l *LegacyReadLease) end() bool {
	l.mu.Lock()
	l.users--
	closed := l.closed
	var release *legacyStreamLease
	if closed && l.users == 0 {
		release, l.lease = l.lease, nil
	}
	l.mu.Unlock()
	if release != nil {
		release.Release()
	}
	return closed
}

func (l *LegacyReadLease) Check(ctx context.Context) (result error) {
	lease, err := l.begin()
	if err != nil {
		return ErrUnsafe
	}
	defer func() {
		if l.end() {
			result = ErrUnsafe
		}
	}()
	owner, err := l.fence.Acquire(ctx, false)
	if err != nil {
		return ErrUnsafe
	}
	defer owner.Release()
	record, err := l.fence.readLegacyState(ctx, owner, l.scope)
	if err != nil || record.State != "active" || lease.check(record) != nil {
		return ErrUnsafe
	}
	return nil
}

// WithStream holds the lock for the complete synchronous callback, including
// closing the Go stream. authorize runs under a short shared owner lock;
// after it succeeds the read is admitted and may drain after revocation starts.
// Release during the callback prevents new uses but defers the OS unlock until
// it returns. The callback must not hand work to an unjoined goroutine.
func (l *LegacyReadLease) WithStream(ctx context.Context, authorize func(context.Context, *Lease) error, stream func(context.Context) error) (result error) {
	if ctx == nil || authorize == nil || stream == nil {
		return ErrUnsafe
	}
	lease, err := l.begin()
	if err != nil {
		return ErrUnsafe
	}
	defer func() {
		if l.end() && result == nil {
			result = ErrUnsafe
		}
	}()
	owner, err := l.fence.Acquire(ctx, false)
	if err != nil {
		return ErrUnsafe
	}
	defer func() {
		if owner != nil {
			owner.Release()
		}
	}()
	record, err := l.fence.readLegacyState(ctx, owner, l.scope)
	if err != nil || record.State != "active" || lease.check(record) != nil || authorize(ctx, owner) != nil || owner.Check(ctx) != nil {
		return ErrUnsafe
	}
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed || ctx.Err() != nil {
		return ErrUnsafe
	}
	owner.Release()
	owner = nil
	return stream(ctx)
}

func (l *LegacyReadLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.closed = true
	var release *legacyStreamLease
	if l.users == 0 {
		release, l.lease = l.lease, nil
	}
	l.mu.Unlock()
	if release != nil {
		release.Release()
	}
}

// AcquireLegacyRead takes the stream lock before the short owner lock. It
// rejects draining/revoked state and retains the stream lock until Release.
func (f *Fence) AcquireLegacyRead(ctx context.Context, scope LegacyReadScope) (*LegacyReadLease, error) {
	lease, err := f.acquireLegacyStream(ctx, false)
	if err != nil {
		return nil, err
	}
	owner, err := f.Acquire(ctx, false)
	if err != nil {
		lease.Release()
		return nil, err
	}
	record, err := f.readLegacyState(ctx, owner, scope)
	if err != nil || record.State != "active" || lease.check(record) != nil {
		owner.Release()
		lease.Release()
		return nil, ErrUnsafe
	}
	owner.Release()
	return &LegacyReadLease{fence: f, lease: lease, scope: scope}, nil
}

// RevokeLegacyRead first persists draining under the short owner lock, then
// waits for the independent stream lock, and finally persists revoked and
// commits under stream-exclusive -> owner-exclusive. authorize authenticates
// the Master in phase one; commit must revalidate identity, relationship and
// marker before signing. Callbacks may not do network I/O or reacquire either
// lock. A returned error must discard any partially prepared receipt.
func (f *Fence) RevokeLegacyRead(ctx context.Context, scope LegacyReadScope, operationID, challenge string, expiresAt int64, authorize, commit func(context.Context, *Lease) error) error {
	return f.RevokeLegacyReadChecked(ctx, scope, operationID, challenge, expiresAt, authorize, authorize, commit)
}

// RevokeLegacyReadChecked separates nonce-consuming authentication from the
// repeatable identity and marker check required after stream drainage.
func (f *Fence) RevokeLegacyReadChecked(ctx context.Context, scope LegacyReadScope, operationID, challenge string, expiresAt int64, authorize, recheck, commit func(context.Context, *Lease) error) error {
	if ctx == nil || expiresAt <= time.Now().Unix() || expiresAt > time.Now().Unix()+300 {
		return ErrUnsafe
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(expiresAt, 0))
	defer cancel()
	return f.revokeLegacyReadChecked(bounded, scope, operationID, challenge, expiresAt, authorize, recheck, commit, func() error { return syncDirectory(f.root) })
}

func (f *Fence) revokeLegacyRead(ctx context.Context, scope LegacyReadScope, operationID, challenge string, expiresAt int64, authorize, commit func(context.Context, *Lease) error, syncDir func() error) error {
	return f.revokeLegacyReadChecked(ctx, scope, operationID, challenge, expiresAt, authorize, authorize, commit, syncDir)
}

func (f *Fence) revokeLegacyReadChecked(ctx context.Context, scope LegacyReadScope, operationID, challenge string, expiresAt int64, authorize, recheck, commit func(context.Context, *Lease) error, syncDir func() error) error {
	if ctx == nil || expiresAt <= time.Now().Unix() || !scope.valid() || !legacyID.MatchString(operationID) || !legacyDigest.MatchString(challenge) || authorize == nil || recheck == nil || commit == nil || syncDir == nil {
		return ErrUnsafe
	}
	lease, err := f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	phaseOne := func() error {
		defer lease.Release()
		if authorize(ctx, lease) != nil || lease.Check(ctx) != nil || time.Now().Unix() >= expiresAt {
			return ErrUnsafe
		}
		record, err := f.readLegacyState(ctx, lease, scope)
		if err != nil {
			return ErrUnsafe
		}
		if record.State == "active" {
			record.State, record.OperationID, record.Challenge, record.ExpiresAt = "draining", operationID, challenge, expiresAt
			if f.writeLegacyState(ctx, lease, record, legacyReadName, false, syncDir) != nil {
				return ErrUnsafe
			}
		} else if record.OperationID != operationID || record.Challenge != challenge || record.ExpiresAt != expiresAt {
			return ErrUnsafe
		}
		// A previous rename may have succeeded while fsync failed.
		if syncDir() != nil || lease.Check(ctx) != nil {
			return ErrUnsafe
		}
		confirmed, err := f.readLegacyState(ctx, lease, scope)
		if err != nil || confirmed.State != "draining" && confirmed.State != "revoked" || confirmed.OperationID != operationID || confirmed.Challenge != challenge || confirmed.ExpiresAt != expiresAt || time.Now().Unix() >= expiresAt {
			return ErrUnsafe
		}
		return nil
	}
	if err = phaseOne(); err != nil {
		return err
	}
	stream, err := f.acquireLegacyStream(ctx, true)
	if err != nil {
		return err
	}
	defer stream.Release()
	lease, err = f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	defer lease.Release()
	record, err := f.readLegacyState(ctx, lease, scope)
	if err != nil || time.Now().Unix() >= expiresAt || record.OperationID != operationID || record.Challenge != challenge || record.ExpiresAt != expiresAt || record.State != "draining" && record.State != "revoked" || stream.check(record) != nil || recheck(ctx, lease) != nil || lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	if record.State == "draining" {
		if time.Now().Unix() >= expiresAt || ctx.Err() != nil {
			return ErrUnsafe
		}
		record.State = "revoked"
		if f.writeLegacyState(ctx, lease, record, legacyReadName, false, syncDir) != nil {
			return ErrUnsafe
		}
	}
	if syncDir() != nil || lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	confirmed, err := f.readLegacyState(ctx, lease, scope)
	if err != nil || time.Now().Unix() >= expiresAt || confirmed.State != "revoked" || confirmed.OperationID != operationID || confirmed.Challenge != challenge || confirmed.ExpiresAt != expiresAt || stream.check(confirmed) != nil {
		return ErrUnsafe
	}
	if commit(ctx, lease) != nil || lease.Check(ctx) != nil {
		return ErrUnsafe
	}
	confirmed, err = f.readLegacyState(ctx, lease, scope)
	if err != nil || time.Now().Unix() >= expiresAt || confirmed.State != "revoked" || confirmed.OperationID != operationID || confirmed.Challenge != challenge || confirmed.ExpiresAt != expiresAt || stream.check(confirmed) != nil {
		return ErrUnsafe
	}
	return lease.Check(ctx)
}

// ResumeLegacyRead continues only an already-persisted operation. The fresh
// deadline belongs to a separately authenticated request; it never changes
// the original operation or permits an active state to be revoked implicitly.
func (f *Fence) ResumeLegacyRead(ctx context.Context, scope LegacyReadScope, operationID, challenge string, originalExpiresAt, expiresAt int64, authorize, recheck, commit func(context.Context, *Lease) error) error {
	if ctx == nil || !scope.valid() || !legacyID.MatchString(operationID) || !legacyDigest.MatchString(challenge) || originalExpiresAt <= 0 || expiresAt <= time.Now().Unix() || expiresAt > time.Now().Unix()+300 || authorize == nil || recheck == nil || commit == nil {
		return ErrUnsafe
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(expiresAt, 0))
	defer cancel()
	owner, err := f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	check := func(record legacyReadRecord) bool {
		return record.OperationID == operationID && record.Challenge == challenge && record.ExpiresAt == originalExpiresAt && (record.State == "draining" || record.State == "revoked")
	}
	err = func() error {
		defer owner.Release()
		if authorize(ctx, owner) != nil || owner.Check(ctx) != nil || time.Now().Unix() >= expiresAt {
			return ErrUnsafe
		}
		record, e := f.readLegacyState(ctx, owner, scope)
		if e != nil || !check(record) || syncDirectory(f.root) != nil {
			return ErrUnsafe
		}
		return owner.Check(ctx)
	}()
	if err != nil {
		return err
	}
	stream, err := f.acquireLegacyStream(ctx, true)
	if err != nil {
		return err
	}
	defer stream.Release()
	owner, err = f.Acquire(ctx, true)
	if err != nil {
		return err
	}
	defer owner.Release()
	record, err := f.readLegacyState(ctx, owner, scope)
	if err != nil || !check(record) || time.Now().Unix() >= expiresAt || stream.check(record) != nil || recheck(ctx, owner) != nil || owner.Check(ctx) != nil {
		return ErrUnsafe
	}
	if record.State == "draining" {
		if time.Now().Unix() >= expiresAt || ctx.Err() != nil {
			return ErrUnsafe
		}
		record.State = "revoked"
		if f.writeLegacyState(ctx, owner, record, legacyReadName, false, func() error { return syncDirectory(f.root) }) != nil {
			return ErrUnsafe
		}
	}
	if syncDirectory(f.root) != nil || owner.Check(ctx) != nil {
		return ErrUnsafe
	}
	record, err = f.readLegacyState(ctx, owner, scope)
	if err != nil || !check(record) || record.State != "revoked" || time.Now().Unix() >= expiresAt || stream.check(record) != nil {
		return ErrUnsafe
	}
	if commit(ctx, owner) != nil || owner.Check(ctx) != nil {
		return ErrUnsafe
	}
	record, err = f.readLegacyState(ctx, owner, scope)
	if err != nil || !check(record) || record.State != "revoked" || time.Now().Unix() >= expiresAt || stream.check(record) != nil {
		return ErrUnsafe
	}
	return owner.Check(ctx)
}

// ObserveLegacyReadStatus never changes the one-way state. A draining status
// is only an observation; revoked is signed only after reacquiring the stream
// lock exclusively and verifying its identity under the owner lock. A fresh
// request challenge and an external Master intent must be checked by callers.
func (f *Fence) ObserveLegacyReadStatus(ctx context.Context, scope LegacyReadScope, operationID, challenge string, originalExpiresAt int64, authorize func(context.Context, *Lease) error, commit func(context.Context, *Lease, string) error) error {
	if originalExpiresAt <= 0 || !scope.valid() || !legacyID.MatchString(operationID) || !legacyDigest.MatchString(challenge) || authorize == nil || commit == nil {
		return ErrUnsafe
	}
	owner, err := f.Acquire(ctx, false)
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			owner.Release()
		}
	}()
	if authorize(ctx, owner) != nil || owner.Check(ctx) != nil {
		return ErrUnsafe
	}
	record, err := f.readLegacyState(ctx, owner, scope)
	if err != nil || record.State == "active" || record.OperationID != operationID || record.Challenge != challenge || record.ExpiresAt != originalExpiresAt {
		return ErrUnsafe
	}
	if record.State == "draining" {
		// This does not wait for active streams and is never a drain receipt.
		file, err := f.root.OpenFile(legacyReadStreamName, os.O_RDWR, 0)
		if err != nil {
			return ErrUnsafe
		}
		defer file.Close()
		stream := &legacyStreamLease{fence: f, file: file, release: func() {}}
		if stream.check(record) != nil || syncDirectory(f.root) != nil || owner.Check(ctx) != nil || commit(ctx, owner, "draining") != nil {
			return ErrUnsafe
		}
		confirmed, err := f.readLegacyState(ctx, owner, scope)
		if err != nil || confirmed.State != "draining" || confirmed.OperationID != operationID || confirmed.Challenge != challenge || confirmed.ExpiresAt != originalExpiresAt || stream.check(confirmed) != nil {
			return ErrUnsafe
		}
		return owner.Check(ctx)
	}
	owner.Release()
	owned = false
	stream, err := f.acquireLegacyStream(ctx, true)
	if err != nil {
		return err
	}
	defer stream.Release()
	owner, err = f.Acquire(ctx, false)
	if err != nil {
		return err
	}
	owned = true
	record, err = f.readLegacyState(ctx, owner, scope)
	if err != nil || record.State != "revoked" || record.OperationID != operationID || record.Challenge != challenge || record.ExpiresAt != originalExpiresAt || stream.check(record) != nil || syncDirectory(f.root) != nil || owner.Check(ctx) != nil || commit(ctx, owner, "revoked") != nil {
		return ErrUnsafe
	}
	confirmed, err := f.readLegacyState(ctx, owner, scope)
	if err != nil || confirmed.State != "revoked" || confirmed.OperationID != operationID || confirmed.Challenge != challenge || confirmed.ExpiresAt != originalExpiresAt || stream.check(confirmed) != nil {
		return ErrUnsafe
	}
	return owner.Check(ctx)
}
