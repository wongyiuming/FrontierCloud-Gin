// Package migrationdata owns private, bounded and restartable byte staging.
// Services authenticate task commands and reserve quota before using this
// package; it does not publish business owners, initialize identities or delete
// source resources. Its files are excluded from ordinary media discovery.
package migrationdata

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const ChunkBytes = 256 << 10
const journalLimit = 16 << 10

var ErrState = errors.New("migration byte checkpoint conflicts with task or disk state")
var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Spec struct {
	TaskID        string                `json:"task_id"`
	MasterID      string                `json:"master_id"`
	SourceID      string                `json:"source_id"`
	TargetID      string                `json:"target_id"`
	LogicalID     string                `json:"logical_id"`
	ObjectID      string                `json:"object_id"`
	Resource      string                `json:"resource_kind"`
	TargetPath    string                `json:"target_path"`
	SourceVersion string                `json:"source_version"`
	Bytes         int64                 `json:"size_bytes"`
	SHA256        string                `json:"sha256"`
	Encryption    *mediacrypto.Metadata `json:"encryption,omitempty"`
	Recording     *store.RecordingProof `json:"recording_binding,omitempty"`
}
type Checkpoint struct {
	Version   int    `json:"version"`
	Spec      Spec   `json:"binding"`
	Offset    int64  `json:"offset"`
	PrefixSHA string `json:"prefix_sha256"`
	HashState []byte `json:"-"`
	State     string `json:"state"`
}
type journalRecord struct {
	Checkpoint
	SavedHashState []byte `json:"hash_state"`
}
type Receiver struct {
	root           *os.Root
	node, resource string
}

// Status reports persisted transfer facts. It does not upgrade them to disk
// verification; publication still requires Verify and VerifiedReader.
func (r *Receiver) Status(ctx context.Context, s Spec) (Checkpoint, error) {
	if !r.valid(s) {
		return Checkpoint{}, ErrState
	}
	if e := ctx.Err(); e != nil {
		return Checkpoint{}, e
	}
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	if _, e = resumeHash(c); e != nil {
		return c, e
	}
	return c, nil
}

func New(root *os.Root, node, resource string) (*Receiver, error) {
	if root == nil || !identifier.MatchString(node) || (resource != "media" && resource != "recording") {
		return nil, ErrState
	}
	return &Receiver{root: root, node: node, resource: resource}, nil
}
func (r *Receiver) valid(s Spec) bool {
	if !utf8.ValidString(s.TargetPath) {
		return false
	}
	if !identifier.MatchString(s.TaskID) || !identifier.MatchString(s.MasterID) || !identifier.MatchString(s.SourceID) || s.TargetID != r.node || s.SourceID == s.TargetID || s.MasterID == s.TargetID || s.MasterID == s.SourceID || s.Resource != r.resource || !digest.MatchString(s.SourceVersion) || !digest.MatchString(s.SHA256) || s.Bytes <= 0 || s.Bytes > 10*store.GiB || path.Clean(s.TargetPath) != s.TargetPath || strings.HasPrefix(s.TargetPath, "/") || strings.ContainsAny(s.TargetPath, "\\\x00:") || len(s.TargetPath) > 4096 {
		return false
	}
	for _, p := range strings.Split(s.TargetPath, "/") {
		if p == "" || strings.HasPrefix(p, ".") {
			return false
		}
	}
	if s.Resource == "media" && !digest.MatchString(s.LogicalID) || s.Resource == "recording" && !identifier.MatchString(s.LogicalID) {
		return false
	}
	if s.Resource == "media" && !digest.MatchString(s.ObjectID) || s.Resource == "recording" && (!identifier.MatchString(s.ObjectID) || s.Bytes > store.MaxRecordingBytes) {
		return false
	}
	return s.Encryption == nil || s.Resource == "media" && s.Encryption.Validate() == nil && s.Encryption.CiphertextSize == s.Bytes
}
func names(s Spec) (string, string, string) {
	sum := sha256.Sum256([]byte(s.Resource + ":" + s.LogicalID))
	base := ".migration-data-" + s.TaskID + "-" + hex.EncodeToString(sum[:])
	return base + ".part", base + ".json", base + ".lock"
}
func (r *Receiver) private(name string, flags int) (*os.File, error) {
	if info, e := r.root.Lstat(name); e == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrState
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	f, e := r.root.OpenFile(name, flags, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	named, ne := r.root.Lstat(name)
	if e != nil || ne != nil || !info.Mode().IsRegular() || !os.SameFile(info, named) || named.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}
func (r *Receiver) lock(ctx context.Context, s Spec) (func(), error) {
	_, _, name := names(s)
	f, e := r.private(name, os.O_CREATE|os.O_RDWR)
	if e != nil {
		return nil, e
	}
	return filelease.Acquire(ctx, f, true)
}
func bindingEqual(a, b Spec) bool {
	aa, e := json.Marshal(a)
	bb, f := json.Marshal(b)
	return e == nil && f == nil && string(aa) == string(bb)
}
func (r *Receiver) load(s Spec) (Checkpoint, error) {
	_, name, _ := names(s)
	f, e := r.private(name, os.O_RDONLY)
	if e != nil {
		return Checkpoint{}, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if e != nil || len(raw) > journalLimit {
		return Checkpoint{}, ErrState
	}
	var saved journalRecord
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&saved) != nil {
		return Checkpoint{}, ErrState
	}
	c := saved.Checkpoint
	c.HashState = saved.SavedHashState
	if c.Version != 1 || !bindingEqual(c.Spec, s) || c.Offset < 0 || c.Offset > s.Bytes || !digest.MatchString(c.PrefixSHA) || len(c.HashState) > 512 || (c.State != "receiving" && c.State != "received" && c.State != "verified" && c.State != "publishing" && c.State != "published" && c.State != "failed" && c.State != "aborting" && c.State != "aborted") {
		return c, ErrState
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, ErrState
	}
	return c, nil
}
func (r *Receiver) save(c Checkpoint) error {
	_, name, _ := names(c.Spec)
	temporary := name + ".tmp"
	// Only a task's private temporary journal may be reclaimed under its blob
	// lease. Never adopt a symlink or remove a media/recording business path.
	if old, e := r.private(temporary, os.O_RDONLY); e == nil {
		old.Close()
		if e = r.root.Remove(temporary); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := r.private(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(journalRecord{Checkpoint: c, SavedHashState: c.HashState})
	if e == nil {
		_, e = f.Write(append(raw, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = r.root.Rename(temporary, name); e != nil {
		return e
	}
	return fsutil.SyncDirectory(r.root, ".")
}
func hashCheckpoint(c *Checkpoint, h hash.Hash) error {
	state, e := h.(encoding.BinaryMarshaler).MarshalBinary()
	if e != nil {
		return e
	}
	c.HashState = state
	c.PrefixSHA = hex.EncodeToString(h.Sum(nil))
	return nil
}
func resumeHash(c Checkpoint) (hash.Hash, error) {
	h := sha256.New()
	if h.(encoding.BinaryUnmarshaler).UnmarshalBinary(c.HashState) != nil || hex.EncodeToString(h.Sum(nil)) != c.PrefixSHA {
		return nil, ErrState
	}
	return h, nil
}

// Begin is idempotent only for an identical task/object/version binding. A
// crash before a checkpoint is written leaves private material for inspection.
func (r *Receiver) Begin(ctx context.Context, s Spec) (Checkpoint, error) {
	if !r.valid(s) {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	c, e := r.load(s)
	if e == nil {
		if c.State == "aborted" || c.State == "aborting" || c.State == "failed" {
			return c, ErrState
		}
		return r.inspect(ctx, c)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return c, e
	}
	name, _, _ := names(s)
	f, e := r.private(name, os.O_CREATE|os.O_EXCL|os.O_RDWR)
	if errors.Is(e, os.ErrExist) {
		// The initial empty private file can outlive a crash before its first
		// journal. Nonempty material without a checkpoint is never adopted.
		f, e = r.private(name, os.O_RDWR)
		if e == nil {
			info, se := f.Stat()
			if se != nil || info.Size() != 0 {
				f.Close()
				return c, ErrState
			}
		}
	}
	if e != nil {
		return c, e
	}
	e = errors.Join(f.Sync(), f.Close())
	if e != nil {
		return c, e
	}
	c = Checkpoint{Version: 1, Spec: s, State: "receiving"}
	if e = hashCheckpoint(&c, sha256.New()); e != nil {
		return c, e
	}
	return c, r.save(c)
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func (r *Receiver) inspect(ctx context.Context, c Checkpoint) (Checkpoint, error) {
	name, _, _ := names(c.Spec)
	f, e := r.private(name, os.O_RDONLY)
	if e != nil {
		return c, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() < c.Offset {
		return c, ErrState
	}
	// Reopening checks the persisted prefix against actual disk bytes, never
	// merely a length. A crash tail is discarded only after this proof.
	h := sha256.New()
	n, e := io.CopyBuffer(h, contextReader{ctx, io.NewSectionReader(f, 0, c.Offset)}, make([]byte, 64<<10))
	if e != nil {
		return c, e
	}
	if n != c.Offset || hex.EncodeToString(h.Sum(nil)) != c.PrefixSHA {
		return c, ErrState
	}
	if (c.State == "received" || c.State == "verified" || c.State == "publishing" || c.State == "published") && (c.Offset != c.Spec.Bytes || info.Size() != c.Offset || c.PrefixSHA != c.Spec.SHA256) {
		return c, ErrState
	}
	return c, nil
}

// Append accepts one fixed bounded chunk. Duplicate requests compare actual
// disk bytes. There is no quota refund, publication or owner switch here.
func (r *Receiver) Append(ctx context.Context, s Spec, offset int64, data []byte, chunkSHA string) (Checkpoint, error) {
	return r.AppendAdmitted(ctx, s, offset, data, chunkSHA, nil)
}

// Admission runs inside the private blob lease. Node services use it to check
// the durable task/runner epoch again after waiting, rather than relying on
// authentication performed before a potentially blocking lease acquisition.
func (r *Receiver) AppendAdmitted(ctx context.Context, s Spec, offset int64, data []byte, chunkSHA string, admission func() error) (Checkpoint, error) {
	if !r.valid(s) || len(data) == 0 || len(data) > ChunkBytes || offset < 0 || offset%ChunkBytes != 0 || offset > s.Bytes-int64(len(data)) || len(data) != ChunkBytes && offset+int64(len(data)) != s.Bytes {
		return Checkpoint{}, ErrState
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != chunkSHA {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	if admission != nil {
		if e = admission(); e != nil {
			return Checkpoint{}, e
		}
	}
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	if c.State == "aborted" || c.State == "aborting" || c.State == "failed" {
		return c, ErrState
	}
	name, _, _ := names(s)
	f, e := r.private(name, os.O_RDWR)
	if e != nil {
		return c, e
	}
	defer f.Close()
	if offset < c.Offset {
		if offset+int64(len(data)) > c.Offset {
			return c, ErrState
		}
		disk := make([]byte, len(data))
		if _, e = f.ReadAt(disk, offset); e != nil {
			return c, e
		}
		actual := sha256.Sum256(disk)
		if actual != sum {
			return c, ErrState
		}
		return c, nil
	}
	if offset != c.Offset || c.State != "receiving" {
		return c, ErrState
	}
	h, e := resumeHash(c)
	if e != nil {
		return c, e
	}
	info, e := f.Stat()
	if e != nil || info.Size() < c.Offset {
		return c, ErrState
	}
	if info.Size() > c.Offset {
		if _, e = r.inspect(ctx, c); e != nil {
			return c, e
		}
		if e = f.Truncate(c.Offset); e != nil {
			return c, e
		}
	}
	if e = ctx.Err(); e != nil {
		return c, e
	}
	n, e := f.WriteAt(data, offset)
	if e != nil {
		return c, e
	}
	if n != len(data) {
		return c, io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return c, e
	}
	disk := make([]byte, len(data))
	if _, e = f.ReadAt(disk, offset); e != nil {
		return c, e
	}
	actual := sha256.Sum256(disk)
	if actual != sum {
		return c, ErrState
	}
	h.Write(disk)
	c.Offset += int64(len(disk))
	if e = hashCheckpoint(&c, h); e != nil {
		return c, e
	}
	if c.Offset == s.Bytes {
		if c.PrefixSHA != s.SHA256 {
			c.State = "failed"
			return c, errors.Join(ErrState, r.save(c))
		}
		c.State = "received"
	}
	return c, r.save(c)
}

// Abort removes precisely one private staging artifact after recording intent.
// Admission must prove it is unpublished/cancellable. It never follows a
// business path and never refunds capacity; the service reconciles that only
// after authenticating this completed cleanup receipt.
func (r *Receiver) Abort(ctx context.Context, s Spec, admission func() error) (Checkpoint, error) {
	if !r.valid(s) || admission == nil {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	if e = admission(); e != nil {
		return Checkpoint{}, e
	}
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	if c.State == "aborted" {
		return c, nil
	}
	if c.State == "publishing" || c.State == "published" {
		return c, ErrState
	}
	c.State = "aborting"
	if e = r.save(c); e != nil {
		return c, e
	}
	name, _, _ := names(s)
	if f, e := r.private(name, os.O_RDONLY); e == nil {
		f.Close()
		if e = r.root.Remove(name); e != nil {
			return c, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return c, e
	}
	if e = fsutil.SyncDirectory(r.root, "."); e != nil {
		return c, e
	}
	c.State = "aborted"
	return c, r.save(c)
}

// Verification is a distinct local job, not part of the final chunk HTTP
// request. A large file's full disk scan must not be restarted repeatedly by
// a short control-request timeout. Until this succeeds the bytes are unpublished.
func (r *Receiver) Verify(ctx context.Context, s Spec, admission func() error) (Checkpoint, error) {
	if !r.valid(s) {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	if admission != nil {
		if e = admission(); e != nil {
			return Checkpoint{}, e
		}
	}
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	if c.State != "received" && c.State != "verified" {
		return c, ErrState
	}
	if c.Offset != s.Bytes || c.PrefixSHA != s.SHA256 {
		return c, ErrState
	}
	if _, e = r.inspect(ctx, c); e != nil {
		if errors.Is(e, ErrState) {
			c.State = "failed"
			e = errors.Join(e, r.save(c))
		}
		return c, e
	}
	if admission != nil {
		if e = admission(); e != nil {
			return c, e
		}
	}
	c.State = "verified"
	return c, r.save(c)
}

// VerifiedReader rehashes disk bytes before exposing a private read-only file
// to a coordinated publication transaction. Callers must retain its blob lease
// until their publication journal owns the verified material.
func (r *Receiver) VerifiedReader(ctx context.Context, s Spec) (*os.File, func(), error) {
	if !r.valid(s) {
		return nil, nil, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return nil, nil, e
	}
	c, e := r.load(s)
	if e == nil && c.State == "verified" {
		_, e = r.inspect(ctx, c)
	} else if e == nil {
		e = ErrState
	}
	if e != nil {
		release()
		return nil, nil, e
	}
	name, _, _ := names(s)
	f, e := r.private(name, os.O_RDONLY)
	if e != nil {
		release()
		return nil, nil, e
	}
	return f, func() { f.Close(); release() }, nil
}

// Publish preserves the verified private hard-link anchor across filesystem and
// database commit windows. Retrying requires the same binding and actual bytes;
// callers must never overwrite a different inode at the destination. The local
// volume coordinator is acquired by commit after the bounded-buffer disk scan.
func (r *Receiver) Publish(ctx context.Context, s Spec, admission func() error, commit func(string) error) (Checkpoint, error) {
	if !r.valid(s) || admission == nil || commit == nil {
		return Checkpoint{}, ErrState
	}
	release, e := r.lock(ctx, s)
	if e != nil {
		return Checkpoint{}, e
	}
	defer release()
	c, e := r.load(s)
	if e != nil {
		return c, e
	}
	if c.State != "verified" && c.State != "publishing" && c.State != "published" {
		return c, ErrState
	}
	if e = admission(); e != nil {
		return c, e
	}
	if _, e = r.inspect(ctx, c); e != nil {
		return c, e
	}
	if e = admission(); e != nil {
		return c, e
	}
	if c.State != "published" {
		c.State = "publishing"
		if e = r.save(c); e != nil {
			return c, e
		}
	}
	name, _, _ := names(s)
	if e = commit(name); e != nil {
		return c, e
	}
	c.State = "published"
	return c, r.save(c)
}
