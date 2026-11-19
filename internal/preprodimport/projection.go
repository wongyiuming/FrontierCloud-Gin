package preprodimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// Decode admits only the media-only projection schema; unknown fields such as
// users, sessions, node credentials, or endpoints are rejected, not ignored.
func Decode(r io.Reader) (Snapshot, error) {
	var s Snapshot
	limited := &io.LimitedReader{R: r, N: 32*1024*1024 + 1}
	d := json.NewDecoder(limited)
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, invalid("decode")
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) || limited.N <= 0 {
		return Snapshot{}, invalid("trailing data")
	}
	return s, nil
}

type Event struct {
	Kind, Role, ObjectID string
	Bytes                int64
}
type Options struct {
	MaxBytesPerSecond int64
	Progress          func(Event) error
}
type limiter struct {
	start       time.Time
	bytes, rate int64
}
type checkedReader struct {
	context.Context
	io.Reader
	limiter *limiter
}

func (r checkedReader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	n, err := r.Reader.Read(p)
	r.limiter.bytes += int64(n)
	seconds := r.limiter.bytes / r.limiter.rate
	remainder := r.limiter.bytes % r.limiter.rate
	expected := time.Duration(seconds)*time.Second + time.Duration(remainder*int64(time.Second)/r.limiter.rate)
	if wait := expected - time.Since(r.limiter.start); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context.Done():
			return n, r.Context.Err()
		}
	}
	return n, err
}

func verifyFile(ctx context.Context, root *os.Root, role, id string, size int64, expected string, limit *limiter) error {
	// This path is an opaque stage ID, never a user-supplied logical path.
	name := role + "/objects/" + id + ".blob"
	for _, p := range []string{role, role + "/objects", name} {
		v, err := root.Lstat(p)
		if err != nil || !privateOwned(v, p != name) {
			return invalid("staged path")
		}
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() != size {
		return invalid("staged file size")
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		f.Close()
		return invalid("staged file replaced")
	}
	h := sha256.New()
	n, readErr := io.CopyBuffer(h, checkedReader{ctx, io.LimitReader(f, size+1), limit}, make([]byte, 64*1024))
	after, statErr := f.Stat()
	closeErr := f.Close()
	current, currentErr := root.Lstat(name)
	if readErr != nil {
		return readErr
	}
	if statErr != nil || closeErr != nil || currentErr != nil || n != size || after.Size() != size || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, current) || !current.ModTime().Equal(before.ModTime()) || hex.EncodeToString(h.Sum(nil)) != expected {
		return invalid("staged file changed or checksum mismatch")
	}
	return nil
}

// Prepare is deliberately unavailable until the encrypted tree and its atomic
// import protocol exist. The experimental projection stores logical paths in
// plaintext and cannot be used for real snapshots under the current policy.
func Prepare(ctx context.Context, s Snapshot, premaster []byte, stageDir, parentDir string, opts Options) (report Report, err error) {
	return report, invalid("encrypted tree import not implemented")
}
