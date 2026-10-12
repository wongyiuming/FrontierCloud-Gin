package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func readMigrationIntent(f *os.File) (j journal, e error) {
	info, e := f.Stat()
	if e != nil {
		return j, e
	}
	if !info.Mode().IsRegular() || info.Size() > store.MaxRecordingMetadata+16384 {
		return j, ErrRecovery
	}
	d := json.NewDecoder(io.LimitReader(f, store.MaxRecordingMetadata+16385))
	if e = d.Decode(&j); e != nil {
		return j, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF || j.Version != 1 || !identifier.MatchString(j.UserID) || !identifier.MatchString(j.MemberID) || !identifier.MatchString(j.Relationship) {
		return j, ErrRecovery
	}
	return j, nil
}

// Cleanup uses the same private recording journal and tombstone transaction as
// ordinary deletion. The persisted Master grant is checked again before staging.
func (s *Storage) MigrationCleanupAuthorized(ctx context.Context, relationship string, l store.MigrationLease, id string, peer store.MigrationPeerRepository) error {
	unlock, e := s.Lock(id)
	if e != nil {
		return e
	}
	defer unlock()
	v, e := peer.AuthorizePeerMigration(ctx, relationship, l, id, "cleanup")
	if e != nil {
		return e
	}
	if v.Object.Resource != "recording" || v.Object.Recording == nil {
		return store.ErrMigrationState
	}
	if v.State == "deleted" {
		release, e := s.acquire(ctx, true)
		if e != nil {
			return e
		}
		e = s.finishMigrationIntent(ctx, id, l.TaskID)
		// Historical full-byte scans happen after releasing the volume lease.
		release()
		if e != nil {
			return e
		}
		return s.migrationHistory(ctx, relationship, l, v, peer)
	}
	if v.State != "deleting" {
		return store.ErrMigrationState
	}
	release, e := s.acquire(ctx, false)
	if e != nil {
		return e
	}
	if e = s.ready(); e != nil {
		release()
		return e
	}
	info, e := s.info(v.Object.Path)
	if e != nil {
		release()
		return e
	}
	if info.Size() != v.Object.Bytes {
		release()
		return store.ErrMigrationState
	}
	f, e := s.root.Open(v.Object.Path)
	release()
	if e != nil {
		return e
	}
	defer f.Close()
	pinned, e := f.Stat()
	if e != nil || !os.SameFile(info, pinned) {
		return ErrRecovery
	}
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, err := f.Read(buffer)
		if n > 0 {
			size += int64(n)
			if size > v.Object.Bytes {
				return store.ErrMigrationState
			}
			_, _ = digest.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	after, e := f.Stat()
	if e != nil || size != v.Object.Bytes || hex.EncodeToString(digest.Sum(nil)) != v.Proof.SHA256 || !os.SameFile(pinned, after) || pinned.Size() != after.Size() || !pinned.ModTime().Equal(after.ModTime()) {
		return store.ErrMigrationState
	}
	if !store.RecordingProofSnapshotMatches(*v.Object.Recording, Metadata(f, size)) {
		return store.ErrMigrationState
	}
	release, e = s.acquire(ctx, true)
	if e != nil {
		return e
	}
	held := true
	defer func() {
		if held {
			release()
		}
	}()
	if e = s.ready(); e != nil {
		return e
	}
	if _, e = peer.AuthorizePeerMigration(ctx, relationship, l, id, "cleanup"); e != nil {
		return e
	}
	current, e := s.info(v.Object.Path)
	if e != nil {
		return e
	}
	if !os.SameFile(pinned, current) || current.Size() != pinned.Size() || !current.ModTime().Equal(pinned.ModTime()) {
		return store.ErrMigrationState
	}
	row, e := peer.StagePeerRecordingDeletion(ctx, relationship, l, id)
	if e != nil {
		return e
	}
	j := journal{Version: 1, Operation: "delete", Relationship: relationship, Recording: *row, UserID: row.UserID, MemberID: row.MemberID, MigrationTask: l.TaskID}
	if e = s.writeJournal(j); e != nil {
		s.fence()
		return e
	}
	if e = s.finishDelete(ctx, j); e != nil {
		return e
	}
	release()
	held = false
	return s.migrationHistory(ctx, relationship, l, v, peer)
}

func (s *Storage) migrationHistory(ctx context.Context, relationship string, l store.MigrationLease, v store.MigrationPeerObject, repo store.MigrationPeerRepository) error {
	r, e := migrationdata.New(s.root, v.Header.SourceID, "recording")
	if e != nil {
		return e
	}
	return r.HistoricalAnchors(ctx, v.Header.MasterID, v.Object, v.Proof.SHA256, func() error {
		current, e := repo.AuthorizePeerMigration(ctx, relationship, l, v.Object.ID, "cleanup")
		if e != nil {
			return e
		}
		if current.State != "deleted" {
			return store.ErrMigrationState
		}
		return nil
	})
}
func (s *Storage) MigrationHistoryFinished(ctx context.Context, v store.MigrationPeerObject) (bool, error) {
	r, e := migrationdata.New(s.root, v.Header.SourceID, "recording")
	if e != nil {
		return false, e
	}
	return r.HistoricalAnchorsFinished(ctx, v.Header.MasterID, v.Object, v.Proof.SHA256)
}

func (s *Storage) finishMigrationIntent(ctx context.Context, id, task string) error {
	name := ".recording-" + id + ".json"
	info, e := s.info(name)
	if errors.Is(e, os.ErrNotExist) {
		if _, e = s.info(".recording-" + id + ".deleted"); !errors.Is(e, os.ErrNotExist) {
			return ErrRecovery
		}
		return nil
	}
	if e != nil {
		return e
	}
	f, e := s.root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	pinned, e := f.Stat()
	if e != nil || !os.SameFile(info, pinned) {
		return ErrRecovery
	}
	// The usual recovery parser validates the same bounded journal. Here the
	// replay also requires the exact migration task before touching its trash.
	j, e := readMigrationIntent(f)
	if e != nil {
		return e
	}
	if j.Recording.ID != id || j.MigrationTask != task || j.Operation != "delete" || j.Absent {
		return ErrRecovery
	}
	return s.finishDelete(ctx, j)
}

func (s *Storage) MigrationCleanupFinished(ctx context.Context, task, id string) (bool, error) {
	if !identifier.MatchString(task) || !identifier.MatchString(id) {
		return false, store.ErrMigrationState
	}
	release, e := s.acquire(ctx, false)
	if e != nil {
		return false, e
	}
	defer release()
	for _, name := range []string{".recording-" + id + ".json", ".recording-" + id + ".deleted"} {
		if _, e = s.info(name); e == nil {
			return false, nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return false, e
		}
	}
	return true, nil
}
