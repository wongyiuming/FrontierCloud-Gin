package sealedtree

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
)

// CheckpointLyricBlobs enumerates authenticated local ciphertext while the
// caller holds the shared tree fence through snapshot and byte capture.
// Includes hidden/default lyrics; audio/video bytes are deliberately excluded.
func (s *SQLStore) CheckpointLyricBlobs(ctx context.Context, lease *TreeLease, master string, visit func(Placement) error) error {
	if !s.valid() || lease == nil || visit == nil || !lowerHex(master, 32) {
		return ErrInvalid
	}
	lease.mu.Lock()
	validLease := lease.fence != nil && lease.fence.store == s && !lease.exclusive
	lease.mu.Unlock()
	if !validLease {
		return ErrFenceRequired
	}
	if err := lease.Check(ctx); err != nil {
		return err
	}
	cursor := ""
	for {
		rows, err := s.db.QueryContext(ctx, `SELECT object_index,blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index>? ORDER BY object_index LIMIT 64`, cursor)
		if err != nil {
			return err
		}
		batch := []PlacementRecord{}
		for rows.Next() {
			var p PlacementRecord
			if err = rows.Scan(&p.ObjectIndex, &p.BlobIndex, &p.Revision, &p.Sealed); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, p)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, record := range batch {
			p, err := s.tree.OpenPlacement(record)
			if err != nil {
				return err
			}
			entry, _, err := s.Get(ctx, p.ObjectID)
			if err != nil {
				return err
			}
			if entry.Kind == "lyric" {
				if p.OwnerID != master || p.Encryption == nil || p.Bytes < 0 || p.Bytes > 4*1024*1024 {
					return ErrInvalid
				}
				if err = visit(p); err != nil {
					return err
				}
			}
			cursor = record.ObjectIndex
		}
	}
	return lease.Check(ctx)
}

// ValidateCheckpointLyrics verifies every lyric byte against its authenticated
// placement. No audio, video or recording payload is required in a state point.
func (s *SQLStore) ValidateCheckpointLyrics(ctx context.Context, db *sql.DB, mediaPath, master string) error {
	if !s.valid() || db == nil || !lowerHex(master, 32) {
		return ErrInvalid
	}
	copyStore, err := OpenSQLite(ctx, db, s.tree, s.rootID)
	if err != nil {
		return err
	}
	// Open lazily: a namespace without lyrics legitimately has no media directory.
	var root *os.Root
	defer func() {
		if root != nil {
			root.Close()
		}
	}()
	cursor := ""
	for {
		var record PlacementRecord
		err = db.QueryRowContext(ctx, `SELECT object_index,blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index>? ORDER BY object_index LIMIT 1`, cursor).Scan(&record.ObjectIndex, &record.BlobIndex, &record.Revision, &record.Sealed)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		p, err := copyStore.tree.OpenPlacement(record)
		if err != nil {
			return err
		}
		entry, _, err := copyStore.Get(ctx, p.ObjectID)
		if err != nil {
			return err
		}
		if entry.Kind == "lyric" {
			if p.OwnerID != master || p.Encryption == nil || p.Bytes < 0 || p.Bytes > 4*1024*1024 {
				return ErrInvalid
			}
			if root == nil {
				root, err = os.OpenRoot(mediaPath)
				if err != nil {
					return err
				}
			}
			name, err := BlobPath(p.BlobID)
			if err != nil {
				return err
			}
			named, err := root.Lstat(name)
			if err != nil || !named.Mode().IsRegular() || named.Size() != p.Bytes {
				return ErrInvalid
			}
			file, err := root.Open(name)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(named, opened) {
				file.Close()
				return ErrInvalid
			}
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(file, p.Bytes+1))
			closeErr := file.Close()
			if err != nil || closeErr != nil || n != p.Bytes || hex.EncodeToString(h.Sum(nil)) != p.SHA256 {
				return ErrInvalid
			}
		}
		cursor = record.ObjectIndex
	}
}

// ValidateCheckpointDatabase authenticates the copied namespace with the
// existing Master tree key. It never creates a key, root, fence or identity.
func (s *SQLStore) ValidateCheckpointDatabase(ctx context.Context, db *sql.DB) error {
	if !s.valid() || db == nil {
		return ErrInvalid
	}
	copy, err := OpenSQLite(ctx, db, s.tree, s.rootID)
	if err != nil {
		return err
	}

	cursor := ""
	for {
		rows, err := db.QueryContext(ctx, `SELECT object_index,blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index>? ORDER BY object_index LIMIT 64`, cursor)
		if err != nil {
			return err
		}
		var records []PlacementRecord
		for rows.Next() {
			var r PlacementRecord
			if err = rows.Scan(&r.ObjectIndex, &r.BlobIndex, &r.Revision, &r.Sealed); err != nil {
				rows.Close()
				return err
			}
			records = append(records, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}
		for _, r := range records {
			p, e := copy.tree.OpenPlacement(r)
			if e != nil {
				return e
			}
			if _, _, e = copy.Get(ctx, p.ObjectID); e != nil {
				return e
			}
			if _, _, e = copy.GetFacts(ctx, p.ObjectID); e != nil {
				return e
			}
			cursor = r.ObjectIndex
		}
	}
}
