package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type MediaDeletionBackend string

const (
	MediaDeletionFollower    MediaDeletionBackend = "Follower"
	MediaDeletionMasterLocal MediaDeletionBackend = "MasterLocal"
	MediaDeletionS3          MediaDeletionBackend = "S3"
)

func selectedMediaDeletionKind(name string) string {
	if !factPath(name) {
		return ""
	}
	if validMasterLocalLyricDeletePath(name) {
		return "lyric"
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return ""
	}
	for _, part := range parts {
		if !validComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
			return ""
		}
	}
	ext := strings.ToLower(path.Ext(name))
	if parts[0] == "music" && (ext == ".mp3" || ext == ".m4a" || ext == ".flac" || ext == ".wav") {
		return "audio"
	}
	if parts[0] == "vido" && (ext == ".mp4" || ext == ".webm" || ext == ".mkv") {
		return "video"
	}
	return ""
}

func (s *SQLStore) followerMediaDeleteOperation(id, path string) string {
	return s.listingMAC("selected-native-delete-v1", id, path)[:32]
}

// ClassifyMediaDeletionTx selects the backend of the exact encrypted file or
// authenticated terminal retry. It does not queue deletion or authorize a
// provider or volume operation. The backend must perform its own checks in
// the same transaction before it changes durable state.
func (m *CoordinatedMutation) ClassifyMediaDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) (MediaDeletionBackend, error) {
	kind := selectedMediaDeletionKind(target.Path)
	if m == nil || ctx == nil || tx == nil || !hexID(target.ResourceID) || kind == "" ||
		target.OperationID != "" && !lowerHex(target.OperationID, 32) {
		return "", ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || target.ResourceID == s.rootID {
		return "", ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return "", err
	}
	record, entry, err := s.recordByID(ctx, tx, target.ResourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return s.classifyCompletedMediaDeletion(ctx, tx, target, kind)
	}
	if err != nil || entry.Kind != kind {
		return "", ErrConflict
	}
	if current, err := s.pathInTransaction(ctx, tx, entry); err != nil || current != target.Path {
		return "", ErrConflict
	}
	isS3, err := s.checkIndexedS3(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return "", err
	}
	if isS3 {
		if kind == "lyric" {
			return "", ErrConflict
		}
		view, _, _, _, _, _, err := s.readS3MediaDeletion(ctx, tx, target.ResourceID)
		if err != nil || target.OperationID != "" && target.OperationID != view.Pending.OperationID {
			return "", ErrConflict
		}
		return MediaDeletionS3, nil
	}
	return s.classifyNativeMediaDeletion(ctx, tx, target, entry, record)
}

func (s *SQLStore) classifyNativeMediaDeletion(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, entry Entry, record Record) (MediaDeletionBackend, error) {
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || placement.State != "active" || placement.Encryption == nil {
		return "", ErrConflict
	}
	var masterID, memberKind string
	if err = tx.QueryRowContext(ctx, `SELECT n.node_id,m.member_kind FROM node_identity n
		JOIN cluster_storage_members m ON m.member_id=? WHERE n.singleton=1 AND n.role='Master'`, placement.OwnerID).Scan(&masterID, &memberKind); err != nil || !lowerHex(masterID, 32) {
		return "", ErrConflict
	}
	var backend MediaDeletionBackend
	var operation string
	switch {
	case memberKind == "MasterLocal" && placement.OwnerID == masterID:
		backend, operation = MediaDeletionMasterLocal, s.masterLocalMediaDeleteOperation(target.ResourceID, target.Path)
	case memberKind == "Follower" && placement.OwnerID != masterID && entry.Kind != "lyric":
		backend, operation = MediaDeletionFollower, s.followerMediaDeleteOperation(target.ResourceID, target.Path)
	default:
		return "", ErrConflict
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || facts.InternalPlaceholder || facts.PendingPlaceholder != nil || facts.PendingSelectedUpload != nil || facts.S3Deletion != nil {
		return "", ErrConflict
	}
	if target.OperationID != "" && target.OperationID != operation {
		return "", ErrConflict
	}
	if pending := facts.Revocation; pending != nil {
		if !pending.SelectedDelete || pending.Action != "delete" || pending.OperationID != operation ||
			pending.LocalDelete != (backend == MediaDeletionMasterLocal) || s.verifyRevocation(ctx, tx, pending, placement) != nil {
			return "", ErrConflict
		}
	} else if target.OperationID != "" {
		return "", ErrConflict
	}
	return backend, nil
}

func (s *SQLStore) classifyCompletedMediaDeletion(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget, kind string) (MediaDeletionBackend, error) {
	local := s.masterLocalMediaDeleteOperation(target.ResourceID, target.Path)
	if target.OperationID == "" || target.OperationID == local {
		if done, err := s.nativeDeleteCompleted(ctx, tx, target.ResourceID, local); err != nil {
			return "", err
		} else if done {
			return MediaDeletionMasterLocal, nil
		}
	}
	if kind != "lyric" {
		follower := s.followerMediaDeleteOperation(target.ResourceID, target.Path)
		if target.OperationID == "" || target.OperationID == follower {
			if done, err := s.nativeDeleteCompleted(ctx, tx, target.ResourceID, follower); err != nil {
				return "", err
			} else if done {
				return MediaDeletionFollower, nil
			}
		}
		if target.OperationID != "" {
			if done, err := s.s3DeletionRecordedTx(ctx, tx, target.ResourceID, "s3-media-deleted-v1", target.OperationID, target.Path); err != nil {
				return "", err
			} else if done {
				return MediaDeletionS3, nil
			}
		}
	}
	return "", ErrConflict
}
