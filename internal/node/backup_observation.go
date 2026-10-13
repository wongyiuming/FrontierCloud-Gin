package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ObserveBackup re-reads a known ready generation through the authenticated
// peer's bounded worker. Success is byte integrity at the observation time;
// it neither pins retention nor proves a complete disaster-recovery package.
func (s *Service) ObserveBackup(ctx context.Context, relationship string, expected store.BackupManifest) (resourceinventory.ContentObservation, error) {
	var empty resourceinventory.ContentObservation
	ctx, stop := context.WithTimeout(ctx, resourceinventory.ContentObservationTTL(expected.Bytes))
	defer stop()
	rel, err := s.backupRelation(ctx, relationship, nil)
	if err != nil {
		return empty, err
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || expected.MasterID != identity.ID || expected.Generation <= 0 || expected.State != "ready" || expected.Bytes < 0 || expected.Chunks < 1 || expected.Chunks > store.MaxBackupChunkIndex+1 || expected.Bytes > int64(expected.Chunks)*store.MaxBackupChunk {
		return empty, store.ErrBackupState
	}
	hash, err := hex.DecodeString(expected.Checksum)
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != expected.Checksum {
		return empty, store.ErrBackupState
	}
	digest, err := store.MigrationDigest(expected)
	if err != nil {
		return empty, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	request := resourceinventory.ContentRequest{
		ID:       hex.EncodeToString(nonce[:]),
		Binding:  resourceinventory.Binding{MemberID: rel.PeerID, MasterID: identity.ID, RelationshipID: rel.ID, Scope: "data"},
		Resource: "backup", ObjectID: strconv.FormatInt(expected.Generation, 10), MetadataSHA: digest, Bytes: expected.Bytes,
	}
	// Canonical node signing consumes JSON primitives, not Go structs.
	value := map[string]any{"action": "start", "observation_id": request.ID, "binding": map[string]any{"member_id": rel.PeerID, "master_id": identity.ID, "relationship_id": rel.ID, "scope": "data"}, "resource_kind": "backup", "object_id": request.ObjectID, "metadata_sha256": digest, "expected_bytes": expected.Bytes}
	const route = "/internal/v1/backup-observation"
	var first resourceinventory.ContentJob
	defer func() {
		if first.Incarnation == "" {
			return // Lost starts remain bounded by the peer's fixed expiry.
		}
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		current, err := s.backupRelation(finish, relationship, &rel)
		if err == nil {
			value["action"], value["incarnation"] = "cancel", first.Incarnation
			_, _ = s.Call(finish, current, route, value)
		}
	}()
	for {
		current, err := s.backupRelation(ctx, relationship, &rel)
		if err != nil {
			return empty, err
		}
		response, err := s.Call(ctx, current, route, value)
		if err != nil {
			return empty, err
		}
		raw, err := json.Marshal(response)
		if err != nil || len(raw) > 8192 {
			return empty, store.ErrBackupState
		}
		var job resourceinventory.ContentJob
		if json.Unmarshal(raw, &job) != nil || job.Request != request || !nodeIdentifier.MatchString(job.Incarnation) || len(job.ErrorCode) > 80 {
			return empty, store.ErrBackupState
		}
		now := time.Now().Unix()
		if job.CreatedAt < now-30 && first.Incarnation == "" || job.CreatedAt > now+30 || job.ExpiresAt <= now || job.ExpiresAt != job.CreatedAt+int64(resourceinventory.ContentObservationTTL(expected.Bytes)/time.Second) {
			return empty, store.ErrBackupState
		}
		if first.Incarnation == "" {
			first = job
		} else if job.Incarnation != first.Incarnation || job.CreatedAt != first.CreatedAt || job.ExpiresAt != first.ExpiresAt {
			return empty, store.ErrBackupState
		}
		switch job.State {
		case "observed":
			if job.ErrorCode != "" || job.Observation == nil || job.Observation.Path != "backup/"+request.ObjectID || job.Observation.Bytes != expected.Bytes || job.Observation.SHA256 != expected.Checksum || job.Observation.ModifiedNS != 0 {
				return empty, store.ErrBackupState
			}
			if _, err := s.backupRelation(ctx, relationship, &rel); err != nil {
				return empty, err
			}
			return *job.Observation, nil
		case "queued", "running":
			if job.Observation != nil || job.ErrorCode != "" {
				return empty, store.ErrBackupState
			}
		default:
			return empty, store.ErrBackupState
		}
		value["action"], value["incarnation"] = "status", first.Incarnation
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return empty, ctx.Err()
		case <-timer.C:
		}
	}
}
