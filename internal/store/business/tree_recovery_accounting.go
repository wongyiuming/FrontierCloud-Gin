package business

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

const recoveryOwnerLimit = 1024

var errRecoveryAccounting = errors.New("retained tree storage accounting is inconsistent")

type RecoveryOwnerAccounting struct {
	ID, Kind, RelationshipID string
	Allocation, Bytes        int64
	Objects                  int64
}

type RecoveryAccounting struct {
	TreeGeneration int64
	Media          int64
	Recordings     int64
	Owners         []RecoveryOwnerAccounting
}

// VerifyRecoveryAccounting reconciles all selected media and sealed recording
// charges with Master storage counters. The caller holds the actual Owner and
// tree leases in that order and keeps them through any dependent verification.
// This checks Master accounting only. It does not observe remote storage.
func (r *Repository) VerifyRecoveryAccounting(ctx context.Context, owner store.OwnerControlLease, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, key []byte, nodeVault *vault.Vault) (RecoveryAccounting, error) {
	return r.verifyRecoveryAccounting(ctx, owner, tree, lease, key, nodeVault, nil, nil)
}

func (r *Repository) verifyRecoveryAccounting(ctx context.Context, owner store.OwnerControlLease, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, key []byte, nodeVault *vault.Vault, mediaVisit func(sealedtree.RecoveryMediaPlacement) error, recordingVisit func(RecoveryRecordingPlacement) error) (RecoveryAccounting, error) {
	var empty RecoveryAccounting
	if r == nil || r.backend != "sqlite" || ctx == nil || !validOwnerControlLease(owner) || tree == nil || lease == nil || !validCapacityKey(key) || nodeVault == nil {
		return empty, errRecoveryAccounting
	}
	if err := owner.Check(ctx); err != nil {
		return empty, err
	}
	if err := lease.Check(ctx); err != nil {
		return empty, err
	}
	owners, err := r.recoveryAccountingRoster(ctx, owner)
	if err != nil {
		return empty, err
	}
	charges := make(map[string]*recoveryOwnerCharge, len(owners))
	for i := range owners {
		charges[owners[i].ID] = &owners[i]
	}
	media, err := tree.VisitRecoveryMedia(ctx, lease, func(item sealedtree.RecoveryMediaPlacement) error {
		if err := charges[item.OwnerID].add(item.Bytes, item.S3VersionID != ""); err != nil || mediaVisit == nil {
			return err
		}
		return mediaVisit(item)
	})
	if err != nil {
		return empty, err
	}
	recordings, err := r.VisitRecoveryRecordings(ctx, tree, lease, key, nodeVault, func(item RecoveryRecordingPlacement) error {
		charge := charges[item.OwnerID]
		if charge == nil || charge.expected != item.OwnerUsedBytes || charge.Allocation != item.OwnerAllocationBytes || item.OwnerReservedBytes != 0 {
			return errRecoveryAccounting
		}
		if err := charge.add(item.Bytes, false); err != nil || recordingVisit == nil {
			return err
		}
		return recordingVisit(item)
	})
	if err != nil {
		return empty, err
	}
	result := RecoveryAccounting{TreeGeneration: media.TreeGeneration, Media: media.Objects, Recordings: recordings.Recordings, Owners: make([]RecoveryOwnerAccounting, 0, len(owners))}
	for _, charge := range owners {
		if charge.Bytes != charge.expected {
			return empty, errRecoveryAccounting
		}
		result.Owners = append(result.Owners, charge.RecoveryOwnerAccounting)
	}
	if err = lease.Check(ctx); err != nil {
		return empty, err
	}
	if err = owner.Check(ctx); err != nil {
		return empty, err
	}
	return result, nil
}

type recoveryOwnerCharge struct {
	RecoveryOwnerAccounting
	expected int64
}

func (c *recoveryOwnerCharge) add(bytes int64, s3 bool) error {
	if c == nil || bytes <= 0 || (c.Kind == "S3") != s3 || bytes > c.expected-c.Bytes || c.Objects == math.MaxInt64 {
		return errRecoveryAccounting
	}
	c.Bytes += bytes
	c.Objects++
	return nil
}

func (r *Repository) recoveryAccountingRoster(ctx context.Context, owner store.OwnerControlLease) ([]recoveryOwnerCharge, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = r.checkOwnerControlMarker(ctx, tx, owner); err != nil {
		return nil, err
	}
	master, err := readNode(ctx, tx, "")
	if err != nil || master.Role != "Master" || !nodeIDPattern.MatchString(master.ID) {
		return nil, errRecoveryAccounting
	}
	var other bool
	if err = tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM global_media_objects) OR
		EXISTS(SELECT 1 FROM s3_objects WHERE state<>'deleted') OR
		EXISTS(SELECT 1 FROM node_relationships n LEFT JOIN cluster_storage_members m ON m.relationship_id=n.relationship_id AND m.member_id=n.peer_id WHERE n.direction='downstream' AND n.state='active' AND m.member_id IS NULL) OR
		EXISTS(SELECT 1 FROM s3_members s LEFT JOIN cluster_storage_members m ON m.member_id=s.member_id WHERE m.member_id IS NULL)`).Scan(&other); err != nil || other {
		return nil, errRecoveryAccounting
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.member_id,m.member_kind,m.transport,m.storage_enabled,m.allocated_bytes,m.used_bytes,m.reserved_bytes,m.writable,
		m.relationship_id,n.peer_id,n.direction,n.mode,n.state,s.member_id
		FROM cluster_storage_members m
		LEFT JOIN node_relationships n ON n.relationship_id=m.relationship_id
		LEFT JOIN s3_members s ON s.member_id=m.member_id
		ORDER BY m.member_id LIMIT ?`, recoveryOwnerLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var local bool
	var count int
	var owners []recoveryOwnerCharge
	for rows.Next() {
		var item recoveryOwnerCharge
		var transport string
		var enabled, writable int
		var reserved int64
		var rel, peer, direction, mode, state, s3 sql.NullString
		count++
		if count > recoveryOwnerLimit || rows.Scan(&item.ID, &item.Kind, &transport, &enabled, &item.Allocation, &item.expected, &reserved, &writable, &rel, &peer, &direction, &mode, &state, &s3) != nil ||
			!nodeIDPattern.MatchString(item.ID) || item.expected < 0 || item.Allocation < item.expected || reserved != 0 || (enabled != 0 && enabled != 1) {
			return nil, errRecoveryAccounting
		}
		switch item.Kind {
		case "MasterLocal":
			if local || item.ID != master.ID || transport != "Local" || enabled != 1 || rel.Valid || s3.Valid {
				return nil, errRecoveryAccounting
			}
			local = true
		case "Follower":
			if item.ID == master.ID || !nodeIDPattern.MatchString(rel.String) || peer.String != item.ID || direction.String != "downstream" || mode.String != transport || (transport != "Direct" && transport != "Relay") || s3.Valid {
				return nil, errRecoveryAccounting
			}
			if state.String == "revoked" && item.expected == 0 && writable == 0 {
				continue
			}
			if state.String != "active" {
				return nil, errRecoveryAccounting
			}
			item.RelationshipID = rel.String
		case "S3":
			if item.ID == master.ID || transport != "S3" || rel.Valid || s3.String != item.ID {
				return nil, errRecoveryAccounting
			}
		default:
			return nil, errRecoveryAccounting
		}
		owners = append(owners, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if !local {
		return nil, errRecoveryAccounting
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return owners, nil
}
