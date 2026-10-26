package business

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const s3ProbeColumns = "probe_id,member_id,revision,credential_revision,object_key,provider_upload_id,version_id,etag,state,grant_until,error_code,created_at,updated_at"

func scanS3Probe(row rowScanner) (v store.S3Probe, err error) {
	err = row.Scan(&v.ID, &v.MemberID, &v.Revision, &v.CredentialRevision, &v.Key, &v.ProviderUploadID,
		&v.VersionID, &v.ETag, &v.State, &v.GrantUntil, &v.ErrorCode, &v.CreatedAt, &v.UpdatedAt)
	return
}

func (r *Repository) S3StartProbe(ctx context.Context, id string, revision int64, a store.NodeAudit) (result store.S3Probe, err error) {
	probeID, err := randomID()
	if err != nil {
		return result, err
	}
	probeID = probeID[:32]
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		member, err := r.s3Member(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(member.Revision, revision); err != nil {
			return err
		}
		now := time.Now().Unix()
		if member.SealedCredentials == "" || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= now {
			return nodeConflict("S3 probe requires usable bound credentials")
		}
		_, pending, probes, err := s3BoundState(ctx, q, id, now)
		if err != nil {
			return err
		}
		if probes != 0 || member.CleanupOnly && pending != 0 {
			return nodeConflict("S3 probe cleanup or credential recovery is pending")
		}
		key := "probes/" + id + "/" + probeID
		until := now + store.S3GrantSeconds
		if member.CredentialExpiresAt != 0 {
			until = min(until, member.CredentialExpiresAt)
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO s3_probe_journal("+s3ProbeColumns+") VALUES (?,?,?,?,?,'','','','running',?,'',?,?)",
			probeID, id, revision, member.CredentialRevision, key, until, now, now); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_members SET probe_revision=0,probe_state='testing',error_code='',updated_at=? WHERE member_id=?", now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET writable=0,health='testing',updated_at=? WHERE member_id=?", now, id); err != nil {
			return err
		}
		if err = r.nodeAudit(ctx, q, "s3-probe-started", id, map[string]any{"probe_id": probeID, "revision": revision}, a); err != nil {
			return err
		}
		result = store.S3Probe{ID: probeID, MemberID: id, Revision: revision, CredentialRevision: member.CredentialRevision,
			Key: key, State: "running", GrantUntil: until, CreatedAt: now, UpdatedAt: now}
		return nil
	})
	return
}

func (r *Repository) S3FinishProbe(ctx context.Context, id string, revision int64, proof store.S3ProbeResult, a store.NodeAudit) (result store.S3Member, err error) {
	if !nodeIDPattern.MatchString(id) || !s3Code(proof.ErrorCode) || !s3Opaque(proof.ProviderUploadID, 2048) ||
		!s3Opaque(proof.VersionID, 1024) || !s3Opaque(proof.ETag, 512) || proof.ChecksPassed && proof.NoMutation {
		return result, nodeConflict("invalid S3 probe result")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		probe, err := scanS3Probe(q.QueryRowContext(ctx, "SELECT "+s3ProbeColumns+" FROM s3_probe_journal WHERE probe_id=?"+r.lock(), id))
		if errors.Is(err, sql.ErrNoRows) {
			return s3Missing("probe")
		}
		if err != nil {
			return err
		}
		if err = s3Revision(probe.Revision, revision); err != nil {
			return err
		}
		if proof.Key != probe.Key {
			return nodeConflict("S3 probe result has a different owned key")
		}
		if probe.ProviderUploadID != "" && proof.ProviderUploadID != "" && proof.ProviderUploadID != probe.ProviderUploadID {
			return nodeConflict("S3 probe provider upload identity changed")
		}
		if proof.ProviderUploadID == "" {
			proof.ProviderUploadID = probe.ProviderUploadID
		}
		if proof.VersionID == "" {
			proof.VersionID = probe.VersionID
		}
		if proof.ETag == "" {
			proof.ETag = probe.ETag
		}
		settled := proof.CleanupSettled && (proof.ChecksPassed || proof.NoMutation || proof.ProviderUploadID != "")
		state, code := "cleanup", proof.ErrorCode
		if settled {
			state = "settled"
		}
		if !proof.ChecksPassed && code == "" {
			code = "probe_failed"
		}
		if !settled && code == "" {
			code = "probe_cleanup_pending"
		}
		// The network result may be retried after a lost SQL response, but a
		// settled intent cannot be repurposed to change confidence later.
		if probe.State == "settled" {
			if state != probe.State || code != probe.ErrorCode || proof.ProviderUploadID != probe.ProviderUploadID || proof.VersionID != probe.VersionID || proof.ETag != probe.ETag {
				return nodeConflict("settled S3 probe result is immutable")
			}
			result, err = r.s3Member(ctx, q, probe.MemberID, "")
			return err
		}
		now := time.Now().Unix()
		grantUntil := probe.GrantUntil
		// A proven rejection before any creation or authorization has no bearer
		// to outlive this intent. Unknown creation and any known provider identity
		// retain their original horizon, even if a later cleanup reports success.
		if proof.NoMutation && proof.CleanupSettled && !proof.ChecksPassed &&
			probe.ProviderUploadID == "" && probe.VersionID == "" && probe.ETag == "" &&
			proof.ProviderUploadID == "" && proof.VersionID == "" && proof.ETag == "" {
			grantUntil = 0
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_probe_journal SET provider_upload_id=?,version_id=?,etag=?,state=?,grant_until=?,error_code=?,updated_at=? WHERE probe_id=?",
			proof.ProviderUploadID, proof.VersionID, proof.ETag, state, grantUntil, code, now, id); err != nil {
			return err
		}
		member, err := r.s3Member(ctx, q, probe.MemberID, r.lock())
		if err != nil {
			return err
		}
		// A late result may settle its own orphan journal, but must not mark a
		// changed location/credential generation as having passed the probe.
		if member.Revision == revision && member.CredentialRevision == probe.CredentialRevision {
			ready := proof.ChecksPassed && settled
			if member.CleanupOnly {
				_, pending, _, err := s3BoundState(ctx, q, member.ID, now)
				if err != nil {
					return err
				}
				// Existing objects retain their exact location and provider proof.
				// Only this successful, settled planned-key probe is exempt from
				// its own signature horizon; every other probe stays a fence.
				var probes int64
				if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM s3_probe_journal WHERE member_id=? AND probe_id<>? AND (state<>'settled' OR grant_until>?)", member.ID, id, now).Scan(&probes); err != nil {
					return err
				}
				ready = ready && pending == 0 && probes == 0
			}
			probeRevision, probeState, health, writable := int64(0), "failed", "offline", 0
			if ready {
				probeRevision, probeState, health = revision, "ready", "online"
				if member.Enabled != 0 {
					writable = 1
				}
				code = ""
			}
			if _, err = q.ExecContext(ctx, "UPDATE s3_members SET probe_revision=?,probe_state=?,cleanup_only=?,error_code=?,updated_at=? WHERE member_id=?",
				probeRevision, probeState, member.CleanupOnly && !ready, code, now, member.ID); err != nil {
				return err
			}
			if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET health=?,writable=?,updated_at=? WHERE member_id=?", health, writable, now, member.ID); err != nil {
				return err
			}
		}
		if err = r.nodeAudit(ctx, q, "s3-probe-finished", member.ID, map[string]any{"probe_id": id, "state": state, "code": code}, a); err != nil {
			return err
		}
		result, err = r.s3Member(ctx, q, member.ID, "")
		return err
	})
	return
}

// S3CheckpointProbe records the exact Create result before any presigned grant
// or payload operation. A lost response cannot erase or replace that identity.
func (r *Repository) S3CheckpointProbe(ctx context.Context, id string, revision int64, providerUploadID string) error {
	if !nodeIDPattern.MatchString(id) || providerUploadID == "" || !s3Opaque(providerUploadID, 2048) {
		return nodeConflict("invalid S3 probe creation checkpoint")
	}
	return r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		probe, err := scanS3Probe(q.QueryRowContext(ctx, "SELECT "+s3ProbeColumns+" FROM s3_probe_journal WHERE probe_id=?"+r.lock(), id))
		if errors.Is(err, sql.ErrNoRows) {
			return s3Missing("probe")
		}
		if err != nil {
			return err
		}
		if err = s3Revision(probe.Revision, revision); err != nil {
			return err
		}
		if probe.State == "settled" || probe.ProviderUploadID != "" && probe.ProviderUploadID != providerUploadID {
			return nodeConflict("S3 probe checkpoint identity changed or already settled")
		}
		if probe.ProviderUploadID == providerUploadID {
			return nil
		}
		_, err = q.ExecContext(ctx, "UPDATE s3_probe_journal SET provider_upload_id=?,updated_at=? WHERE probe_id=?", providerUploadID, time.Now().Unix(), id)
		return err
	})
}

// Legacy callers cannot manufacture a successful probe by supplying an empty
// error code. The persisted matching probe intent must already be settled.
func (r *Repository) S3ProbeMember(ctx context.Context, id string, revision int64, code string, a store.NodeAudit) (result store.S3Member, err error) {
	if !s3Code(code) {
		return result, nodeConflict("invalid S3 probe code")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		member, err := r.s3Member(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(member.Revision, revision); err != nil {
			return err
		}
		if code == "" {
			var count int64
			if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM s3_probe_journal WHERE member_id=? AND revision=? AND credential_revision=? AND state='settled' AND error_code=''", id, revision, member.CredentialRevision).Scan(&count); err != nil {
				return err
			}
			if count == 0 || member.ProbeRevision != revision || member.ProbeState != "ready" || member.CleanupOnly {
				return nodeConflict("S3 probe has no completed matching intent")
			}
		} else {
			now := time.Now().Unix()
			if _, err = q.ExecContext(ctx, "UPDATE s3_members SET probe_revision=0,probe_state='failed',error_code=?,updated_at=? WHERE member_id=?", code, now, id); err != nil {
				return err
			}
			if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET health='offline',writable=0,updated_at=? WHERE member_id=?", now, id); err != nil {
				return err
			}
		}
		result, err = r.s3Member(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3RecoveryProbes(ctx context.Context, limit int) ([]store.S3Probe, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+s3ProbeColumns+" FROM s3_probe_journal WHERE state<>'settled' ORDER BY updated_at,probe_id LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []store.S3Probe{}
	for rows.Next() {
		v, err := scanS3Probe(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
