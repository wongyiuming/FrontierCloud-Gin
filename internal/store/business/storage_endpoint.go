package business

import (
	"context"
	"net/url"
	"strconv"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// These methods are offline maintenance operations, not remote control APIs.
// Callers must hold the closed DATA_ROOT maintenance gate with all writers stopped.
func validStorageEndpoint(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(value) > 512 {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port >= 1024 && port <= 65535
}

func endpointIdle(ctx context.Context, q queryer) error {
	for _, query := range []string{
		"SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'",
		"SELECT COUNT(*) FROM cluster_upload_sessions WHERE state NOT IN ('complete','cancelled')",
		"SELECT COUNT(*) FROM global_media_objects WHERE state<>'active'",
		"SELECT COUNT(*) FROM karaoke_recordings WHERE state NOT IN ('ready','deleted')",
		"SELECT COUNT(*) FROM karaoke_users WHERE status NOT IN ('active','banned','deleted')",
		"SELECT COUNT(*) FROM cluster_storage_members WHERE reserved_bytes<>0",
		"SELECT COUNT(*) FROM cluster_business_backups WHERE state NOT IN ('ready','failed')",
		"SELECT COUNT(*) FROM cluster_worker_jobs WHERE state NOT IN ('queued','complete')",
	} {
		var count int64
		if err := q.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return store.ErrBackupBusy
		}
	}
	return nil
}

func (r *Repository) MoveStorageEndpoint(ctx context.Context, id, previous, next string) error {
	if !nodeIDPattern.MatchString(id) || previous == "" || previous == next || !validStorageEndpoint(next) {
		return store.ErrNodeState
	}
	return r.write(ctx, func(q queryer) error {
		identity, err := readNode(ctx, q, r.lock())
		if err != nil {
			return err
		}
		if identity.ID != id || identity.Role != "Follower" || (identity.Endpoint != previous && identity.Endpoint != next) {
			return store.ErrNodeState
		}
		if err := endpointIdle(ctx, q); err != nil {
			return err
		}
		if identity.Endpoint == next {
			return nil
		}
		if _, err := q.ExecContext(ctx, "UPDATE node_identity SET endpoint=? WHERE singleton=1", next); err != nil {
			return err
		}
		return r.nodeAudit(ctx, q, "storage-endpoint-moved", "", map[string]any{"previous": previous, "next": next}, store.NodeAudit{Actor: "offline-storage-handover"})
	})
}

// expected contains the exact peer key and encrypted credential used during the
// signed challenge. Rechecking them in the transaction prevents probe/write races.
func (r *Repository) RebindStorageEndpoint(ctx context.Context, master string, expected store.Relationship, next string) error {
	if !nodeIDPattern.MatchString(master) || !validStorageEndpoint(next) || expected.Endpoint == next {
		return store.ErrNodeState
	}
	return r.withRelation(ctx, expected.ID, func(q queryer, identity store.NodeIdentity, current store.Relationship) error {
		if identity.ID != master || identity.Role != "Master" || current.Direction != "downstream" || current.State != "active" ||
			current.PeerID != expected.PeerID || current.PublicKey != expected.PublicKey || current.Credential != expected.Credential ||
			(current.Endpoint != expected.Endpoint && current.Endpoint != next) {
			return store.ErrNodeState
		}
		if err := endpointIdle(ctx, q); err != nil {
			return err
		}
		if current.Endpoint == next {
			return nil
		}
		if _, err := q.ExecContext(ctx, "UPDATE node_relationships SET peer_endpoint=?,status='offline',last_heartbeat=0 WHERE relationship_id=?", next, current.ID); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, "UPDATE cluster_storage_members SET health='offline',writable=0 WHERE member_id=?", current.PeerID); err != nil {
			return err
		}
		return r.nodeAudit(ctx, q, "storage-endpoint-rebound", current.ID, map[string]any{"peer_id": current.PeerID, "previous": expected.Endpoint, "next": next}, store.NodeAudit{Actor: "offline-storage-handover"})
	})
}
