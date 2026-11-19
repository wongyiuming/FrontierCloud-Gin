package node

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func observedInteger(value map[string]any, key string) int64 {
	n, _ := intField(value, key)
	return max(0, n)
}
func observedBool(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case json.Number:
		n, err := v.Int64()
		return err == nil && n != 0
	}
	return false
}
func observedText(value map[string]any, key, fallback string) string {
	v, _ := value[key].(string)
	if v == "" {
		return fallback
	}
	return v
}

func hostUsageView(relation *store.Relationship, now int64) map[string]any {
	if relation == nil || relation.Direction != "downstream" || relation.State != "active" || relation.Status != "online" ||
		relation.LastHeartbeat <= 0 || relation.LastHeartbeat > now || now-relation.LastHeartbeat >= 120 {
		return nil
	}
	report, _ := relation.Summary["host_usage"].(map[string]any)
	if len(report) == 0 {
		return nil
	}
	result := map[string]any{}
	if cpu, ok := intField(report, "cpu_percent"); ok && cpu >= 0 && cpu <= 100 {
		result["cpu_percent"] = cpu
	}
	used, haveUsed := intField(report, "memory_used_bytes")
	total, haveTotal := intField(report, "memory_total_bytes")
	if haveUsed && haveTotal && total > 0 && used >= 0 && used <= total {
		result["memory_used_bytes"] = used
		result["memory_total_bytes"] = total
	}
	return result
}

func connectionView(relation *store.Relationship) map[string]any {
	if relation == nil {
		return map[string]any{"status": "local", "current_rtt_ms": 0, "min_rtt_ms": 0, "avg_rtt_ms": 0, "max_rtt_ms": 0, "sample_count": 0, "last_heartbeat": 0, "failures": 0, "recoveries": 0}
	}
	h, _ := relation.Summary["heartbeat"].(map[string]any)
	current := observedInteger(h, "current_ms")
	if current == 0 {
		current = int64(max(0, relation.RTT))
	}
	read := func(name string) int64 {
		n := observedInteger(h, name)
		if n == 0 {
			return current
		}
		return n
	}
	count := observedInteger(h, "count")
	if count == 0 && current != 0 {
		count = 1
	}
	window := observedInteger(h, "window_seconds")
	if window == 0 {
		window = 3600
	}
	status := relation.Status
	if status == "" {
		status = "unknown"
	}
	return map[string]any{"status": status, "current_rtt_ms": current, "min_rtt_ms": read("min_ms"), "avg_rtt_ms": read("avg_ms"), "max_rtt_ms": read("max_ms"), "sample_count": count, "window_seconds": window, "last_heartbeat": max(0, relation.LastHeartbeat), "failures": max(0, relation.Failures), "recoveries": max(0, relation.Recoveries)}
}
func resourceSync(desired, observed map[string]any, keys []string, online bool) string {
	if !online {
		return "offline"
	}
	if len(observed) == 0 {
		return "awaiting"
	}
	for _, key := range keys {
		if v, ok := desired[key].(bool); ok {
			if v != observedBool(observed[key]) {
				return "syncing"
			}
		} else {
			left, ok1 := intField(desired, key)
			right, ok2 := intField(observed, key)
			if !ok1 || !ok2 || left != right {
				return "syncing"
			}
		}
	}
	return "effective"
}
func backupView(configured, observed map[string]any, now int64) map[string]any {
	enabled := observedBool(configured["enabled"])
	last := observedInteger(configured, "last_success")
	if last == 0 {
		last = observedInteger(observed, "last_success")
	}
	state := observedText(observed, "state", observedText(configured, "state", "disabled"))
	attemptState := observedText(observed, "last_attempt_state", state)
	attempt := observedInteger(observed, "last_attempt")
	running := state == "receiving"
	if configuredAttempt := observedInteger(configured, "last_attempt"); configuredAttempt > attempt {
		attempt = configuredAttempt
		attemptState = observedText(configured, "last_attempt_state", state)
		running = attemptState == "receiving"
	}
	lag := int64(0)
	if enabled && last != 0 {
		lag = max(0, now-last)
	}
	health := "healthy"
	switch {
	case !enabled:
		health = "disabled"
	case running || attemptState == "receiving":
		health = "running"
	case attemptState == "failed":
		health = "failed"
	case last == 0:
		health = "waiting-first-backup"
	case lag > 30*60*60:
		health = "stale"
	}
	generation := observedInteger(configured, "generation")
	if generation == 0 {
		generation = observedInteger(observed, "generation")
	}
	checksum := observedText(configured, "checksum", observedText(observed, "checksum", ""))
	if len(checksum) > 64 {
		checksum = checksum[:64]
	}
	due := int64(0)
	if enabled && last > 0 {
		due = min(last, math.MaxInt64-24*60*60) + 24*60*60
	}
	if enabled && attemptState == "failed" && attempt > 0 {
		due = min(attempt, math.MaxInt64-5*60) + 5*60
	}
	return map[string]any{"enabled": enabled, "health": health, "raw_state": state, "generation": generation, "last_success": last, "lag_seconds": lag, "next_due": due, "checksum": checksum, "last_size_bytes": observedInteger(observed, "last_size_bytes"), "recovery_points": observedInteger(observed, "recovery_points"), "last_attempt": attempt, "last_attempt_state": attemptState}
}

// Observability projects existing authoritative members and heartbeat facts.
// It never probes peers, invents liveness, or exposes relationship credentials.
func (s *Service) Observability(ctx context.Context) (map[string]any, error) {
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	relations, err := s.repo.Relationships(ctx, false)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	result := map[string]any{"generated_at": now, "role": identity.Role, "members": []map[string]any{}}
	if identity.Role != "Master" {
		views := []map[string]any{}
		for _, r := range relations {
			views = append(views, map[string]any{"relationship_id": r.ID, "peer_id": r.PeerID, "connection": connectionView(&r)})
		}
		result["relationships"] = views
		return result, nil
	}
	if s.pool == nil {
		return nil, store.ErrNodeState
	}
	members, err := s.pool.Members(ctx)
	if err != nil {
		return nil, err
	}
	views := []map[string]any{}
	for _, member := range members {
		var relation *store.Relationship
		for _, r := range relations {
			if r.PeerID == member.ID && member.RelationshipID != nil && r.ID == *member.RelationshipID {
				copy := r
				relation = &copy
				break
			}
		}
		storage, observedBackup := map[string]any{}, map[string]any{}
		if relation != nil {
			if v, ok := relation.Summary["storage"].(map[string]any); ok {
				storage = v
			}
			if v, ok := relation.Summary["backup"].(map[string]any); ok {
				observedBackup = v
			}
		}
		online := member.Kind == "MasterLocal" || relation != nil && relation.Status == "online"
		storageSync := resourceSync(map[string]any{"enabled": member.Enabled != 0, "allocated_bytes": member.Allocation}, storage, []string{"enabled", "allocated_bytes"}, online)
		backupSync := resourceSync(map[string]any{"enabled": observedBool(member.Backup["enabled"])}, observedBackup, []string{"enabled"}, online)
		if member.Kind == "MasterLocal" {
			storageSync, backupSync = "effective", "effective"
		}
		observed := map[string]any{"storage": storage, "backup": observedBackup}
		if usage := hostUsageView(relation, now); len(usage) != 0 {
			observed["host_usage"] = usage
		}
		views = append(views, map[string]any{"member_id": member.ID, "member_kind": member.Kind, "relationship_id": member.RelationshipID, "connection": connectionView(relation), "sync": map[string]any{"storage": storageSync, "backup": backupSync}, "observed": observed, "backup": backupView(member.Backup, observedBackup, now)})
	}
	// A concurrent reset cannot turn a stale Master projection into authority.
	current, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if current.ID != identity.ID || current.Role != identity.Role {
		return nil, store.ErrNodeState
	}
	result["members"] = views
	return result, nil
}
