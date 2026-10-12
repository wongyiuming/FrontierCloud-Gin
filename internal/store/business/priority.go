package business

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/text/cases"
)

func (r *Repository) priorityIdentity(ctx context.Context, q queryer) (store.NodeIdentity, error) {
	node, err := readNode(ctx, q, r.lock())
	// Local metadata can be prepared before node identity initialization. Live
	// runtimes initialize the singleton before accepting Admin traffic.
	if errors.Is(err, sql.ErrNoRows) {
		return store.NodeIdentity{Role: "Standalone"}, nil
	}
	return node, err
}

// Directory ties follow the public category comparator; media ties follow the
// public playback comparator. The planner must use those exact comparators.
func priorityTie(a, b store.PriorityEntry, kind string) bool {
	if kind == "directory" {
		fold := cases.Fold()
		x, y := fold.String(a.Path), fold.String(b.Path)
		if x != y {
			return x < y
		}
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.ID < b.ID
}

func priorityRevision(scope store.PriorityScope, items []store.PriorityEntry) string {
	data, _ := json.Marshal(struct {
		Path, Kind string
		Items      []store.PriorityEntry
	}{scope.Path, scope.Kind, items})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (r *Repository) priorityOrder(ctx context.Context, q queryer, scope store.PriorityScope) (store.PriorityOrder, error) {
	result := store.PriorityOrder{Scope: scope.Path, Kind: scope.Kind, Items: []store.PriorityEntry{}}
	node, err := r.priorityIdentity(ctx, q)
	if err != nil {
		return result, err
	}
	if node.Role == "Follower" {
		return result, store.ErrNodeState
	}
	if scope.Path == "" || (scope.Kind != "media" && scope.Kind != "directory") {
		return result, store.ErrPriorityMove
	}
	objects := scope.Objects
	if node.Role == "Master" {
		if err := r.checkGlobalRenameScopes(ctx, q, []store.DeleteItem{{Path: scope.Path, Directory: true}}); err != nil {
			return result, err
		}
		where, args := r.pathScope("media_path", scope.Path, true)
		var reserved int
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM cluster_upload_sessions WHERE state='reserved' AND "+where, args...).Scan(&reserved); err != nil {
			return result, err
		}
		if reserved != 0 {
			return result, store.ErrNodeState
		}
		rows, err := q.QueryContext(ctx, "SELECT media_id,media_path,object_kind,state FROM global_media_objects WHERE "+where+" ORDER BY media_path,media_id"+r.lock(), args...)
		if err != nil {
			return result, err
		}
		objects = nil
		directories := map[string]bool{}
		for rows.Next() {
			var o store.MediaObject
			var state string
			if err = rows.Scan(&o.ID, &o.Path, &o.Kind, &state); err != nil {
				break
			}
			if state != "active" {
				err = store.ErrNodeState
				break
			}
			if scope.Kind == "media" && path.Dir(o.Path) == scope.Path {
				objects = append(objects, o)
			}
			if scope.Kind == "directory" && strings.HasPrefix(o.Path, scope.Path+"/") {
				rest := strings.TrimPrefix(o.Path, scope.Path+"/")
				if strings.Contains(rest, "/") {
					d := scope.Path + "/" + strings.Split(rest, "/")[0]
					if strings.Count(d, "/") <= 2 && !directories[d] {
						objects = append(objects, store.MediaObject{Path: d, Kind: "directory"})
						directories[d] = true
					}
				}
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return result, err
		}
	}
	// Load facts once for the entire scope, including hidden and off-page peers.
	where, args := r.pathScope("media_path", scope.Path, true)
	rows, err := q.QueryContext(ctx, "SELECT media_id,media_path,preference FROM media_playback_stats WHERE "+where+" ORDER BY media_id"+r.lock(), args...)
	if err != nil {
		return result, err
	}
	byID := map[string]int{}
	for rows.Next() {
		var id, p string
		var value int
		if err = rows.Scan(&id, &p, &value); err != nil {
			break
		}
		byID[id] = value
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return result, err
	}
	identityRows, err := q.QueryContext(ctx, "SELECT media_id,media_path,object_kind FROM media_objects WHERE "+where+" ORDER BY media_id"+r.lock(), args...)
	if err != nil {
		return result, err
	}
	identities := map[string]store.MediaObject{}
	for identityRows.Next() {
		var object store.MediaObject
		if err = identityRows.Scan(&object.ID, &object.Path, &object.Kind); err != nil {
			break
		}
		identities[object.Path] = object
	}
	if err == nil {
		err = identityRows.Err()
	}
	identityRows.Close()
	if err != nil {
		return result, err
	}
	for _, o := range objects {
		if path.Dir(o.Path) != scope.Path {
			return result, store.ErrPriorityMove
		}
		if o.ID == "" {
			if object, ok := identities[o.Path]; ok && object.Kind == o.Kind {
				o.ID = object.ID
			}
		}
		value := byID[o.ID]
		result.Items = append(result.Items, store.PriorityEntry{ID: o.ID, Path: o.Path, Preference: value, ObjectKind: o.Kind})
	}
	sort.Slice(result.Items, func(i, j int) bool {
		a, b := result.Items[i], result.Items[j]
		if a.Preference != b.Preference {
			return a.Preference > b.Preference
		}
		return priorityTie(a, b, scope.Kind)
	})
	result.Revision = priorityRevision(scope, result.Items)
	return result, nil
}

func (r *Repository) PriorityOrder(ctx context.Context, scope store.PriorityScope) (result store.PriorityOrder, err error) {
	err = r.write(ctx, func(q queryer) error { var err error; result, err = r.priorityOrder(ctx, q, scope); return err })
	return
}

// Each canonical inversion needs one integer step. Expand a contiguous window
// until those steps fit between its unchanged neighbours. Work is linear; no
// catalog-wide unique renumbering, fractional ranks or new tie-break store.
func planPriority(items []store.PriorityEntry, at int, kind string) error {
	return planPriorityRange(items, at, kind, store.PriorityMinimum, store.PriorityMaximum)
}

func planPriorityRange(items []store.PriorityEntry, at int, kind string, minimum, maximum int) error {
	n := len(items)
	gap := make([]int, n)
	for i := 1; i < n; i++ {
		gap[i] = gap[i-1]
		if !priorityTie(items[i-1], items[i], kind) {
			gap[i]++
		}
	}
	l, r := at, at
	limits := func(l, r int) (int, int) {
		hi, lo := maximum, minimum
		if l > 0 {
			hi = items[l-1].Preference - (gap[l] - gap[l-1])
		}
		if r+1 < n {
			lo = items[r+1].Preference + (gap[r+1] - gap[r])
		}
		return hi, lo
	}
	for {
		hi, lo := limits(l, r)
		if hi-lo >= gap[r]-gap[l] {
			for i := l; i <= r; i++ {
				minimum := lo + gap[r] - gap[i]
				items[i].Preference = max(minimum, min(hi, items[i].Preference))
				if i < r {
					hi = items[i].Preference - (gap[i+1] - gap[i])
				}
			}
			return nil
		}
		if l == 0 && r == n-1 {
			return store.ErrPriorityRange
		}
		leftGain, rightGain := -1, -1
		if l > 0 {
			upper, _ := limits(l-1, r)
			leftGain = upper - hi - (gap[l] - gap[l-1])
		}
		if r+1 < n {
			_, lower := limits(l, r+1)
			rightGain = lo - lower - (gap[r+1] - gap[r])
		}
		if l > 0 && (r == n-1 || leftGain > rightGain || leftGain == rightGain && at-l <= r-at) {
			l--
		} else {
			r++
		}
	}
}

func (r *Repository) MovePriority(ctx context.Context, scope store.PriorityScope, move store.PriorityMove, audit store.AdminAudit) (result store.PriorityOrder, err error) {
	err = r.write(ctx, func(q queryer) error {
		current, e := r.priorityOrder(ctx, q, scope)
		if e != nil {
			return e
		}
		if move.Revision != current.Revision {
			return store.ErrPriorityStale
		}
		if move.Path == "" || move.Before == move.Path || move.After == move.Path || (move.Before == "" && move.After == "") {
			return store.ErrPriorityMove
		}
		items := make([]store.PriorityEntry, 0, len(current.Items))
		var moved store.PriorityEntry
		old := map[string]int{}
		for _, v := range current.Items {
			old[v.Path] = v.Preference
			if v.Path == move.Path {
				moved = v
			} else {
				items = append(items, v)
			}
		}
		if moved.Path == "" {
			return store.ErrPriorityMove
		}
		at := -1
		for i := 0; i <= len(items); i++ {
			before, after := "", ""
			if i < len(items) {
				before = items[i].Path
			}
			if i > 0 {
				after = items[i-1].Path
			}
			if before == move.Before && after == move.After {
				at = i
				break
			}
		}
		if at < 0 {
			return store.ErrPriorityMove
		}
		items = append(items, store.PriorityEntry{})
		copy(items[at+1:], items[at:])
		items[at] = moved
		if e := planPriority(items, at, scope.Kind); e != nil {
			return e
		}
		paths := []string{}
		changes := []map[string]any{}
		now := timestamp(time.Now())
		for i := range items {
			v := &items[i]
			if old[v.Path] == v.Preference {
				continue
			}
			id := v.ID
			if v.ObjectKind == "directory" || id == "" {
				id, e = r.ensure(ctx, q, store.MediaObject{Path: v.Path, Kind: v.ObjectKind})
				if e != nil {
					return e
				}
			}
			query := "INSERT INTO media_playback_stats(media_id,media_path,play_score,preference,created_at,updated_at) VALUES (?,?,0,?,?,?)"
			if r.backend == "sqlite" {
				query += " ON CONFLICT(media_id) DO UPDATE SET preference=excluded.preference,updated_at=excluded.updated_at"
			} else {
				query += " ON DUPLICATE KEY UPDATE preference=VALUES(preference),updated_at=VALUES(updated_at)"
			}
			if _, e = q.ExecContext(ctx, query, id, v.Path, v.Preference, now, now); e != nil {
				return e
			}
			paths = append(paths, v.Path)
			changes = append(changes, map[string]any{"path": v.Path, "before": old[v.Path], "after": v.Preference})
		}
		// Audit failure rolls the complete preference batch back.
		if len(paths) > 0 {
			if e = appendPriorityAudit(ctx, q, audit, scope, move, paths, changes); e != nil {
				return e
			}
		}
		result, e = r.priorityOrder(ctx, q, scope)
		result.Changed = len(paths)
		return e
	})
	return
}

func appendPriorityAudit(ctx context.Context, q queryer, audit store.AdminAudit, scope store.PriorityScope, move store.PriorityMove, paths []string, changes []map[string]any) error {
	// appendAudit bounds fields at 10000 runes. Split complete JSON evidence,
	// including the plan origin, instead of truncating a large collision batch.
	for start := 0; start < len(paths); {
		end := start
		var detail []byte
		for end < len(paths) {
			candidate, err := json.Marshal(map[string]any{"scope": scope.Path, "kind": scope.Kind, "move": move, "changes": changes[start : end+1], "changed_total": len(paths)})
			if err != nil {
				return err
			}
			if utf8.RuneCount(candidate) > 9500 {
				break
			}
			detail = candidate
			end++
		}
		if end == start {
			return store.ErrPriorityMove
		}
		audit.Detail = string(detail)
		audit.Result = "success"
		audit.TargetCount = end - start
		if err := appendMutationAudit(ctx, q, audit, paths[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}
