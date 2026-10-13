package resourcemigration

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

type trafficSchedule struct {
	runner         *Runner
	source, target store.Relationship
	task, master   string
	views          []store.MigrationTraffic
	expires        time.Time
	waiting        bool
	waited         time.Duration
}

func trafficDelay(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func validTraffic(v businesstraffic.View) bool {
	now := time.Now().UnixMilli()
	if v.ObservedAt < now-5000 || v.ObservedAt > now+5000 || v.Ingress < 0 || v.Egress < 0 || v.Recent < 0 || v.High != businesstraffic.HighBytesPerSecond || v.Low != businesstraffic.LowBytesPerSecond || v.WindowSeconds != 5 || v.LowSeconds != 30 || v.ResumeAfter < 0 || v.ResumeAfter > 30 {
		return false
	}
	return v.CanRun && v.State == "low_traffic" && v.ResumeAfter == 0 || !v.CanRun && (v.State == "high_traffic" || v.State == "cooldown" || v.State == "unavailable" && v.Reason == "edge_traffic_unavailable")
}

// A peer can encounter a new burst after the cached scheduler observation.
// Retain its authenticated fresh refusal observation before displaying wait.
func (s *trafficSchedule) observePeerWait(nodeID string, view businesstraffic.View) error {
	if nodeID != s.source.PeerID && nodeID != s.target.PeerID || view.CanRun || !validTraffic(view) {
		return store.ErrMigrationState
	}
	for i := range s.views {
		if s.views[i].NodeID == nodeID {
			s.views[i].View = view
			s.expires = time.Time{}
			return nil
		}
	}
	return store.ErrMigrationState
}
func (s *trafficSchedule) markWait(ctx context.Context, lease store.MigrationLease, phase, object, nodeID string) error {
	if !s.waiting {
		if e := s.runner.Repository.MigrationRunState(ctx, lease, phase, object, "waiting_business_traffic", store.NodeAudit{}); e != nil {
			return e
		}
		s.waiting = true
	}
	s.runner.executionMutex.Lock()
	if s.runner.execution == nil || s.runner.execution.TaskID != s.task {
		s.runner.execution = &store.MigrationExecution{TaskID: s.task}
	}
	v := s.runner.execution
	v.State, v.ObjectID, v.WaitingNode, v.Speed, v.ObservedAt = "waiting_traffic", object, nodeID, 0, time.Now().UnixMilli()
	v.Traffic = append([]store.MigrationTraffic(nil), s.views...)
	if s.runner.Traffic != nil {
		found := false
		for i := range v.Traffic {
			if v.Traffic[i].Role == "master" {
				v.Traffic[i].View = s.runner.Traffic.Snapshot()
				found = true
			}
		}
		if !found {
			v.Traffic = append([]store.MigrationTraffic{{NodeID: s.master, Role: "master", View: s.runner.Traffic.Snapshot()}}, v.Traffic...)
		}
	}
	s.runner.executionMutex.Unlock()
	return nil
}
func (s *trafficSchedule) wait(ctx context.Context, lease *store.MigrationLease, phase, object string, ensure func() error) error {
	started := time.Now()
	blocked := false
	defer func() {
		if blocked {
			s.waited += time.Since(started)
		}
	}()
	for {
		if e := ensure(); e != nil {
			return e
		}
		views := []store.MigrationTraffic{}
		if s.runner.Traffic != nil {
			views = append(views, store.MigrationTraffic{NodeID: s.master, Role: "master", View: s.runner.Traffic.Snapshot()})
		}
		if time.Now().After(s.expires) {
			s.views = nil
			for i, rel := range []store.Relationship{s.source, s.target} {
				value, e := s.runner.request(ctx, rel, prefix+"traffic", map[string]any{})
				if e != nil {
					return e
				}
				var response struct {
					ID   string               `json:"node_id"`
					View businesstraffic.View `json:"traffic"`
				}
				if e = decode(value, &response); e != nil || response.ID != rel.PeerID || !validTraffic(response.View) {
					return store.ErrMigrationState
				}
				role := "source"
				if i == 1 {
					role = "target"
				}
				s.views = append(s.views, store.MigrationTraffic{NodeID: rel.PeerID, Role: role, View: response.View})
			}
			s.expires = time.Now().Add(time.Second)
		}
		views = append(views, s.views...)
		waiting := ""
		for _, peer := range views {
			if !peer.View.CanRun {
				waiting = peer.NodeID
				break
			}
		}
		if waiting == "" {
			if s.waiting {
				if e := s.runner.Repository.MigrationRunState(ctx, *lease, phase, object, "", store.NodeAudit{}); e != nil {
					return e
				}
				s.waiting = false
			}
			s.runner.executionMutex.Lock()
			if s.runner.execution == nil || s.runner.execution.TaskID != s.task {
				s.runner.execution = &store.MigrationExecution{TaskID: s.task}
			}
			v := s.runner.execution
			if v.ObjectID != object {
				v.CurrentBytes, v.CurrentTotal, v.Speed = 0, 0, 0
			}
			v.State, v.ObjectID, v.WaitingNode, v.ObservedAt = phase, object, "", time.Now().UnixMilli()
			v.Traffic = append([]store.MigrationTraffic(nil), views...)
			s.runner.executionMutex.Unlock()
			return nil
		}
		blocked = true
		s.views = views
		if e := s.markWait(ctx, *lease, phase, object, waiting); e != nil {
			return e
		}
		// Avoid retaining a duplicate Master entry in the peer cache.
		if s.runner.Traffic != nil {
			s.views = s.views[1:]
		}
		if e := trafficDelay(ctx); e != nil {
			return e
		}
	}
}

func (r *Runner) progress(task, phase, object string, offset, total int64) {
	r.executionMutex.Lock()
	defer r.executionMutex.Unlock()
	now := time.Now().UnixMilli()
	if r.execution == nil || r.execution.TaskID != task {
		r.execution = &store.MigrationExecution{TaskID: task}
	}
	v := r.execution
	speed := int64(0)
	if v.ObjectID == object && offset > v.CurrentBytes && now > v.ObservedAt {
		speed = (offset - v.CurrentBytes) * 1000 / (now - v.ObservedAt)
	}
	v.State, v.ObjectID, v.CurrentBytes, v.CurrentTotal, v.Speed, v.ObservedAt = phase, object, offset, total, speed, now
}

// Live observations supplement durable SQL/peer checkpoints. They are never
// authority to commit or resume a manually paused task.
func (r *Runner) ExecutionStatus(task string) *store.MigrationExecution {
	r.executionMutex.RLock()
	defer r.executionMutex.RUnlock()
	if r.execution == nil || r.execution.TaskID != task || r.execution.ObservedAt < time.Now().Add(-5*time.Second).UnixMilli() {
		return nil
	}
	copy := *r.execution
	copy.Traffic = append([]store.MigrationTraffic(nil), copy.Traffic...)
	return &copy
}
