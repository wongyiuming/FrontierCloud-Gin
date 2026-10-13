package resourcemigration

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type trafficRepository struct {
	store.MigrationRepository
	mutex   sync.Mutex
	states  []string
	entered chan struct{}
}

func (r *trafficRepository) MigrationRunState(_ context.Context, _ store.MigrationLease, phase, _, code string, _ store.NodeAudit) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.states = append(r.states, phase+":"+code)
	if code == "waiting_business_traffic" && len(r.states) == 1 {
		close(r.entered)
	}
	return nil
}

type trafficCaller struct {
	busy   *atomic.Bool
	source string
}

func (c trafficCaller) Call(_ context.Context, rel store.Relationship, path string, _ any) (map[string]any, error) {
	if path != prefix+"traffic" {
		return nil, store.ErrMigrationState
	}
	v := businesstraffic.View{State: "low_traffic", CanRun: true, ObservedAt: time.Now().UnixMilli(), High: businesstraffic.HighBytesPerSecond, Low: businesstraffic.LowBytesPerSecond, WindowSeconds: 5, LowSeconds: 30}
	if c.busy.Load() && rel.PeerID == c.source {
		v.CanRun = false
		v.State = "high_traffic"
		v.Recent = v.High
	}
	return map[string]any{"node_id": rel.PeerID, "traffic": v}, nil
}
func TestMigrationTrafficWaitingResumesAndNeverOverridesManualPause(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic-low-traffic", true: "manual-pause"}[manual], func(t *testing.T) {
			source, target := store.Relationship{PeerID: strings.Repeat("a", 32)}, store.Relationship{PeerID: strings.Repeat("b", 32)}
			var busy, paused atomic.Bool
			busy.Store(true)
			repo := &trafficRepository{entered: make(chan struct{})}
			r := &Runner{Repository: repo, Client: trafficCaller{&busy, source.PeerID}}
			s := trafficSchedule{runner: r, source: source, target: target, task: strings.Repeat("c", 32)}
			lease := store.MigrationLease{TaskID: s.task}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- s.wait(ctx, &lease, "queued", "", func() error {
					if paused.Load() {
						return store.ErrMigrationLease
					}
					return nil
				})
			}()
			select {
			case <-repo.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			v := r.ExecutionStatus(s.task)
			for v == nil && ctx.Err() == nil {
				time.Sleep(time.Millisecond)
				v = r.ExecutionStatus(s.task)
			}
			if v == nil || v.State != "waiting_traffic" || v.WaitingNode != source.PeerID {
				t.Fatal(v)
			}
			paused.Store(manual)
			busy.Store(false)
			e := <-done
			if manual && e != store.ErrMigrationLease || !manual && e != nil {
				t.Fatal(e)
			}
			repo.mutex.Lock()
			defer repo.mutex.Unlock()
			if manual && len(repo.states) != 1 || !manual && (len(repo.states) != 2 || repo.states[1] != "queued:") {
				t.Fatal(repo.states)
			}
		})
	}
}

func TestPeerBurstReplacesCachedQuietObservationBeforeWaitIsVisible(t *testing.T) {
	source, target := strings.Repeat("a", 32), strings.Repeat("b", 32)
	quiet := businesstraffic.View{State: "low_traffic", CanRun: true, ObservedAt: time.Now().UnixMilli(), High: businesstraffic.HighBytesPerSecond, Low: businesstraffic.LowBytesPerSecond, WindowSeconds: 5, LowSeconds: 30}
	repo := &trafficRepository{entered: make(chan struct{})}
	r := &Runner{Repository: repo, Traffic: businesstraffic.New(nil)}
	s := trafficSchedule{runner: r, source: store.Relationship{PeerID: source}, target: store.Relationship{PeerID: target}, master: strings.Repeat("d", 32), task: strings.Repeat("c", 32), views: []store.MigrationTraffic{{NodeID: source, Role: "source", View: quiet}, {NodeID: target, Role: "target", View: quiet}}}
	busy := quiet
	busy.CanRun, busy.State, busy.Recent = false, "high_traffic", busy.High
	if s.observePeerWait(source, quiet) == nil || s.observePeerWait("unknown", busy) == nil {
		t.Fatal("invalid wait observation accepted")
	}
	stale := busy
	stale.ObservedAt = time.Now().Add(-time.Minute).UnixMilli()
	if s.observePeerWait(source, stale) == nil {
		t.Fatal("stale peer refusal accepted")
	}
	if e := s.observePeerWait(source, busy); e != nil {
		t.Fatal(e)
	}
	if e := s.markWait(context.Background(), store.MigrationLease{TaskID: s.task}, "copying", "object", source); e != nil {
		t.Fatal(e)
	}
	v := r.ExecutionStatus(s.task)
	if v == nil || len(v.Traffic) != 3 || v.WaitingNode != source || v.Traffic[1].View.CanRun || v.Traffic[1].View.Recent != busy.High || !v.Traffic[2].View.CanRun {
		t.Fatal("first visible wait lost fresh peer traffic", v)
	}
}
