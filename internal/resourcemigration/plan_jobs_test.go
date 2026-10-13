package resourcemigration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type plannerFixture struct {
	mutex            sync.Mutex
	calls, starts    int
	changeBytes      bool
	observationError error
	blockers         int
	entered          chan struct{}
	release          chan struct{}
}

func (f *plannerFixture) ObservePlan(ctx context.Context, id, source, target string, progress func(int64, int64)) (PlanObservation, error) {
	if f.observationError != nil {
		return PlanObservation{}, f.observationError
	}
	f.mutex.Lock()
	f.calls++
	call := f.calls
	f.mutex.Unlock()
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return PlanObservation{}, ctx.Err()
		case <-f.release:
		}
	}
	sha := strings.Repeat("1", 64)
	if f.changeBytes && call > 1 {
		sha = strings.Repeat("2", 64)
	}
	objects := []store.MigrationObject{}
	proofs := []store.MigrationDiskProof{}
	for i := 0; i < 17; i++ {
		id := strings.Repeat("0", 62) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
		o := store.MigrationObject{ID: id, ObjectID: id, Resource: "media", Path: "music/unit/" + id + ".mp3", TargetPath: "music/unit/" + id + ".mp3", Parent: "music/unit", Kind: "audio", Bytes: 7, Version: strings.Repeat("3", 64)}
		objects = append(objects, o)
		proofs = append(proofs, store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: 7, SHA256: sha})
	}
	progress(17, 119)
	now := time.Now().Unix()
	blocks := make([]store.MigrationBlocker, f.blockers)
	for i := range blocks {
		blocks[i] = store.MigrationBlocker{Code: "fixture_conflict", Resource: strings.Repeat("a", 32)}
	}
	return PlanObservation{Plan: store.MigrationPlan{ID: id, Catalog: store.MigrationCatalog{MasterID: strings.Repeat("9", 32), Source: store.StorageMember{ID: source}, Target: store.StorageMember{ID: target}, Version: strings.Repeat("4", 64), Objects: objects, TotalBytes: 119, Blockers: blocks}, Proofs: proofs, TargetFree: 10 * store.GiB, TargetAbsent: true, CreatedAt: now, ExpiresAt: now + 300}}, nil
}

func TestPlannerBoundsBlockerSamplesWithoutLosingAdmissionBlock(t *testing.T) {
	f := &plannerFixture{blockers: 70}
	p, e := newPlanner(context.Background(), f, f)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	v, e := p.Create(strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32))
	if e != nil {
		t.Fatal(e)
	}
	v = awaitPlan(t, p, v.ID, "blocked")
	if v.BlockerCount != 70 || len(v.Blockers) != 64 {
		t.Fatal("unbounded or missing blockers", v.BlockerCount, len(v.Blockers))
	}
	if _, e = p.Start(v.ID, v.ReviewSHA, v.Source.ID, v.Target.ID, store.NodeAudit{}); e == nil {
		t.Fatal("truncated blockers admitted start")
	}
}
func (f *plannerFixture) StartMigration(ctx context.Context, p store.MigrationPlan, a store.NodeAudit) (store.MigrationTask, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.starts++
	return store.MigrationTask{ID: p.ID, SourceID: p.Catalog.Source.ID, TargetID: p.Catalog.Target.ID, State: "queued"}, nil
}
func awaitPlan(t *testing.T, p *Planner, id string, state string) PlanView {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		v, e := p.Status(id, "")
		if e != nil {
			t.Fatal(e)
		}
		if v.State == state {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("plan state", v.State, v.ErrorCode)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestPlannerAsyncPaginationFreshProofAndIdempotentStart(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "same_metadata_changed_bytes"}[change], func(t *testing.T) {
			f := &plannerFixture{changeBytes: change}
			p, e := newPlanner(context.Background(), f, f)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			request, source, target := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
			v, e := p.Create(request, source, target)
			if e != nil {
				t.Fatal(e)
			}
			v = awaitPlan(t, p, v.ID, "ready")
			if v.ObjectCount != 17 || v.UnitCount != 1 || len(v.Objects) != 16 || v.Complete || v.VerifiedBytes != 119 {
				t.Fatal(v)
			}
			last, e := p.Status(v.ID, v.Next)
			if e != nil || len(last.Objects) != 1 || !last.Complete {
				t.Fatal(last, e)
			}
			replayed, e := p.Create(request, source, target)
			if e != nil || replayed.ID != v.ID || replayed.ReviewSHA != v.ReviewSHA {
				t.Fatal("create replay", replayed, e)
			}
			if _, e = p.Start(v.ID, strings.Repeat("0", 64), source, target, store.NodeAudit{}); e == nil {
				t.Fatal("unreviewed plan started")
			}
			if _, e = p.Start(v.ID, v.ReviewSHA, target, source, store.NodeAudit{}); e == nil {
				t.Fatal("swapped confirmation started")
			}
			if _, e = p.Start(v.ID, v.ReviewSHA, source, target, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if !change {
				if _, e = p.Start(v.ID, v.ReviewSHA, source, target, store.NodeAudit{}); e != nil {
					t.Fatal("start replay", e)
				}
				awaitPlan(t, p, v.ID, "started")
			} else {
				awaitPlan(t, p, v.ID, "failed")
			}
			f.mutex.Lock()
			calls, starts := f.calls, f.starts
			f.mutex.Unlock()
			if calls != 2 || !change && starts != 1 || change && starts != 0 {
				t.Fatal("fresh observation or commit count", calls, starts)
			}
		})
	}
}
func TestPlannerSingleWorkerCloseJoinsAndRejectsExpiredPlan(t *testing.T) {
	f := &plannerFixture{entered: make(chan struct{}, 1), release: make(chan struct{})}
	p, e := newPlanner(context.Background(), f, f)
	if e != nil {
		t.Fatal(e)
	}
	v, e := p.Create(strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32))
	if e != nil {
		t.Fatal(e)
	}
	<-f.entered
	if _, e = p.Create(strings.Repeat("4", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)); e != ErrPlanBusy {
		t.Fatal(e)
	}
	close(f.release)
	v = awaitPlan(t, p, v.ID, "ready")
	p.mutex.Lock()
	p.current.view.ExpiresAt = time.Now().Unix() - 1
	p.mutex.Unlock()
	if _, e = p.Start(v.ID, v.ReviewSHA, v.Source.ID, v.Target.ID, store.NodeAudit{}); e != ErrPlanState {
		t.Fatal("expired started", e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Status(v.ID, ""); e != ErrPlanState {
		t.Fatal(e)
	}
	blocked := &plannerFixture{entered: make(chan struct{}, 1), release: make(chan struct{})}
	p, e = newPlanner(context.Background(), blocked, blocked)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Create(strings.Repeat("5", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)); e != nil {
		t.Fatal(e)
	}
	<-blocked.entered
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestPlannerReportsOnlyControlledObservationStage(t *testing.T) {
	secret := errors.New("https://private-node.example/token?secret=hidden; signed-body")
	for _, stage := range []PlanObservationStage{PlanStageCatalog, PlanStageSourceInventory, PlanStageSourceContent, PlanStageTargetInventory, PlanStageSeal, PlanStageAdmission, "https://untrusted-stage.example"} {
		t.Run(string(stage), func(t *testing.T) {
			failure := &PlanObservationError{Stage: stage, Cause: secret}
			if !errors.Is(failure, secret) || strings.Contains(failure.Error(), "secret") {
				t.Fatal("unsafe or lost internal cause")
			}
			f := &plannerFixture{observationError: failure}
			p, e := newPlanner(context.Background(), f, f)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			v, e := p.Create(strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32))
			if e != nil {
				t.Fatal(e)
			}
			v = awaitPlan(t, p, v.ID, "failed")
			expected := stage
			if strings.HasPrefix(string(stage), "https:") {
				expected = ""
			}
			if v.ErrorStage != expected || v.ErrorCode != "physical_observation_changed_or_unavailable" {
				t.Fatal(v.ErrorStage, v.ErrorCode)
			}
			raw, e := json.Marshal(v)
			if e != nil || strings.Contains(string(raw), "https:") || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "signed-body") {
				t.Fatal("underlying peer diagnostics leaked")
			}
		})
	}
}
