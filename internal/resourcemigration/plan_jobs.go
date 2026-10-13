package resourcemigration

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrPlanBusy = errors.New("another migration plan observation is active")
var ErrPlanState = errors.New("migration plan expired, changed or unavailable")

type PlanView struct {
	ID              string                     `json:"plan_id"`
	RequestID       string                     `json:"request_id"`
	State           string                     `json:"state"`
	Source          store.StorageMember        `json:"source"`
	Target          store.StorageMember        `json:"target"`
	ReviewSHA       string                     `json:"review_sha256"`
	ObjectCount     int64                      `json:"object_count"`
	UnitCount       int64                      `json:"unit_count"`
	Bytes           int64                      `json:"total_bytes"`
	VerifiedObjects int64                      `json:"verified_objects"`
	VerifiedBytes   int64                      `json:"verified_bytes"`
	AdditionalBytes int64                      `json:"additional_target_bytes"`
	TargetFree      int64                      `json:"target_physical_free"`
	PhysicalReserve int64                      `json:"physical_reserve_bytes"`
	CreatedAt       int64                      `json:"created_at"`
	ExpiresAt       int64                      `json:"expires_at"`
	ErrorCode       string                     `json:"error_code,omitempty"`
	ErrorStage      PlanObservationStage       `json:"error_stage,omitempty"`
	Blockers        []store.MigrationBlocker   `json:"blockers"`
	BlockerCount    int64                      `json:"blocker_count"`
	SourceVolumes   []resourceinventory.Volume `json:"source_volumes"`
	TargetVolumes   []resourceinventory.Volume `json:"target_volumes"`
	Concerns        []PlanConcern              `json:"source_residuals"`
	BackupItems     int64                      `json:"source_backup_items"`
	Task            *store.MigrationTask       `json:"task,omitempty"`
	After           string                     `json:"after"`
	Next            string                     `json:"next"`
	Complete        bool                       `json:"complete"`
	Objects         []store.MigrationObject    `json:"objects"`
}

type planBuilder interface {
	ObservePlan(context.Context, string, string, string, func(int64, int64)) (PlanObservation, error)
}
type planStarter interface {
	StartMigration(context.Context, store.MigrationPlan, store.NodeAudit) (store.MigrationTask, error)
}
type plannedWork struct {
	view        PlanView
	observation PlanObservation
	audit       store.NodeAudit
	active      bool
}
type Planner struct {
	mutex   sync.Mutex
	builder planBuilder
	starter planStarter
	ctx     context.Context
	cancel  context.CancelFunc
	queue   chan *plannedWork
	done    chan struct{}
	current *plannedWork
	closed  bool
}

// One joined worker observes ephemeral plans; only StartMigration persists a
// task. A process restart invalidates previews and never loses a started task.
func NewPlanner(parent context.Context, runner *Runner) (*Planner, error) {
	if runner == nil || runner.Repository == nil {
		return nil, ErrPlanState
	}
	return newPlanner(parent, runner, runner.Repository)
}
func newPlanner(parent context.Context, builder planBuilder, starter planStarter) (*Planner, error) {
	if parent == nil || builder == nil || starter == nil {
		return nil, ErrPlanState
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Planner{builder: builder, starter: starter, ctx: ctx, cancel: cancel, queue: make(chan *plannedWork, 1), done: make(chan struct{})}
	go p.run()
	return p, nil
}
func (p *Planner) Create(requestID, source, target string) (PlanView, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.closed || !planHex(requestID, 16) || !planHex(source, 16) || !planHex(target, 16) || source == target {
		return PlanView{}, ErrPlanState
	}
	if p.current != nil {
		if p.current.view.RequestID == requestID {
			if p.current.view.Source.ID != source || p.current.view.Target.ID != target {
				return PlanView{}, ErrPlanState
			}
			return p.pageLocked(p.current, "")
		}
		if p.current.active {
			return PlanView{}, ErrPlanBusy
		}
	}
	id, e := planToken()
	if e != nil {
		return PlanView{}, e
	}
	w := &plannedWork{active: true, view: PlanView{ID: id, RequestID: requestID, State: "observing", Source: store.StorageMember{ID: source}, Target: store.StorageMember{ID: target}, CreatedAt: time.Now().Unix(), PhysicalReserve: store.PhysicalReserve, Objects: []store.MigrationObject{}, Blockers: []store.MigrationBlocker{}, Concerns: []PlanConcern{}}}
	p.current = w
	p.queue <- w
	return p.pageLocked(w, "")
}
func (p *Planner) Status(id, after string) (PlanView, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.closed || p.current == nil || p.current.view.ID != id || !planHex(id, 16) || after != "" && !planHex(after, 16) && !planHex(after, 32) {
		return PlanView{}, ErrPlanState
	}
	return p.pageLocked(p.current, after)
}
func (p *Planner) Start(id, review, source, target string, audit store.NodeAudit) (PlanView, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	w := p.current
	if p.closed || w == nil || w.view.ID != id || !planHex(review, 32) || review != w.view.ReviewSHA || source != w.view.Source.ID || target != w.view.Target.ID {
		return PlanView{}, ErrPlanState
	}
	if w.view.State == "starting" || w.view.State == "started" {
		return p.pageLocked(w, "")
	}
	if w.active || w.view.State != "ready" || w.view.ExpiresAt <= time.Now().Unix() {
		return PlanView{}, ErrPlanState
	}
	w.active = true
	w.audit = audit
	w.view.State = "starting"
	w.view.VerifiedObjects = 0
	w.view.VerifiedBytes = 0
	p.queue <- w
	return p.pageLocked(w, "")
}
func (p *Planner) pageLocked(w *plannedWork, after string) (PlanView, error) {
	if !w.active && (w.view.State == "ready" || w.view.State == "blocked") && w.view.ExpiresAt <= time.Now().Unix() {
		w.view.State = "expired"
	}
	v := w.view
	v.Objects = []store.MigrationObject{}
	v.After = after
	v.Next = after
	v.Complete = true
	// UI and durable execution have independent page sizes. New plans read
	// immutable bindings directly and never materialize the entire catalog.
	pageBytes := 0
	objects := w.observation.Plan.Catalog.Objects
	if w.observation.Plan.Format != "" {
		repository, ok := p.starter.(store.MigrationPlanRepository)
		if !ok {
			return PlanView{}, ErrPlanState
		}
		var e error
		objects, e = repository.MigrationPlanPage(p.ctx, w.view.ID, after)
		if e != nil {
			return PlanView{}, e
		}
	}
	for _, o := range objects {
		if o.ID <= after {
			continue
		}
		if len(v.Objects) == 16 {
			v.Complete = false
			break
		}
		raw, e := json.Marshal(o)
		if e != nil {
			return PlanView{}, e
		}
		if pageBytes+len(raw) > 48<<10 {
			if len(v.Objects) == 0 {
				return PlanView{}, ErrPlanState
			}
			v.Complete = false
			break
		}
		pageBytes += len(raw)
		v.Objects = append(v.Objects, o)
		v.Next = o.ID
	}
	return v, nil
}
func (p *Planner) run() {
	defer close(p.done)
	for {
		select {
		case <-p.ctx.Done():
			return
		case w := <-p.queue:
			p.observe(w)
		}
	}
}
func (p *Planner) observe(w *plannedWork) {
	p.mutex.Lock()
	starting := w.view.State == "starting"
	id, source, target := w.view.ID, w.view.Source.ID, w.view.Target.ID
	p.mutex.Unlock()
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	observation, e := p.builder.ObservePlan(ctx, id, source, target, func(count, bytes int64) {
		p.mutex.Lock()
		defer p.mutex.Unlock()
		w.view.VerifiedObjects = count
		w.view.VerifiedBytes = bytes
	})
	var task store.MigrationTask
	if starting && e == nil {
		old := w.observation.Plan
		previous, err := store.MigrationDigest(old.Proofs)
		if old.Format != "" {
			previous = old.ProofsSHA
		}
		if err != nil {
			e = err
		}
		fresh, err := store.MigrationDigest(observation.Plan.Proofs)
		if observation.Plan.Format != "" {
			fresh = observation.Plan.ProofsSHA
		}
		if err != nil {
			e = err
		}
		if old.Catalog.Version != observation.Plan.Catalog.Version || previous != fresh || observation.Plan.Catalog.TotalBlockers() != 0 || !observation.Plan.TargetAbsent {
			e = ErrPlanState
		}
		if e == nil {
			task, e = p.starter.StartMigration(ctx, observation.Plan, w.audit)
		}
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	w.active = false
	if e != nil {
		w.view.State = "failed"
		w.view.ErrorCode = "physical_observation_changed_or_unavailable"
		w.view.ErrorStage = planErrorStage(e)
		if starting && w.view.ErrorStage == "" {
			w.view.ErrorStage = PlanStageAdmission
		}
		logPlanFailure(ctx, slog.Default(), &PlanObservationError{Stage: w.view.ErrorStage, Cause: e})
		if errors.Is(e, store.ErrMigrationInventoryLimit) {
			w.view.ErrorCode = "catalog_exceeds_current_task_limit"
		}
		return
	}
	if starting {
		w.view.State = "started"
		w.view.Task = &task
		return
	}
	w.observation = observation
	c := observation.Plan.Catalog
	w.view.Source = c.Source
	w.view.Target = c.Target
	w.view.ObjectCount = int64(len(c.Objects))
	if observation.Plan.Format != "" {
		w.view.ObjectCount = observation.Plan.ObjectCount
	}
	w.view.Bytes = c.TotalBytes
	w.view.AdditionalBytes = c.TotalBytes
	w.view.TargetFree = observation.Plan.TargetFree
	w.view.BlockerCount = c.TotalBlockers()
	w.view.Blockers = c.Blockers[:min(len(c.Blockers), 64)]
	w.view.SourceVolumes = observation.SourceVolumes
	w.view.TargetVolumes = observation.TargetVolumes
	w.view.Concerns = observation.Concerns
	w.view.BackupItems = observation.BackupItems
	w.view.ExpiresAt = observation.Plan.ExpiresAt
	if w.view.ExpiresAt == 0 {
		w.view.ExpiresAt = time.Now().Unix() + 300
	}
	units := map[string]bool{}
	for _, o := range c.Objects {
		units[o.Resource+":"+o.Parent] = true
	}
	w.view.UnitCount = int64(len(units))
	if observation.Plan.Format != "" {
		w.view.UnitCount = observation.Plan.UnitCount
	}
	w.view.ReviewSHA, e = store.MigrationDigest(observation.Plan)
	if e != nil {
		w.view.State = "failed"
		w.view.ErrorCode = "catalog_exceeds_current_task_limit"
		return
	}
	w.view.State = "ready"
	if c.TotalBlockers() > 0 {
		w.view.State = "blocked"
	}
}
func (p *Planner) Close() error {
	p.mutex.Lock()
	p.closed = true
	p.cancel()
	p.mutex.Unlock()
	<-p.done
	return nil
}
