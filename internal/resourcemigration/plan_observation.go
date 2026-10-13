package resourcemigration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"iter"
	"math"
	"path"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrPlanObservation = errors.New("migration plan observation is incomplete or changed")

// Stages are controlled public diagnostics. The underlying error is retained
// only for internal errors.Is/As; paths, URLs and signed peer bodies are never
// included in this error's text or the plan response.
type PlanObservationStage string

const (
	PlanStageCatalog         PlanObservationStage = "catalog"
	PlanStageSourceInventory PlanObservationStage = "source_inventory"
	PlanStageSourceContent   PlanObservationStage = "source_content"
	PlanStageTargetInventory PlanObservationStage = "target_inventory"
	PlanStageSeal            PlanObservationStage = "seal"
	PlanStageAdmission       PlanObservationStage = "admission"
)

type PlanObservationError struct {
	Stage PlanObservationStage
	Cause error
}

func (e *PlanObservationError) Error() string { return "migration plan observation failed" }
func (e *PlanObservationError) Unwrap() error { return e.Cause }
func planErrorStage(err error) PlanObservationStage {
	var observation *PlanObservationError
	if !errors.As(err, &observation) {
		return ""
	}
	switch observation.Stage {
	case PlanStageCatalog, PlanStageSourceInventory, PlanStageSourceContent, PlanStageTargetInventory, PlanStageSeal, PlanStageAdmission:
		return observation.Stage
	default:
		return ""
	}
}

type PlanConcern struct {
	Code    string   `json:"code"`
	Count   int64    `json:"count"`
	Samples []string `json:"samples"`
}
type PlanObservation struct {
	Plan          store.MigrationPlan        `json:"-"`
	SourceVolumes []resourceinventory.Volume `json:"source_volumes"`
	TargetVolumes []resourceinventory.Volume `json:"target_volumes"`
	Concerns      []PlanConcern              `json:"source_residuals"`
	BackupItems   int64                      `json:"source_backup_items"`
}

func planToken() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func planHex(s string, length int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == length && hex.EncodeToString(b) == s
}
func (o *PlanObservation) concern(code, sample string) error {
	if len(code) > 80 || len(sample) > resourceinventory.MaxPathBytes+16 {
		return ErrPlanObservation
	}
	for i := range o.Concerns {
		if o.Concerns[i].Code == code {
			o.Concerns[i].Count++
			if len(o.Concerns[i].Samples) < 8 {
				o.Concerns[i].Samples = append(o.Concerns[i].Samples, sample)
			}
			return nil
		}
	}
	if len(o.Concerns) >= 64 {
		return ErrPlanObservation
	}
	o.Concerns = append(o.Concerns, PlanConcern{Code: code, Count: 1, Samples: []string{sample}})
	return nil
}

// ObservePlan is read-only. Every peer fact comes through the existing signed
// control transport. It hashes source bytes without holding a SQL transaction,
// then rechecks the complete catalog and both relationship bindings. The
// production repository persists bounded object pages for the whole task.
func (r *Runner) ObservePlan(ctx context.Context, id, source, target string, progress func(int64, int64)) (out PlanObservation, err error) {
	stage := PlanStageCatalog
	defer func() {
		if err != nil {
			err = &PlanObservationError{Stage: stage, Cause: err}
		}
	}()
	if !planHex(id, 16) || r.Repository == nil || r.Nodes == nil || r.Client == nil {
		return out, ErrPlanObservation
	}
	if r.Traffic != nil {
		if err = businesstraffic.Wait(ctx, r.Traffic.Snapshot); err != nil {
			return out, err
		}
	}
	var catalog store.MigrationCatalog
	var e error
	paged, usePages := r.Repository.(store.MigrationPlanRepository)
	if usePages {
		out.Plan, e = paged.BuildMigrationPlan(ctx, id, source, target)
		catalog = out.Plan.Catalog
	} else {
		catalog, e = r.Repository.MigrationCatalog(ctx, source, target)
	}
	if e != nil {
		return out, e
	}
	if !usePages {
		out.Plan = store.MigrationPlan{ID: id, Catalog: catalog, Proofs: []store.MigrationDiskProof{}}
	}
	out.Concerns = []PlanConcern{}
	if catalog.TotalBlockers() != 0 {
		out.Plan.CreatedAt = time.Now().Unix()
		out.Plan.ExpiresAt = out.Plan.CreatedAt + 300
		return out, nil
	}
	if catalog.Source.RelationshipID == nil || catalog.Target.RelationshipID == nil {
		return out, ErrPlanObservation
	}
	sr, e := r.Nodes.Relationship(ctx, *catalog.Source.RelationshipID)
	if e != nil {
		return out, e
	}
	tr, e := r.Nodes.Relationship(ctx, *catalog.Target.RelationshipID)
	if e != nil {
		return out, e
	}
	for _, rel := range []store.Relationship{sr, tr} {
		if rel.State != "active" || rel.Direction != "downstream" || rel.PeerID != source && rel.PeerID != target {
			return out, ErrPlanObservation
		}
	}
	stage = PlanStageSourceInventory
	expected := map[string]store.ExpectedPhysicalItem{}
	for _, scope := range []string{"data", "media", "recordings"} {
		if e = r.observePlanScope(ctx, sr, catalog.MasterID, scope, &out, expected); e != nil {
			return out, e
		}
	}
	if !usePages && len(expected) != len(catalog.Objects) {
		out.Plan.Catalog.AddBlocker("source_native_roster_changed", source)
	}
	if out.Plan.Catalog.TotalBlockers() != 0 {
		out.Plan.CreatedAt = time.Now().Unix()
		out.Plan.ExpiresAt = out.Plan.CreatedAt + 300
		return out, nil
	}
	stage = PlanStageSourceContent
	var verifiedBytes, verifiedObjects int64
	for o, err := range r.planObjects(ctx, out.Plan) {
		if err != nil {
			return out, err
		}
		item, ok := expected[o.Resource+":"+o.ObjectID]
		if usePages {
			item, e = paged.MigrationPlanNative(ctx, id, o.ID)
			if e != nil {
				return out, e
			}
			ok = true
		}
		scope := "media"
		if o.Resource == "recording" {
			scope = "recordings"
		}
		if !ok || item.Path != scope+"/"+o.Path || !planHex(item.MetadataSHA256, 32) || item.ExpectedBytes != nil && *item.ExpectedBytes != o.Bytes {
			return out, ErrPlanObservation
		}
		digest, e := store.MigrationNativeMetadataSHA(o, source)
		if e != nil || digest != item.MetadataSHA256 {
			return out, ErrPlanObservation
		}
		proof, e := r.observePlanContent(ctx, sr, catalog.MasterID, o, item)
		if e != nil {
			return out, e
		}
		if usePages {
			if e = paged.ObserveMigrationPlanProof(ctx, id, proof); e != nil {
				return out, e
			}
		} else {
			out.Plan.Proofs = append(out.Plan.Proofs, proof)
		}
		verifiedBytes += o.Bytes
		verifiedObjects++
		if progress != nil {
			progress(verifiedObjects, verifiedBytes)
		}
	}
	// Source hashes may take time. Observe target paths and free capacity only
	// afterwards, immediately before the final metadata/identity recheck.
	stage = PlanStageTargetInventory
	for _, scope := range []string{"data", "media", "recordings"} {
		if e = r.observePlanScope(ctx, tr, catalog.MasterID, scope, &out, expected); e != nil {
			return out, e
		}
	}
	stage = PlanStageSeal
	current := catalog
	if !usePages {
		current, e = r.Repository.MigrationCatalog(ctx, source, target)
	}
	if e != nil {
		return out, e
	}
	if current.Version != catalog.Version || current.SourceBinding != catalog.SourceBinding || current.TargetBinding != catalog.TargetBinding {
		return out, ErrPlanObservation
	}
	physicalBlockers := out.Plan.Catalog
	out.Plan.Catalog = current
	out.Plan.Catalog.MergeBlockers(physicalBlockers)
	// Capacity can be shared across roots. Taking the minimum free observation
	// and charging the entire transfer once is conservative for either shared
	// or separate filesystems; it never adds their free values together.
	free := int64(math.MaxInt64)
	for _, volume := range out.TargetVolumes {
		free = min(free, volume.FreeBytes)
	}
	if len(out.TargetVolumes) != 3 || free == math.MaxInt64 {
		return out, ErrPlanObservation
	}
	out.Plan.TargetFree = free
	out.Plan.TargetAbsent = physicalBlockers.TotalBlockers() == 0
	if free < store.PhysicalReserve || free-store.PhysicalReserve-current.Target.Reserved < current.TotalBytes {
		out.Plan.Catalog.AddBlocker("target_physical_capacity_insufficient", target)
	}
	now := time.Now().Unix()
	out.Plan.CreatedAt = now
	out.Plan.ExpiresAt = now + 300
	if usePages {
		out.Plan, e = paged.SealMigrationPlan(ctx, out.Plan)
		if e != nil {
			return out, e
		}
	}
	return out, nil
}

func (r *Runner) observePlanScope(ctx context.Context, rel store.Relationship, master, scope string, out *PlanObservation, expected map[string]store.ExpectedPhysicalItem) (err error) {
	id, e := planToken()
	if e != nil {
		return e
	}
	request := map[string]any{"action": "open", "member_id": rel.PeerID, "scope": scope, "session_id": id}
	value, e := r.request(ctx, rel, "/internal/v1/resource-inventory", request)
	if e != nil {
		return e
	}
	var session resourceinventory.Session
	if e = decode(value, &session); e != nil {
		return e
	}
	defer func() {
		if !planHex(session.Incarnation, 16) {
			return
		}
		finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, e := r.request(finish, rel, "/internal/v1/resource-inventory", map[string]any{"action": "close", "member_id": rel.PeerID, "scope": scope, "session_id": id, "incarnation": session.Incarnation})
		err = errors.Join(err, e)
	}()
	binding := resourceinventory.Binding{MemberID: rel.PeerID, MasterID: master, RelationshipID: rel.ID, Scope: scope}
	now := time.Now().Unix()
	if session.ID != id || !planHex(session.Incarnation, 16) || session.Binding != binding || session.CreatedAt < now-30 || session.CreatedAt > now+30 || session.ExpiresAt <= now || session.ExpiresAt != session.CreatedAt+300 {
		return ErrPlanObservation
	}
	request["incarnation"] = session.Incarnation
	call := func(action string) (map[string]any, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().Unix() >= session.ExpiresAt {
			return nil, ErrPlanObservation
		}
		request["action"] = action
		return r.request(ctx, rel, "/internal/v1/resource-inventory", request)
	}
	source := rel.PeerID == out.Plan.Catalog.Source.ID
	if scope == "data" {
		value, e = call("volumes")
		if e != nil {
			return e
		}
		var volumes struct {
			Session resourceinventory.Session  `json:"session"`
			Volumes []resourceinventory.Volume `json:"volumes"`
		}
		if e = decode(value, &volumes); e != nil {
			return e
		}
		if volumes.Session != session || len(volumes.Volumes) != 3 {
			return ErrPlanObservation
		}
		for i, name := range []string{"data", "media", "recordings"} {
			v := volumes.Volumes[i]
			if v.Scope != name || v.FreeBytes < 0 || v.TotalBytes < v.FreeBytes || v.ObservedAt < time.Now().Unix()-30 || v.ObservedAt > time.Now().Unix()+30 || v.WritableVerified {
				return ErrPlanObservation
			}
		}
		if source {
			out.SourceVolumes = volumes.Volumes
		} else {
			out.TargetVolumes = volumes.Volumes
		}
		if source {
			for _, resource := range []string{"media", "recording", "backup", "backup_chunk"} {
				after := ""
				complete := false
				for pageNo := 0; pageNo < 100000; pageNo++ {
					request["resource"], request["after"] = resource, after
					value, e = call("expected")
					if e != nil {
						return e
					}
					var page struct {
						Session  resourceinventory.Session    `json:"session"`
						Manifest store.ExpectedPhysicalPage   `json:"manifest"`
						Presence []resourceinventory.Presence `json:"presence"`
					}
					if e = decode(value, &page); e != nil {
						return e
					}
					if page.Session != session || page.Manifest.Resource != resource || page.Manifest.After != after || len(page.Manifest.Items) > 16 || len(page.Presence) != len(page.Manifest.Items) {
						return ErrPlanObservation
					}
					last := after
					for i, item := range page.Manifest.Items {
						cursor := item.ObjectID
						if item.Cursor != "" {
							cursor = item.Cursor
						}
						if cursor <= last {
							return ErrPlanObservation
						}
						last = cursor
						if resource == "backup" || resource == "backup_chunk" {
							out.BackupItems++
							if e = out.concern("backup_retention_required", item.ObjectID); e != nil {
								return e
							}
							continue
						}
						if page.Presence[i].State != "present" {
							return ErrPlanObservation
						}
						if out.Plan.Format != "" {
							if e = r.Repository.(store.MigrationPlanRepository).ObserveMigrationPlanNative(ctx, out.Plan.ID, resource, item); e != nil {
								return e
							}
						} else {
							if len(expected) >= store.MaxMigrationObjects {
								return ErrPlanObservation
							}
							expected[resource+":"+item.ObjectID] = item
						}
					}
					if page.Manifest.Next != last || !page.Manifest.Complete && last == after {
						return ErrPlanObservation
					}
					if page.Manifest.Complete {
						complete = true
						break
					}
					after = last
				}
				if !complete {
					return ErrPlanObservation
				}
			}
			delete(request, "resource")
			delete(request, "after")
		}
	}
	// Validate the scanner's complete rolling transcript. Only bounded samples
	// survive a page; no complete physical disk listing is retained.
	digest := sha256.New()
	count := uint64(0)
	bytes := int64(0)
	targetNames, targetParents, targetAncestors := planTargetPaths(out.Plan.Catalog.Objects, scope)
	for sequence := uint64(0); sequence < 100000; sequence++ {
		request["sequence"] = sequence
		value, e = call("page")
		if e != nil {
			return e
		}
		var page struct {
			resourceinventory.SessionPage
			Facts []store.PhysicalInventoryFact `json:"facts"`
		}
		if e = decode(value, &page); e != nil {
			return e
		}
		if page.Session != session || page.Page.Sequence != sequence || len(page.Page.Entries) > resourceinventory.PageEntries || len(page.Facts) != len(page.Page.Entries) {
			return ErrPlanObservation
		}
		for i, entry := range page.Page.Entries {
			if entry.LogicalBytes < 0 || bytes > math.MaxInt64-entry.LogicalBytes || len(entry.Path) > resourceinventory.MaxPathBytes {
				return ErrPlanObservation
			}
			count++
			bytes += entry.LogicalBytes
			raw, e := json.Marshal(entry)
			if e != nil {
				return e
			}
			digest.Write(raw)
			digest.Write([]byte{'\n'})
			fact := page.Facts[i]
			if source && fact.Blocking && fact.Category != "managed_media" && fact.Category != "managed_recording" {
				if e = out.concern("physical_"+fact.Category, scope+"/"+entry.Path); e != nil {
					return e
				}
			}
			conflict := false
			if !source && scope != "data" {
				if out.Plan.Format != "" {
					resource := "media"
					if scope == "recordings" {
						resource = "recording"
					}
					conflict, e = r.Repository.(store.MigrationPlanRepository).MigrationPlanPathConflict(ctx, out.Plan.ID, resource, entry.Path, entry.Kind == "directory")
					if e != nil {
						return e
					}
				} else {
					conflict = targetNames[entry.Path] || entry.Kind != "directory" && (targetAncestors[entry.Path] || targetParents[path.Dir(entry.Path)])
				}
			}
			if conflict {
				out.Plan.Catalog.AddBlocker("target_physical_path_conflict", scope+"/"+entry.Path)
			}
		}
		if page.Page.EntryCount != count || page.Page.LogicalBytes != bytes || page.Page.ObservationSHA256 != hex.EncodeToString(digest.Sum(nil)) {
			return ErrPlanObservation
		}
		if page.Page.Complete {
			return nil
		}
		if len(page.Page.Entries) == 0 {
			return ErrPlanObservation
		}
	}
	return ErrPlanObservation
}

func planTargetPaths(objects []store.MigrationObject, scope string) (names, parents, ancestors map[string]bool) {
	names, parents, ancestors = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, o := range objects {
		if (o.Resource == "media") != (scope == "media") {
			continue
		}
		names[o.TargetPath] = true
		parents[path.Dir(o.TargetPath)] = true
		for parent := path.Dir(o.TargetPath); parent != "." && parent != "/"; parent = path.Dir(parent) {
			ancestors[parent] = true
		}
	}
	return
}

func (r *Runner) observePlanContent(ctx context.Context, rel store.Relationship, master string, o store.MigrationObject, item store.ExpectedPhysicalItem) (proof store.MigrationDiskProof, err error) {
	id, e := planToken()
	if e != nil {
		return proof, e
	}
	req := resourceinventory.ContentRequest{ID: id, Binding: resourceinventory.Binding{MemberID: rel.PeerID, MasterID: master, RelationshipID: rel.ID, Scope: "data"}, Resource: o.Resource, ObjectID: o.ObjectID, MetadataSHA: item.MetadataSHA256, Bytes: o.Bytes}
	var incarnation string
	call := func(action string) (resourceinventory.ContentJob, error) {
		v, e := r.request(ctx, rel, "/internal/v1/content-observation", struct {
			Action string `json:"action"`
			resourceinventory.ContentRequest
			Incarnation string `json:"incarnation,omitempty"`
		}{action, req, incarnation})
		if e != nil {
			return resourceinventory.ContentJob{}, e
		}
		var job resourceinventory.ContentJob
		e = decode(v, &job)
		return job, e
	}
	startedAt := time.Now().Unix()
	job, e := call("start")
	if e != nil {
		return proof, e
	}
	incarnation = job.Incarnation
	first := job
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, e := r.request(finish, rel, "/internal/v1/content-observation", struct {
			Action string `json:"action"`
			resourceinventory.ContentRequest
			Incarnation string `json:"incarnation"`
		}{"cancel", req, incarnation})
		err = errors.Join(err, e)
	}()
	var pollWait time.Duration
	for {
		now := time.Now().Unix()
		if job.Request != req || !planHex(job.Incarnation, 16) || job.Incarnation != incarnation || job.CreatedAt != first.CreatedAt || first.CreatedAt < startedAt-30 || job.ExpiresAt != first.ExpiresAt || job.CreatedAt > now+30 || job.ExpiresAt <= now || job.ExpiresAt != job.CreatedAt+int64(resourceinventory.ContentObservationTTL(req.Bytes)/time.Second) || job.ErrorCode != "" {
			return proof, ErrPlanObservation
		}
		if job.State == "observed" {
			actual := job.Observation
			if actual == nil || actual.Path != item.Path || actual.Bytes != o.Bytes || !planHex(actual.SHA256, 32) || o.Resource == "recording" && actual.SHA256 != o.ETag {
				return proof, ErrPlanObservation
			}
			return store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: actual.Bytes, SHA256: actual.SHA256}, nil
		}
		if job.State != "queued" && job.State != "running" {
			return proof, ErrPlanObservation
		}
		if job.Observation != nil {
			return proof, ErrPlanObservation
		}
		// Start always queues a job. Check once immediately so a small file
		// does not pay a fixed 250 ms floor; pending work then backs off.
		if pollWait > 0 {
			timer := time.NewTimer(pollWait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return proof, ctx.Err()
			case <-timer.C:
			}
		}
		pollWait = min(max(25*time.Millisecond, pollWait*2), 250*time.Millisecond)
		job, e = call("status")
		if e != nil {
			return proof, e
		}
	}
}

func (r *Runner) planObjects(ctx context.Context, p store.MigrationPlan) iter.Seq2[store.MigrationObject, error] {
	return func(yield func(store.MigrationObject, error) bool) {
		if p.Format == "" {
			for _, o := range p.Catalog.Objects {
				if !yield(o, nil) {
					return
				}
			}
			return
		}
		repository, ok := r.Repository.(store.MigrationPlanRepository)
		if !ok {
			yield(store.MigrationObject{}, store.ErrMigrationState)
			return
		}
		after := ""
		for {
			page, e := repository.MigrationPlanPage(ctx, p.ID, after)
			if e != nil {
				yield(store.MigrationObject{}, e)
				return
			}
			for _, o := range page {
				if o.ID <= after {
					yield(store.MigrationObject{}, store.ErrMigrationState)
					return
				}
				if !yield(o, nil) {
					return
				}
				after = o.ID
			}
			if len(page) < store.MigrationPageObjects {
				return
			}
		}
	}
}
