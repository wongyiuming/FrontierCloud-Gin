package operator

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func validClientPlan(v resourcemigration.PlanView, master, id, after string) bool {
 switch v.ErrorStage {
 case "", resourcemigration.PlanStageCatalog, resourcemigration.PlanStageSourceInventory, resourcemigration.PlanStageSourceContent, resourcemigration.PlanStageTargetInventory, resourcemigration.PlanStageSeal, resourcemigration.PlanStageAdmission:
 default: return false
 }
 if v.ErrorStage != "" && v.State != "failed" { return false }

	if v.BlockerCount < int64(len(v.Blockers)) || v.BlockerCount > store.MaxStorageAllocation || v.State == "ready" && v.BlockerCount != 0 {
		return false
	}
	if !nodeClientID(v.ID) || id != "" && v.ID != id || !nodeClientID(v.RequestID) || !nodeClientID(v.Source.ID) || !nodeClientID(v.Target.ID) || v.Source.ID == v.Target.ID || v.Source.ID == master || v.Target.ID == master || v.After != after || v.ObjectCount < 0 || v.ObjectCount > v.Bytes || v.UnitCount < 0 || v.UnitCount > v.ObjectCount || v.Bytes < 0 || v.Bytes > store.MaxStorageAllocation || v.VerifiedObjects < 0 || v.VerifiedBytes < 0 || v.TargetFree < 0 || v.AdditionalBytes < 0 || len(v.Objects) > 16 || len(v.Blockers) > 64 || len(v.Concerns) > 64 || len(v.ErrorCode) > 80 || len(v.SourceVolumes) > 3 || len(v.TargetVolumes) > 3 {
		return false
	}
	switch v.State {
	case "observing", "starting", "ready", "blocked", "started", "failed", "expired":
	default:
		return false
	}
	if (v.State == "ready" || v.State == "starting" || v.State == "started") && !clientHash(v.ReviewSHA) {
		return false
	}
	if v.State == "ready" && (len(v.Blockers) != 0 || v.VerifiedObjects != v.ObjectCount || v.VerifiedBytes != v.Bytes || v.ExpiresAt <= v.CreatedAt) {
		return false
	}
	last := after
	for _, o := range v.Objects {
		if o.ID <= last || !clientHash(o.ID) && !nodeClientID(o.ID) || !clientHash(o.Version) || len(o.Path) > 4096 || len(o.TargetPath) > 4096 || o.Bytes <= 0 || o.Resource != "media" && o.Resource != "recording" {
			return false
		}
		last = o.ID
	}
	raw, e := json.Marshal(v.Objects)
	if e != nil || len(raw) > (48<<10)+32 || v.Next != last || !v.Complete && last == after {
		return false
	}
	if v.State == "started" {
		if v.Task == nil || !validClientTask(*v.Task, master, v.ID) || v.Task.SourceID != v.Source.ID || v.Task.TargetID != v.Target.ID {
			return false
		}
	} else if v.Task != nil {
		return false
	}
	return true
}
func (c *NodeClient) migrationPlanRequest(ctx context.Context, method, path, query string, body any, id, after string) (resourcemigration.PlanView, error) {
	var v resourcemigration.PlanView
	master, e := c.migrationMaster(ctx)
	if e != nil {
		return v, e
	}
	payload := ""
	if body != nil {
		raw, e := json.Marshal(body)
		if e != nil {
			return v, e
		}
		payload = string(raw)
	}
	status, e := c.requestQuery(ctx, method, path, query, payload, "application/json", &v)
	if e != nil {
		return resourcemigration.PlanView{}, e
	}
	if status != 200 {
		return resourcemigration.PlanView{}, ErrMigrationClientConflict
	}
	if !validClientPlan(v, master, id, after) {
		return resourcemigration.PlanView{}, ErrNodeClient
	}
	return v, nil
}
func (c *NodeClient) CreateMigrationPlan(ctx context.Context, request, source, target string) (resourcemigration.PlanView, error) {
	if !nodeClientID(request) || !nodeClientID(source) || !nodeClientID(target) || source == target {
		return resourcemigration.PlanView{}, ErrNodeAuthority
	}
	v, e := c.migrationPlanRequest(ctx, "POST", "/nodes/migration-plans", "", map[string]any{"request_id": request, "source_id": source, "target_id": target}, "", "")
	if e == nil && (v.RequestID != request || v.Source.ID != source || v.Target.ID != target) {
		return resourcemigration.PlanView{}, ErrNodeClient
	}
	return v, e
}
func (c *NodeClient) MigrationPlanStatus(ctx context.Context, id, after string) (resourcemigration.PlanView, error) {
	if !nodeClientID(id) || after != "" && !nodeClientID(after) && !clientHash(after) {
		return resourcemigration.PlanView{}, ErrNodeAuthority
	}
	query := ""
	if after != "" {
		query = url.Values{"after": {after}}.Encode()
	}
	return c.migrationPlanRequest(ctx, "GET", "/nodes/migration-plans/"+id, query, nil, id, after)
}
func (c *NodeClient) StartMigrationPlan(ctx context.Context, id, review, source, target string) (resourcemigration.PlanView, error) {
	if !nodeClientID(id) || !clientHash(review) || !nodeClientID(source) || !nodeClientID(target) || source == target {
		return resourcemigration.PlanView{}, ErrNodeAuthority
	}
	v, e := c.migrationPlanRequest(ctx, "POST", "/nodes/migration-plans/"+id+"/start", "", map[string]any{"review_sha256": review, "confirm_source_id": source, "confirm_target_id": target}, id, "")
	if e == nil && (v.ReviewSHA != review || v.Source.ID != source || v.Target.ID != target) {
		return resourcemigration.PlanView{}, ErrNodeClient
	}
	return v, e
}
