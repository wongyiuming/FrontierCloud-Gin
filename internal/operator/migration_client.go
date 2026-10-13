package operator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/url"
	"strings"
)

var ErrMigrationClientConflict = errors.New("migration task state or identity changed; query status and confirm its current revision")

func (c *NodeClient) migrationMaster(ctx context.Context) (string, error) {
	if c.csrf == "" {
		return "", ErrNodeAuthority
	}
	var nodes struct {
		Role string `json:"role"`
		ID   string `json:"node_id"`
	}
	status, e := c.request(ctx, "GET", "/nodes", "", "application/json", &nodes)
	if e != nil || status != 200 {
		return "", ErrNodeClient
	}
	if nodes.Role != "Master" || !nodeClientID(nodes.ID) {
		return "", ErrNodeAuthority
	}
	return nodes.ID, nil
}
func clientHash(value string) bool {
	decoded, e := hex.DecodeString(value)
	return e == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
func validClientTask(task store.MigrationTask, master, id string) bool {
	if task.ID != id || task.MasterID != master || !nodeClientID(task.ID) || !nodeClientID(task.SourceID) || !nodeClientID(task.TargetID) || task.SourceID == task.TargetID || task.SourceID == master || task.TargetID == master || !clientHash(task.PlanSHA) || task.Revision < 1 || task.ObjectCount < 0 || task.TotalBytes < 0 || task.CommittedBytes < 0 || task.CommittedBytes > task.TotalBytes || len(task.ErrorCode) > 64 {
		return false
	}
	switch task.State {
	case "queued", "copying", "verifying", "committing", "cleanup_pending", "paused", "cancelling", "cancelled", "failed", "completed":
		return true
	}
	return false
}
func (c *NodeClient) MigrationStatus(ctx context.Context, id, after string) (store.MigrationStatus, error) {
	var report store.MigrationStatus
	if !nodeClientID(id) || after != "" && !clientHash(after) {
		return report, ErrNodeAuthority
	}
	master, e := c.migrationMaster(ctx)
	if e != nil {
		return report, e
	}
	path := "/nodes/migrations/" + id
	query := ""
	if after != "" {
		query = url.Values{"after": {after}}.Encode()
	}
	status, e := c.requestQuery(ctx, "GET", path, query, "", "application/json", &report)
	if e != nil {
		return store.MigrationStatus{}, e
	}
	if status != 200 {
		return store.MigrationStatus{}, ErrMigrationClientConflict
	}
	if !validClientTask(report.Task, master, id) || report.RetirementReady || report.After != after || len(report.Objects) > 16 || len(report.ObjectStages) > 16 || len(report.UnitStages) > 16 {
		return store.MigrationStatus{}, ErrNodeClient
	}
	for _, stages := range [][]store.MigrationStage{report.ObjectStages, report.UnitStages} {
		for _, stage := range stages {
			if stage.Count < 1 || stage.Bytes < 0 || stage.VerifiedBytes < 0 || stage.VerifiedBytes > stage.Bytes || len(stage.State) > 32 {
				return store.MigrationStatus{}, ErrNodeClient
			}
		}
	}
	last := after
	for _, object := range report.Objects {
		if !clientHash(object.ID) || !clientHash(object.UnitID) || object.ID <= last || len(object.Path) > 4096 || len(object.State) > 32 || object.Bytes < 0 || object.VerifiedBytes < 0 || object.VerifiedBytes > object.Bytes {
			return store.MigrationStatus{}, ErrNodeClient
		}
		last = object.ID
	}
	raw, e := json.Marshal(report.Objects)
	if e != nil || len(raw) > (48<<10)+32 || report.Next != last || !report.Complete && last == after {
		return store.MigrationStatus{}, ErrNodeClient
	}
	return report, nil
}
func (c *NodeClient) ControlMigration(ctx context.Context, id, action string, revision int64, source, target string) (store.MigrationTask, error) {
	var task store.MigrationTask
	if !nodeClientID(id) || revision < 1 || !nodeClientID(source) || !nodeClientID(target) || source == target {
		return task, ErrNodeAuthority
	}
	switch action {
	case "pause", "resume", "cancel", "retry":
	default:
		return task, ErrNodeAuthority
	}
	master, e := c.migrationMaster(ctx)
	if e != nil {
		return task, e
	}
	if source == master || target == master {
		return task, ErrNodeAuthority
	}
	body, _ := json.Marshal(map[string]any{"action": action, "revision": revision, "confirm_source_id": source, "confirm_target_id": target})
	status, e := c.request(ctx, "POST", "/nodes/migrations/"+id+"/control", string(body), "application/json", &task)
	if e != nil {
		return store.MigrationTask{}, e
	}
	if status != 200 {
		return store.MigrationTask{}, ErrMigrationClientConflict
	}
	if !validClientTask(task, master, id) || task.SourceID != source || task.TargetID != target || task.Revision < revision {
		return store.MigrationTask{}, ErrNodeClient
	}
	return task, nil
}
