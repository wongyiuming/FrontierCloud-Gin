package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterBackupObservationRejectsReplyDrift(t *testing.T) {
	master, follower, _, transport, rel, sender := backupDeliveryFixture(t)
	ctx := context.Background()
	if err := sender.DeliverBackup(ctx, rel.ID); err != nil {
		t.Fatal(err)
	}
	var generation int64
	if err := follower.db.Database().QueryRow("SELECT generation FROM cluster_business_backups WHERE master_id=? AND state='ready'", master.id).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	manifest, err := follower.db.Backups().(store.BackupObservationRepository).ReadyBackupManifest(ctx, rel.ID, follower.id, master.id, generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.ObserveBackup(ctx, rel.ID, manifest); err != nil {
		t.Fatal("actual byte observation", err)
	}
	mutations := map[string]func(*resourceinventory.ContentJob){
		"foreign-member":    func(j *resourceinventory.ContentJob) { j.Request.Binding.MemberID = strings.Repeat("f", 32) },
		"wrong-generation":  func(j *resourceinventory.ContentJob) { j.Request.ObjectID = "1" },
		"wrong-hash":        func(j *resourceinventory.ContentJob) { j.Observation.SHA256 = strings.Repeat("f", 64) },
		"prefix-only":       func(j *resourceinventory.ContentJob) { j.Observation.Bytes-- },
		"arbitrary-path":    func(j *resourceinventory.ContentJob) { j.Observation.Path = "/secrets/node.key" },
		"expiry-extension":  func(j *resourceinventory.ContentJob) { j.ExpiresAt++ },
		"expired":           func(j *resourceinventory.ContentJob) { j.ExpiresAt = time.Now().Unix() - 1 },
		"wrong-incarnation": func(j *resourceinventory.ContentJob) { j.Incarnation = strings.Repeat("f", 32) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			injected := false
			transport.after = func(route string, value map[string]any, err error) (map[string]any, error) {
				if err != nil || route != "/internal/v1/backup-observation" || value["state"] != "observed" {
					return value, err
				}
				var job resourceinventory.ContentJob
				if err := decodeInventory(value, &job); err != nil {
					t.Fatal(err)
				}
				mutate(&job)
				injected = true
				raw, err := json.Marshal(job)
				if err != nil {
					t.Fatal(err)
				}
				if err = controlJSON(raw, &value); err != nil {
					t.Fatal(err)
				}
				return value, nil
			}
			if _, err = sender.ObserveBackup(ctx, rel.ID, manifest); err == nil || !injected {
				t.Fatal("invalid successful observation accepted or fault not reached", err, injected)
			}
			transport.after = nil
		})
	}
	configuration, err := master.db.Pool().MemberConfiguration(ctx, follower.id)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Backup.Enabled = false
	if err = master.db.Pool().ConfigureMember(ctx, follower.id, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = sender.ObserveBackup(ctx, rel.ID, manifest); err == nil {
		t.Fatal("disabled backup target observed")
	}
}
