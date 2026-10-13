package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestReadyRestoreRetriesRecordedStageCleanupWithoutRemovingAdminMaintenance(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "fc-cleanup", factory)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory); e != nil {
		t.Fatal(e)
	}
	member := orderedSetMembers(report.Manifest)[0]
	d, r, e := openRestoredMember(ctx, state, member, factory)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := d.openRestore(ctx, r, member.NodeID, true)
	if e != nil {
		t.Fatal(e)
	}
	_, ready, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(target, member.NodeID, "data")
	stage := filepath.Join(data, restoreManualStage)
	if e = os.WriteFile(stage, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	admin := filepath.Join(data, sitecontrol.Manual)
	if e = os.WriteFile(admin, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	journal.StageCleanupWarning = "generated staging remains pending"
	if e = d.saveRestore(journal); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Backup(ctx, ready, filepath.Join(target, "new.tar"), false, false); e == nil {
		t.Fatal("pending cleanup material silently backed up")
	}
	journal, e = d.openRestore(ctx, ready, member.NodeID, true)
	if e != nil || journal.StageCleanupWarning != "" {
		t.Fatal(journal.StageCleanupWarning, e)
	}
	if _, e = os.Stat(stage); !os.IsNotExist(e) {
		t.Fatal("generated stage retained", e)
	}
	if _, e = os.Stat(admin); e != nil {
		t.Fatal("administrator maintenance removed", e)
	}
}
