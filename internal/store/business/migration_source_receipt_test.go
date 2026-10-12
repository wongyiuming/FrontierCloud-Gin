package business_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestResourceMigrationSourceReceiptKeepsCleanupScopesAndTargetAuthority(t *testing.T) {
	f:=migrationDatabase(t); ctx:=context.Background(); p:=f.plan(t,hashPath(t.Name())[:32])
	if _,e:=f.repo.StartMigration(ctx,p,store.NodeAudit{}); e!=nil { t.Fatal(e) }
	l,e:=f.repo.ClaimMigration(ctx,p.ID,strings.Repeat("e",32),time.Minute); if e!=nil { t.Fatal(e) }
	w,e:=f.repo.MigrationWork(ctx,p.ID); if e!=nil { t.Fatal(e) }
	for _,cp:=range w.Objects { if e=f.repo.VerifyMigrationObject(ctx,l,cp.Object.ID,cp.Object.Bytes,cp.SourceSHA); e!=nil { t.Fatal(e) } }
	for _,u:=range w.Units {
		if e=f.repo.PrepareMigrationPublication(ctx,l,u.ID); e!=nil { t.Fatal(e) }
		for _,cp:=range w.Objects { if cp.UnitID==u.ID { if e=f.repo.PublishMigrationObject(ctx,l,cp.Object.ID); e!=nil { t.Fatal(e) } } }
		if e=f.repo.CommitMigrationUnit(ctx,l,u.ID,store.NodeAudit{}); e!=nil { t.Fatal(e) }
	}
	cp:=w.Objects[0]
	receipt:=store.MigrationSourceReceipt{TaskID:p.ID,SourceID:f.source,TargetID:f.target,PlanSHA:w.Task.PlanSHA,Proof:store.MigrationDiskProof{ID:cp.Object.ID,Version:cp.Object.Version,Bytes:cp.Object.Bytes,SHA256:cp.SourceSHA},ManagedCopyDeleted:true}
	if e=f.repo.RecordMigrationSourceDeletion(ctx,l,receipt,store.NodeAudit{}); !errors.Is(e,store.ErrMigrationState) { t.Fatal("grace bypass",e) }
	now:=time.Now().Unix()
	if _,e=f.raw.Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?",now-3601,now-1,p.ID); e!=nil { t.Fatal(e) }
	wrong:=receipt; wrong.PlanSHA=strings.Repeat("0",64)
	if e=f.repo.RecordMigrationSourceDeletion(ctx,l,wrong,store.NodeAudit{}); !errors.Is(e,store.ErrMigrationState) { t.Fatal("wrong receipt binding",e) }
	if e=f.repo.MigrationRunState(ctx,l,"cleanup_pending",cp.Object.ID,"source_cleanup",store.NodeAudit{}); e!=nil { t.Fatal(e) }
	if e=f.repo.ReleaseMigration(ctx,l); e!=nil { t.Fatal(e) }
	if id,e:=f.repo.NextMigrationRun(ctx); e!=nil || id!="" { t.Fatal("cleanup error auto-retry",id,e) }
	if _,e=f.repo.ControlMigration(ctx,p.ID,"retry",store.NodeAudit{}); e!=nil { t.Fatal(e) }
	if id,e:=f.repo.NextMigrationRun(ctx); e!=nil || id!=p.ID { t.Fatal("due cleanup not scheduled",id,e) }
	l,e=f.repo.ClaimMigration(ctx,p.ID,strings.Repeat("f",32),time.Minute); if e!=nil { t.Fatal(e) }
	before,e:=f.repo.MigrationTask(ctx,p.ID); if e!=nil { t.Fatal(e) }
	for range 2 { if e=f.repo.RecordMigrationSourceDeletion(ctx,l,receipt,store.NodeAudit{}); e!=nil { t.Fatal(e) } }
	after,e:=f.repo.MigrationTask(ctx,p.ID); if e!=nil || after.Revision!=before.Revision+1 || after.State!="cleanup_pending" { t.Fatal("receipt completed task or repeated progress",after,e) }
	var scopes int
	if e=f.raw.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?",p.ID).Scan(&scopes); e!=nil || scopes==0 { t.Fatal("source receipt released scopes",scopes,e) }
	row,e:=f.db.Pool().Resource(ctx,cp.Object.ID); if e!=nil || row.MemberID!=f.target { t.Fatal("receipt reversed authority",row,e) }
}
