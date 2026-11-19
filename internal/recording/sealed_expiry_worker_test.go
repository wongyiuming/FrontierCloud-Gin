package recording

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type expiryLegacySpy struct {
	store.RecordingRepository
	legacy atomic.Int32
}

func (s *expiryLegacySpy) StageExpiredRecordings(context.Context, int) error { s.legacy.Add(1);return nil }
func (s *expiryLegacySpy) PendingRecordingDeletions(context.Context, int) ([]store.Recording,error) { s.legacy.Add(1);return nil,nil }
func (s *expiryLegacySpy) CheckLegacyPhysicalWritesAllowed(context.Context) error { s.legacy.Add(1);return nil }

func TestSealedExpiryWorkerNeverRunsLegacyCleanup(t *testing.T) {
	volume,db,_,_:=storageFixture(t)
	spy:=&expiryLegacySpy{RecordingRepository:db.Recordings()}
	volume.repo=spy
	manager:=NewManager(spy,db.Karaoke(),db.Nodes(),db.Pool(),nil,volume)
	if err:=manager.ConfigureSealedExpiry(func(context.Context) error{return nil});err == nil { t.Fatal("unsealed storage accepted sealed worker") }
	volume.sealed=true
	ctx,cancel:=context.WithCancel(context.Background())
	var calls atomic.Int32
	if err:=manager.ConfigureSealedExpiry(func(c context.Context) error {
		if _,ok:=c.Deadline();!ok { t.Error("worker callback has no deadline") }
		calls.Add(1);cancel();return nil
	});err != nil { t.Fatal(err) }
	if err:=manager.ConfigureSealedExpiry(func(context.Context) error{return nil});err == nil { t.Fatal("worker was replaced") }
	manager.Run(ctx)
	if calls.Load()!=1 || spy.legacy.Load()!=0 { t.Fatalf("sealed callback=%d legacy=%d",calls.Load(),spy.legacy.Load()) }
}

func TestSealedExpiryWorkerRejectsUnexpectedPhysicalState(t *testing.T) {
	volume,db,_,_:=storageFixture(t)
	spy:=&expiryLegacySpy{RecordingRepository:db.Recordings()}
	volume.repo=spy;volume.sealed=true
	if err:=volume.root.WriteFile("unexpected",[]byte("fixture"),0600);err != nil { t.Fatal(err) }
	defer volume.root.Remove("unexpected")
	manager:=NewManager(spy,db.Karaoke(),db.Nodes(),db.Pool(),nil,volume)
	var calls atomic.Int32
	if err:=manager.ConfigureSealedExpiry(func(context.Context) error{calls.Add(1);return nil});err != nil { t.Fatal(err) }
	ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond);defer cancel();manager.Run(ctx)
	if calls.Load()!=0 || spy.legacy.Load()!=0 { t.Fatalf("unsafe state callback=%d legacy=%d",calls.Load(),spy.legacy.Load()) }
	if _,err:=volume.root.Lstat("unexpected");err != nil || os.IsNotExist(err) { t.Fatal("unexpected file was changed",err) }
}
