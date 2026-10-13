package media

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetainedControlLeaseRequiresThisRuntimeHeldInode(t *testing.T) {
	root, _, svc, _ := ownedFixture(t)
	path := filepath.Join(root, ".node-control.lock")
	done, e := svc.ControlLease(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(path)
	if e != nil || !svc.RetainsControlLease(info) {
		done()
		t.Fatal("owned native control lease not retained", e)
	}
	if e = os.WriteFile(path, []byte("unknown"), 0600); e != nil {
		done()
		t.Fatal(e)
	}
	info, _ = os.Lstat(path)
	if svc.RetainsControlLease(info) {
		done()
		t.Fatal("nonempty control state accepted")
	}
	if e = os.Truncate(path, 0); e != nil {
		done()
		t.Fatal(e)
	}
	info, _ = os.Lstat(path)
	if !svc.RetainsControlLease(info) {
		done()
		t.Fatal("restored held inode rejected")
	}
	done()
	if svc.RetainsControlLease(info) {
		t.Fatal("released control lock retained as held")
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := filelease.Try(f, true)
	if e != nil {
		t.Fatal(e)
	}
	if svc.RetainsControlLease(info) {
		foreign()
		t.Fatal("foreign owner counted as native held lease")
	}
	foreign()
	done, e = svc.ControlLease(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer done()
	if e = os.Rename(path, path+".held"); e != nil {
		t.Fatal(e)
	}
	if svc.ValidateRetainedControlState() == nil {
		t.Fatal("missing held control name accepted")
	}
	if e = os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	info, _ = os.Lstat(path)
	if svc.RetainsControlLease(info) {
		t.Fatal("replacement inode counted as owned")
	}
	if svc.ValidateRetainedControlState() == nil {
		t.Fatal("replaced held control name accepted")
	}
}

func TestSafeRetirementRejectsAlreadyAdmittedUploadBeforeAnyStage(t *testing.T) {
	root, db, svc, rel := ownedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	identity, e := db.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	relation, e := db.Nodes().Relationship(ctx, rel)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Nodes().ReserveNodeNonce(ctx, rel, strings.Repeat("a", 32), relation.Credential, time.Now().Unix(), false, false); e != nil {
		t.Fatal(e)
	}
	object := store.MediaObject{ID: strings.Repeat("5", 64), Path: "music/Retirement/raced.mp3", Kind: "audio"}
	paused := &pausedAdmissionRepository{MediaRepository: svc.repository, entered: make(chan struct{}), resume: make(chan struct{})}
	svc.repository = paused
	result := make(chan error, 1)
	go func() {
		_, e := svc.OwnedUploadCapability(ctx, rel, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{}, strings.Repeat("d", 32), time.Now().Unix()+120)
		result <- e
	}()
	select {
	case <-paused.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	fence := db.Pool().(store.RetirementFenceRepository)
	if _, e = fence.BeginRetirement(ctx, rel, identity.ID, store.NodeAudit{}); e != nil {
		close(paused.resume)
		t.Fatal(e)
	}
	if e = svc.RetirementBarrier(ctx, func() error { _, e := fence.CompleteRetirement(ctx, rel, identity.ID, store.NodeAudit{}); return e }); e != nil {
		close(paused.resume)
		t.Fatal(e)
	}
	before, e := os.Stat(root)
	if e != nil {
		close(paused.resume)
		t.Fatal(e)
	}
	close(paused.resume)
	select {
	case e = <-result:
		if !errors.Is(e, store.ErrNodeState) {
			t.Fatal("late PUT survived fence", e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	after, e := os.Stat(root)
	if e != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("late request mutated directory after retirement", e)
	}
	if e = filepath.WalkDir(root, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if strings.HasPrefix(entry.Name(), ".upload-") {
			t.Errorf("late request left upload material: %s", entry.Name())
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ownedFunds(t, db, 0, 0)
	if actual, e := db.Media().ObjectByID(ctx, object.ID); e != nil || actual != nil {
		t.Fatal("late upload published", actual, e)
	}
}
