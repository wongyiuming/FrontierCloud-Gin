package httpapi

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type changingStateInventory struct {
	store.PhysicalInventoryRepository
	store.ExpectedPhysicalRepository
	store.RetirementRepository
	change  func()
	changed bool
}

func (r *changingStateInventory) ClassifyPhysicalInventory(ctx context.Context, rel, member, master string, entries []store.PhysicalInventoryEntry) ([]store.PhysicalInventoryFact, error) {
	facts, e := r.PhysicalInventoryRepository.ClassifyPhysicalInventory(ctx, rel, member, master, entries)
	if e == nil && !r.changed {
		for _, fact := range facts {
			if fact.Category == "deleted_recording_lease" {
				r.changed = true
				r.change()
				break
			}
		}
	}
	return facts, e
}

func TestNativeVolumeRetirementExternalMountsAndStaleDefaultCopies(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	mediaDirectory, recordingDirectory := t.TempDir(), t.TempDir()
	_, sdb, dir, public, storage := clusterFixtureRoots(t, "https://storage.test", transport, true, []bool{true}, map[string]string{"media": mediaDirectory, "recordings": recordingDirectory})
	if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := storage.Promote(ctx, "Follower", "https://storage.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := storage.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := mdb.Nodes().Relationship(ctx, rid)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(recordingDirectory, "unmanaged-recording.bin"), []byte("actual mounted recording"), 0600); e != nil {
		t.Fatal(e)
	}
	root := public.media.InventoryRoot()
	f, e := root.Create("music/managed.mp3")
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("actual mounted media")
	if _, e = f.Write(data); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = sdb.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "music/managed.mp3", Kind: "audio"}}); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "media", "music", "managed.mp3"), []byte("stale"), 0600); e != nil {
		t.Fatal(e)
	}
	// Native initialization writes the built-in lyric and coordination files.
	// Include those actual bytes
	// rather than assuming the managed media is the only regular file.
	var expectedMediaBytes int64
	if e = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			expectedMediaBytes += info.Size()
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	id, user := strings.Repeat("4", 32), strings.Repeat("5", 32)
	if _, e = sdb.Database().Exec("INSERT INTO karaoke_recordings(recording_id,user_id,storage_member_id,filename,content_type,size_bytes,state,title,lyrics,created_at,updated_at) VALUES (?,?,?,?,?,0,'deleted','','{}',1,2)", id, user, rel.PeerID, "voice.webm", "audio/webm"); e != nil {
		t.Fatal(e)
	}
	leasePath := filepath.Join(recordingDirectory, ".recording-"+id+".lease")
	if e = os.WriteFile(leasePath, nil, 0600); e != nil {
		t.Fatal(e)
	}
	service := noderetirement.Service{Repository: mdb.Pool().(store.RetirementRepository), Nodes: mdb.Nodes(), Client: master}
	report, e := service.Check(ctx, rel.PeerID, rid)
	if e != nil || !report.ObservationComplete || len(report.Volumes) != 3 {
		t.Fatal(report, e)
	}
	if report.Volumes[1].InDataRoot || report.Volumes[2].InDataRoot || report.Volumes[1].LogicalBytes != expectedMediaBytes || report.Volumes[2].LogicalBytes != int64(len("actual mounted recording")) {
		t.Fatal("wrong mount", report.Volumes)
	}
	stale, managed := false, false
	for _, concern := range report.Concerns {
		if concern.Code == "expected_missing" {
			t.Fatal("default root used for expected presence", report)
		}
		for _, sample := range concern.Samples {
			if concern.Code == "physical_unmanaged_file" && sample == "data/media/music/managed.mp3" {
				stale = true
			}
			if concern.Code == "physical_managed_media" && sample == "media/music/managed.mp3" {
				managed = true
			}
		}
	}
	if !stale || !managed {
		t.Fatal("stale or managed mount omitted", report.Concerns)
	}
	if report.Volumes[1].RetainedEntries < 2 || report.Volumes[2].RetainedEntries < 2 {
		t.Fatal("known native state not reported", report.Volumes)
	}
	held, e := os.Open(leasePath)
	if e != nil {
		t.Fatal(e)
	}
	release, e := filelease.Try(held, false)
	if e != nil {
		t.Fatal(e)
	}
	busyReport, e := service.Check(ctx, rel.PeerID, rid)
	release()
	if e != nil {
		t.Fatal(e)
	}
	blocked := false
	for _, concern := range busyReport.Concerns {
		if concern.Code == "physical_native_lease_unverified" {
			blocked = true
		}
	}
	if !blocked || busyReport.Volumes[2].RetainedEntries >= report.Volumes[2].RetainedEntries {
		t.Fatal("busy lease retained", busyReport)
	}
	request := map[string]any{"action": "open", "member_id": rel.PeerID, "scope": "secrets", "session_id": strings.Repeat("1", 32)}
	if _, e = master.Call(ctx, rel, "/internal/v1/resource-inventory", request); e == nil {
		t.Fatal("unknown mount")
	}
	// Closing inventory sessions must not close either borrowed native root.
	if _, e = root.Stat("music/managed.mp3"); e != nil {
		t.Fatal(e)
	}
	for _, volume := range report.Volumes {
		if volume.WritableVerified || volume.FreeBytes < 0 || volume.FreeBytes > volume.TotalBytes {
			t.Fatal(volume)
		}
	}

	// Change only this disposable SQL tombstone between native page admission
	// and the second short SQL observation. The entire report must fail closed.
	changing := &changingStateInventory{PhysicalInventoryRepository: sdb.Pool().(store.PhysicalInventoryRepository), ExpectedPhysicalRepository: sdb.Pool().(store.ExpectedPhysicalRepository), RetirementRepository: sdb.Pool().(store.RetirementRepository), change: func() {
		if _, err := sdb.Database().Exec("UPDATE karaoke_recordings SET updated_at=updated_at+1 WHERE recording_id=?", id); err != nil {
			t.Fatal(err)
		}
	}}
	recordingRoot, e := os.OpenRoot(recordingDirectory)
	if e != nil {
		t.Fatal(e)
	}
	defer recordingRoot.Close()
	resolver, e := network.New(nil)
	if e != nil {
		t.Fatal(e)
	}
	changedRouter := gin.New()
	closeChanged, e := RegisterNodePhysicalInventory(changedRouter, public.settings, resolver, storage, changing, root, recordingRoot)
	if e != nil {
		t.Fatal(e)
	}
	defer closeChanged()
	transport.routers["https://storage.test"] = changedRouter
	changedReport, e := service.Check(ctx, rel.PeerID, rid)
	if e == nil || changedReport.ObservationComplete || !changing.changed {
		t.Fatal("changed tombstone retained", changedReport, e)
	}
}
