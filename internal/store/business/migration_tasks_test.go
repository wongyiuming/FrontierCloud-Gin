package business_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type migrationFixture struct {
	db                               store.Store
	raw                              *sql.DB
	repo                             store.MigrationRepository
	source, target, other, rel, base string
	objects                          []store.UploadReservation
}

func migrationDatabase(t *testing.T) *migrationFixture {
	t.Helper()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	ctx := context.Background()
	f := &migrationFixture{db: db, raw: raw, repo: db.Pool().(store.MigrationRepository), source: strings.Repeat("6", 32), target: strings.Repeat("7", 32), other: strings.Repeat("8", 32), rel: strings.Repeat("b", 32), base: "music/" + t.Name()}
	n, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "private-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 5 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		for _, member := range []string{n.ID, f.source, f.target, f.other} {
			for _, table := range []string{"migration_objects", "migration_units", "migration_capacity", "migration_scopes", "migration_runners"} {
				raw.Exec("DELETE FROM "+table+" WHERE task_id IN (SELECT task_id FROM migration_tasks WHERE source_id=?)", member)
			}
			raw.Exec("DELETE FROM migration_tasks WHERE source_id=?", member)
			raw.Exec("DELETE FROM migration_drains WHERE member_id=?", member)
			raw.Exec("DELETE FROM cluster_upload_sessions WHERE storage_member_id=?", member)
			raw.Exec("DELETE FROM global_media_objects WHERE storage_member_id=?", member)
			for _, table := range []string{"cluster_storage_members", "cluster_compute_members", "cluster_backup_members"} {
				raw.Exec("DELETE FROM "+table+" WHERE member_id=?", member)
			}
		}
		for _, o := range f.objects {
			raw.Exec("DELETE FROM media_encryption WHERE object_id=?", o.MediaID)
			raw.Exec("DELETE FROM media_objects WHERE media_id=?", o.MediaID)
			raw.Exec("DELETE FROM media_playback_stats WHERE media_id=?", o.MediaID)
		}
		raw.Exec("DELETE FROM media_visibility WHERE relative_path=?", f.base)
		raw.Exec("DELETE FROM node_relationships WHERE relationship_id IN (?,?,?)", f.rel, strings.Repeat("c", 32), strings.Repeat("d", 32))
		raw.Exec("UPDATE node_identity SET `role`=?,endpoint=? WHERE singleton=1", n.Role, n.Endpoint)
	})
	for i, member := range []string{f.source, f.target, f.other} {
		rel := strings.Repeat(string(rune('b'+i)), 32)
		mode := "Direct"
		if i == 1 {
			mode = "Relay"
		}
		v := store.Relationship{ID: rel, PeerID: member, Endpoint: fmt.Sprintf("https://follower%d.test", i), PublicKey: strings.Repeat("A", 43), Credential: "private-fixture-credential", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
		if e = db.Nodes().PrepareRelationship(ctx, v, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = db.Nodes().ActivateRelationship(ctx, rel, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = db.Nodes().SetRelationshipMode(ctx, rel, mode, false, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		c := store.ResourceConfiguration{}
		c.Storage.Enabled = i == 0
		c.Storage.Allocation = 10 * store.GiB
		if e = db.Pool().ConfigureMember(ctx, member, c, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = db.Nodes().RecordHeartbeat(ctx, rel, true, 1, map[string]any{"capabilities": []string{"storage-v2", store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
	}
	for i := range 3 {
		name := f.base + fmt.Sprintf("/track%d.mp3", i)
		size := int64(7 + i)
		var encryption *mediacrypto.Metadata
		if i == 1 {
			m, e := mediacrypto.NewMetadata(100)
			if e != nil {
				t.Fatal(e)
			}
			encryption = &m
			size = m.CiphertextSize
		}
		v, e := db.Pool().(store.EncryptionRepository).ReserveEncryptedUpload(ctx, name, "direct", size, 10*store.GiB, store.AdminAudit{}, encryption)
		if e != nil {
			t.Fatal(e)
		}
		if v.MemberID != f.source {
			t.Fatal("fixture placement", v)
		}
		if _, e = db.Pool().FinalizeUpload(ctx, v.ID, v.MediaID, size, `"`+hashPath(name)+`"`, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
		f.objects = append(f.objects, v)
	}
	if e = db.Media().SetHidden(ctx, []string{f.base}, true, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Pool().SetGlobalPreference(ctx, f.objects[0].MediaID, 77, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	for _, member := range []string{f.target, f.other} {
		c := store.ResourceConfiguration{}
		c.Storage.Enabled = true
		c.Storage.Allocation = 10 * store.GiB
		if e = db.Pool().ConfigureMember(ctx, member, c, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func (f *migrationFixture) plan(t *testing.T, id string) store.MigrationPlan {
	t.Helper()
	c, e := f.repo.MigrationCatalog(context.Background(), f.source, f.target)
	if e != nil || len(c.Blockers) != 0 {
		t.Fatal("catalog", c.Blockers, e)
	}
	p := store.MigrationPlan{ID: id, Catalog: c, TargetAbsent: true, TargetFree: 20 * store.GiB, CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 120, Proofs: []store.MigrationDiskProof{}}
	// These are repository facts, not real peer/network/disk acceptance. The
	// service must authenticate and independently obtain all disk proofs.
	for _, o := range c.Objects {
		p.Proofs = append(p.Proofs, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Trim(o.ETag, `"`)})
	}
	return p
}
func TestResourceMigrationReadOnlyCatalogAtomicStartAndFences(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	p := f.plan(t, hashPath(t.Name())[:32])
	if len(p.Catalog.Objects) != 3 || p.Catalog.Objects[0].Encryption == nil && p.Catalog.Objects[1].Encryption == nil && p.Catalog.Objects[2].Encryption == nil {
		t.Fatal("hidden or encrypted scope omitted")
	}
	var before, after int64
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&before)
	for range 3 {
		if _, e := f.repo.MigrationCatalog(ctx, f.source, f.target); e != nil {
			t.Fatal(e)
		}
	}
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&after)
	if before != after {
		t.Fatal("read-only plan reserved capacity")
	}
	var count int
	f.raw.QueryRow("SELECT COUNT(*) FROM migration_tasks WHERE source_id=?", f.source).Scan(&count)
	if count != 0 {
		t.Fatal("catalog wrote tasks")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			v, e := f.repo.StartMigration(ctx, p, store.NodeAudit{Actor: "admin", RequestID: t.Name()})
			if e != nil {
				errs <- e
			} else if v.ID != p.ID {
				errs <- store.ErrMigrationState
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&after)
	if after != before+p.Catalog.TotalBytes {
		t.Fatal("duplicate reservation", after)
	}
	f.raw.QueryRow("SELECT COUNT(*) FROM migration_units WHERE task_id=?", p.ID).Scan(&count)
	if count != 1 {
		t.Fatal("directory split into object units", count)
	}
	if _, e := f.db.Pool().ReserveUpload(ctx, f.base+"/new.mp3", "direct", 7, 10*store.GiB, store.AdminAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("locked parent accepted upload", e)
	}
	if _, e := f.db.Pool().PrepareGlobalDelete(ctx, []store.DeleteItem{{Path: f.base, Directory: true}}, store.AdminAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("locked parent accepted delete", e)
	}
	if _, e := f.db.Pool().PrepareGlobalRename(ctx, f.base, f.base+"-new", store.AdminAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("locked parent accepted rename", e)
	}
	u, e := f.db.Pool().ReserveUpload(ctx, "music/"+t.Name()+"Other/new.mp3", "direct", 7, 10*store.GiB, store.AdminAudit{})
	if e != nil || u.MemberID != f.other {
		t.Fatal("drain failed or unrelated node blocked", u, e)
	}
	if e = f.db.Nodes().RecordHeartbeat(ctx, f.rel, true, 1, map[string]any{"capabilities": []string{store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Pool().ReserveUpload(ctx, "music/"+t.Name()+"AfterBeat/new.mp3", "direct", 7, 10*store.GiB, store.AdminAudit{}); e != nil {
		t.Fatal("heartbeat disturbed unrelated allocation", e)
	}
	// Creating a new repository over persisted SQL facts does not lose a task.
	second := business.New(f.raw, f.db.Backend())
	task, e := second.MigrationTask(ctx, p.ID)
	if e != nil || task.State != "queued" {
		t.Fatal("persistent task", task, e)
	}
	lease, e := f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("e", 32), 20*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("f", 32), 20*time.Second); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("two task runners admitted", e)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "pause", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.RenewMigration(ctx, lease, 20*time.Second); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("paused runner retained authority", e)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "resume", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	next, e := f.repo.ClaimMigration(ctx, p.ID, lease.RunnerID, 20*time.Second)
	if e != nil || next.Epoch <= lease.Epoch {
		t.Fatal("runner ABA", next, e)
	}
	if e = f.repo.ReleaseMigration(ctx, lease); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("old runner released new lease", e)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "cancel", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&after)
	if after != before+p.Catalog.TotalBytes {
		t.Fatal("cancel refunded before staged cleanup")
	}
	if e = f.repo.ReleaseMigrationDrain(ctx, p.ID, f.source, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("drain released pending task", e)
	}
	if e = f.db.Nodes().RevokeRelationship(ctx, f.rel, false, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("revoke bypassed task", e)
	}
	for _, o := range f.objects {
		g, e := f.db.Pool().Resource(ctx, o.MediaID)
		if e != nil || g.MemberID != f.source {
			t.Fatal("cancel moved authority", g, e)
		}
	}
}
func TestResourceMigrationRejectsStalePlansAndMissingPhysicalProof(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	p := f.plan(t, hashPath(t.Name())[:32])
	bad := p
	bad.TargetAbsent = false
	if _, e := f.repo.StartMigration(ctx, bad, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("no collision proof", e)
	}
	bad = p
	bad.Proofs = nil
	if _, e := f.repo.StartMigration(ctx, bad, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("no disk hash proof", e)
	}
	bad = p
	bad.ExpiresAt = time.Now().Unix() - 1
	if _, e := f.repo.StartMigration(ctx, bad, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("expired plan", e)
	}
	if _, e := f.raw.Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", `"`+strings.Repeat("9", 64)+`"`, f.objects[0].MediaID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.repo.StartMigration(ctx, p, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("stale content plan", e)
	}
	if _, e := f.repo.MigrationCatalog(ctx, f.source, f.source); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("self migration", e)
	}
	if _, e := f.repo.MigrationCatalog(ctx, strings.Repeat("a", 32), f.target); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("Master Local migration", e)
	}
	var reserved int64
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved)
	if reserved != 0 {
		t.Fatal("rejected plan changed quota", reserved)
	}
}

func TestResourceMigrationRecordingAndNestedUnitsRetainBusinessMetadata(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	id := hashPath(t.Name() + "recording")[:32]
	user := hashPath(t.Name() + "user")[:32]
	ip := "192.0.2.244"
	t.Cleanup(func() {
		f.raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id)
		f.raw.Exec("DELETE FROM karaoke_users WHERE user_id=?", user)
		f.raw.Exec("DELETE FROM karaoke_registration_daily WHERE client_ip=?", ip)
		f.raw.Exec("DELETE FROM karaoke_audit_log WHERE client_ip=?", ip)
	})
	if e := f.db.Karaoke().RegisterUser(ctx, store.KaraokeUser{ID: user, Username: "migration-" + user[:8], NameKey: "migration-" + user[:8], PasswordHash: "private-fixture", Quota: store.GiB}, ip, "20261012", store.KaraokeAudit{IP: ip}); e != nil {
		t.Fatal(e)
	}
	// Select fixture ownership through the ordinary quota-aware allocator.
	if _, e := f.raw.Exec("UPDATE cluster_storage_members SET writable=0 WHERE member_id<>?", f.source); e != nil {
		t.Fatal(e)
	}
	v, m, e := f.db.Recordings().ReserveRecording(ctx, store.Recording{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: 111, Title: "original recording", Lyrics: []store.RecordingLyric{{Time: 1, Text: "original lyric"}}}, 10*store.GiB, store.KaraokeAudit{IP: ip})
	if e != nil || m.ID != f.source {
		t.Fatal("recording placement", m, e)
	}
	if e = f.db.Recordings().FinalizeRecording(ctx, user, id, store.RecordingReceipt{ID: id, Bytes: v.Bytes, SHA256: hashPath(id)}, store.KaraokeAudit{IP: ip}); e != nil {
		t.Fatal(e)
	}
	u, e := f.db.Pool().ReserveUpload(ctx, "music/"+t.Name()+"Nested/child/track.mp3", "direct", 7, 10*store.GiB, store.AdminAudit{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.db.Pool().FinalizeUpload(ctx, u.ID, u.MediaID, 7, `"`+hashPath(u.Path)+`"`, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	f.objects = append(f.objects, u)
	if _, e = f.raw.Exec("UPDATE cluster_storage_members SET writable=1"); e != nil {
		t.Fatal(e)
	}
	p := f.plan(t, hashPath(t.Name())[:32])
	if len(p.Catalog.Objects) != 5 {
		t.Fatal("recording/nested inventory omitted", len(p.Catalog.Objects))
	}
	var recording *store.MigrationObject
	for i := range p.Catalog.Objects {
		if p.Catalog.Objects[i].Resource == "recording" {
			recording = &p.Catalog.Objects[i]
		}
	}
	if recording == nil || recording.ID != id || recording.Parent != user || !strings.HasPrefix(recording.Path, f.rel+"/") || recording.TargetPath == recording.Path {
		t.Fatal("recording locator mapping", recording)
	}
	if _, e = f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	var units int
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_units WHERE task_id=?", p.ID).Scan(&units); e != nil || units != 3 {
		t.Fatal("independent immediate parents", units, e)
	}
	if _, e = f.db.Recordings().StageRecordingDeletion(ctx, user, id, false, store.KaraokeAudit{IP: ip}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("recording delete crossed migration", e)
	}
	if _, e = f.db.Karaoke().StageUserDeletion(ctx, user, store.KaraokeAudit{IP: ip}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("account cascade crossed migration", e)
	}
	current, e := f.db.Recordings().Recording(ctx, id)
	if e != nil || current == nil || current.ID != id || current.MemberID != f.source || current.Title != "original recording" || len(current.Lyrics) != 1 || current.Lyrics[0].Text != "original lyric" {
		t.Fatal("recording metadata changed", current, e)
	}
	if _, e = f.db.Pool().SetGlobalPreference(ctx, f.objects[0].MediaID, 123, store.AdminAudit{}); e != nil {
		t.Fatal("safe priority edit blocked", e)
	}
	global, e := f.db.Pool().Resource(ctx, f.objects[0].MediaID)
	if e != nil || global.Preference != 123 {
		t.Fatal("priority update lost", global, e)
	}
	l, e := f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("e", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	w, e := f.repo.MigrationWork(ctx, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	var recordingUnit string
	for _, checkpoint := range w.Objects {
		if checkpoint.Object.Resource == "recording" {
			recordingUnit = checkpoint.UnitID
			if e = f.repo.VerifyMigrationObject(ctx, l, checkpoint.Object.ID, checkpoint.Object.Bytes, checkpoint.SourceSHA); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e = f.repo.PrepareMigrationPublication(ctx, l, recordingUnit); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.PublishMigrationObject(ctx, l, id); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, recordingUnit, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	current, e = f.db.Recordings().Recording(ctx, id)
	if e != nil || current == nil || current.MemberID != f.target || current.ID != id || current.Title != "original recording" || len(current.Lyrics) != 1 || current.Lyrics[0].Text != "original lyric" {
		t.Fatal("recording cutover lost metadata", current, e)
	}
	var userUsed int64
	if e = f.raw.QueryRow("SELECT used_bytes FROM karaoke_users WHERE user_id=?", user).Scan(&userUsed); e != nil || userUsed != v.Bytes {
		t.Fatal("migration changed user quota", userUsed, e)
	}
}

func TestResourceMigrationTargetsAndSplitOwnershipAreReported(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	if _, e := f.raw.Exec("UPDATE node_relationships SET protocol=1 WHERE peer_id=?", f.target); e != nil {
		t.Fatal(e)
	}
	c, e := f.repo.MigrationCatalog(ctx, f.source, f.target)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, b := range c.Blockers {
		if b.Code == "untrusted_or_incompatible_relationship" {
			found = true
		}
	}
	if !found {
		t.Fatal("incompatible target hidden", c.Blockers)
	}
	if _, e = f.raw.Exec("UPDATE node_relationships SET protocol=2 WHERE peer_id=?", f.target); e != nil {
		t.Fatal(e)
	}
	if _, e = f.raw.Exec("UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?", f.other, f.objects[0].MediaID); e != nil {
		t.Fatal(e)
	}
	c, e = f.repo.MigrationCatalog(ctx, f.source, f.target)
	if e != nil {
		t.Fatal(e)
	}
	found = false
	for _, b := range c.Blockers {
		if b.Code == "split_directory_ownership" {
			found = true
		}
	}
	if !found {
		t.Fatal("historical split parent accepted", c.Blockers)
	}
}

func TestResourceMigrationConcurrentPlansCannotOversellTarget(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	u, e := f.db.Pool().ReserveUpload(ctx, "music/"+t.Name()+"Other/large.mp3", "direct", 7*store.GiB, 10*store.GiB, store.AdminAudit{})
	if e != nil || u.MemberID != f.other {
		t.Fatal("second source fixture", u, e)
	}
	if _, e = f.db.Pool().FinalizeUpload(ctx, u.ID, u.MediaID, u.ExpectedBytes, `"`+hashPath(u.Path)+`"`, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	f.objects = append(f.objects, u)
	// Synthetic occupied capacity exercises SQL accounting; no disk transfer
	// or physical-file acceptance is inferred from these repository fixtures.
	if _, e = f.raw.Exec("UPDATE cluster_storage_members SET used_bytes=? WHERE member_id=?", 3*store.GiB, f.target); e != nil {
		t.Fatal(e)
	}
	p := f.plan(t, hashPath(t.Name() + "first")[:32])
	c, e := f.repo.MigrationCatalog(ctx, f.other, f.target)
	if e != nil || len(c.Blockers) != 0 {
		t.Fatal(c.Blockers, e)
	}
	other := store.MigrationPlan{ID: hashPath(t.Name() + "second")[:32], Catalog: c, TargetAbsent: true, TargetFree: 20 * store.GiB, CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 120, Proofs: []store.MigrationDiskProof{}}
	for _, o := range c.Objects {
		other.Proofs = append(other.Proofs, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Trim(o.ETag, `"`)})
	}
	type result struct {
		task store.MigrationTask
		e    error
	}
	ch := make(chan result, 2)
	var wg sync.WaitGroup
	for _, plan := range []store.MigrationPlan{p, other} {
		wg.Go(func() { task, e := f.repo.StartMigration(ctx, plan, store.NodeAudit{}); ch <- result{task, e} })
	}
	wg.Wait()
	close(ch)
	count := 0
	var bytes int64
	for result := range ch {
		if result.e == nil {
			count++
			bytes = result.task.TotalBytes
		} else if !errors.Is(result.e, store.ErrMigrationState) {
			t.Fatal(result.e)
		}
	}
	if count != 1 {
		t.Fatal("target oversold", count)
	}
	var reserved int64
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved); e != nil || reserved != bytes || reserved > 7*store.GiB {
		t.Fatal("reservation reconciliation", reserved, bytes, e)
	}
}

func TestResourceMigrationUnrelatedLocalMutationDoesNotBlockTask(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	p := f.plan(t, hashPath(t.Name())[:32])
	operation := hashPath(t.Name() + "local")[:32]
	t.Cleanup(func() { f.raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", operation) })
	if _, e := f.raw.Exec("INSERT INTO media_delete_operations(operation_id,state,manifest,created_at) VALUES (?,'pending','{}','2026-10-12 01:02:03')", operation); e != nil {
		t.Fatal(e)
	}
	if _, e := f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
		t.Fatal("unrelated Master Local transaction blocked Storage task", e)
	}
}
