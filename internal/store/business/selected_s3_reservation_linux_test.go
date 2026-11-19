//go:build linux

package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

type selectedS3TestGate struct{}
type selectedS3TestLease struct{}

func (selectedS3TestGate) AcquireSelectedUpload(context.Context, *sealedtree.SQLStore) (SelectedUploadRuntimeLease, error) {
	return selectedS3TestLease{}, nil
}
func (selectedS3TestGate) AcquireSelectedS3(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error) {
	return selectedS3TestLease{}, nil
}
func (selectedS3TestGate) AcquireSelectedS3Admission(context.Context, *sealedtree.SQLStore, string) (SelectedUploadRuntimeLease, error) {
	return selectedS3TestLease{}, nil
}
func (selectedS3TestGate) CheckSelectedS3Member(context.Context, *sealedtree.SQLStore, store.S3Member) error {
	return nil
}
func (selectedS3TestGate) CheckSelectedS3PublicOrigin(context.Context, *sealedtree.SQLStore, store.S3Member, string) error {
	return nil
}
func (selectedS3TestLease) Check(ctx context.Context) error { return ctx.Err() }
func (selectedS3TestLease) Release()                        {}

// This simulates Provider observations only; it is not a live S3 service.
type selectedS3NetworkFixture struct {
	s3store.Provider
	t          *testing.T
	key, owner string
	parts      []s3store.Part
	proof      s3store.Proof
	completed  bool
	completes  int
	creates    int
	aborts     int
	deletes    int
}

func (f *selectedS3NetworkFixture) WithSelectedProvider(ctx context.Context, member store.S3Member, fn func(context.Context, s3store.Provider) error) error {
	if member.Kind != "S3" || member.Revision != 1 {
		return store.ErrNodeState
	}
	return fn(ctx, f)
}
func (f *selectedS3NetworkFixture) CreateMultipart(_ context.Context, key string, metadata map[string]string) (string, error) {
	if _, ok := store.S3OpaqueOwner(key); !ok || metadata["fc-format"] != store.S3OpaqueMetadata || metadata["fc-owner"] == "" || len(metadata) != 2 {
		return "", store.ErrNodeState
	}
	f.key, f.owner = key, metadata["fc-owner"]
	f.creates++
	return "provider-upload", nil
}
func (f *selectedS3NetworkFixture) PresignPart(_ context.Context, key, upload string, number int32, size int64, sum string, duration time.Duration) (s3store.Grant, error) {
	if key != f.key || upload != "provider-upload" || number != 1 || size <= 0 || sum == "" {
		return s3store.Grant{}, store.ErrNodeState
	}
	return s3store.Grant{URL: "https://s3.fixture.test/part", Headers: map[string]string{"x-amz-checksum-sha256": sum}, ExpiresAt: time.Now().Add(duration).Unix()}, nil
}
func (f *selectedS3NetworkFixture) ListParts(_ context.Context, key, upload string) ([]s3store.Part, error) {
	if key != f.key || upload != "provider-upload" {
		return nil, store.ErrNodeState
	}
	if f.aborts > 0 {
		return nil, s3store.ErrNotFound
	}
	return f.parts, nil
}
func (f *selectedS3NetworkFixture) Abort(_ context.Context, key, upload string) error {
	if key != f.key || upload != "provider-upload" {
		return store.ErrNodeState
	}
	f.aborts++
	return nil
}
func (f *selectedS3NetworkFixture) Head(_ context.Context, key, _ string) (s3store.Proof, error) {
	if key != f.key {
		return s3store.Proof{}, store.ErrNodeState
	}
	if !f.completed {
		return s3store.Proof{}, s3store.ErrNotFound
	}
	return f.proof, nil
}
func (f *selectedS3NetworkFixture) Delete(_ context.Context, key, version, etag string) error {
	if key != f.key || !f.completed || version != f.proof.VersionID || etag != f.proof.ETag {
		return store.ErrNodeState
	}
	f.completed = false
	f.deletes++
	return &s3store.OperationError{Code: s3store.ErrNetwork, Uncertain: true}
}
func (f *selectedS3NetworkFixture) Complete(_ context.Context, key, upload string, _ []s3store.Part) (s3store.Proof, error) {
	if key != f.key || upload != "provider-upload" {
		return s3store.Proof{}, store.ErrNodeState
	}
	f.completed = true
	f.completes++
	return f.proof, nil
}

// This fixture tests fenced transaction composition. The preparation token,
// provider and runtime readiness are deliberately not represented as product
// authorization or evidence of remote publication.
func TestSelectedS3ReservationPinsBucketAndRecoversAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "s3.db"))+"?_pragma=busy_timeout(1000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	treeKey, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, treeKey, rootID)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range statements {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	treeDir := t.TempDir()
	if err = os.Chmod(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	music := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("8", 64), Kind: "directory", Name: "music"}
	category := sealedtree.Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("9", 64), Kind: "directory", Name: "category"}
	for _, dir := range []sealedtree.Entry{music, category} {
		if err = tree.CreateDirectoryWithFacts(ctx, dir, sealedtree.Facts{ObjectID: dir.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db, "sqlite")
	ownerDir := t.TempDir()
	if err = os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	fence, err := ownerfence.Create(ownerRoot, ownerDir, selectedCoordinatorCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	master, member := strings.Repeat("1", 32), strings.Repeat("2", 32)
	if _, err = db.Exec(`INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test','fixture',1)`, master); err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigurePublicOrigin("https://public.example"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'S3','S3',1,?,0,0,0,'online',1,1)`, member, store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO s3_members(member_id,name,endpoint,region,bucket,prefix,address_style,namespace_key,sealed_credentials,credential_revision,revision,probe_revision,probe_state,created_at,updated_at) VALUES(?,'fixture','https://s3.us-east-1.amazonaws.com','us-east-1','fixture-private','managed','path','fixture-namespace','sealed-credentials',1,1,1,'ready',1,1)`, member); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = r.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err != nil {
		t.Fatal("empty selected S3 startup", err)
	}
	if err = r.CheckSelectedS3MemberNoHistory(ctx, tree, key, member); err != nil {
		t.Fatal("enabled empty member", err)
	}
	if err = r.CheckSelectedS3MemberUnused(ctx, tree, key, member); err == nil {
		t.Fatal("enabled member allowed removal")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=0 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3MemberUnused(ctx, tree, key, member); err != nil {
		t.Fatal("unused disabled member", err)
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=1 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	entry := sealedtree.Entry{ParentID: category.ObjectID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "private.mp3"}
	placement := sealedtree.Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: member, Bytes: meta.CiphertextSize, SHA256: strings.Repeat("c", 64), Encryption: &meta, State: "active"}
	facts := sealedtree.Facts{ObjectID: entry.ObjectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: strings.Repeat("d", 32), AdminBinding: strings.Repeat("e", 64), Policy: "S3", Revision: 1}}
	check := func(_ context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending) error {
		if p.Placement.OwnerID != member {
			return store.ErrNodeState
		}
		return nil
	}
	partDigest := sha256.Sum256([]byte("fixture ciphertext"))
	checksum := base64.StdEncoding.EncodeToString(partDigest[:])
	first, already, err := r.prepareSelectedCoordinated(ctx, tree, key, entry, placement, facts, 0, check, []string{checksum})
	if err != nil || already {
		t.Fatal("initial S3 reservation", err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); !errors.Is(err, ErrSelectedS3RecoveryRequired) {
		t.Fatal("pending selected S3 must block startup", err)
	}
	if err = r.CheckSelectedS3RecoveryMember(ctx, tree, key, member); err != nil {
		t.Fatal("pending member rejected for recovery probe", err)
	}
	if err = r.CheckSelectedS3RecoveryMember(ctx, tree, key, strings.Repeat("8", 32)); err == nil {
		t.Fatal("unrelated member allowed recovery probe")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes+1 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err == nil || errors.Is(err, ErrSelectedS3RecoveryRequired) {
		t.Fatal("corrupt pending quota treated as recoverable", err)
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-1 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	var journalID, journalState string
	var journalSealed []byte
	index := opaqueCapacityIndex(key, first.OperationID)
	if err = db.QueryRow(`SELECT encryption_id,sealed,state FROM selected_s3_uploads WHERE operation_index=?`, index).Scan(&journalID, &journalSealed, &journalState); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM selected_s3_uploads WHERE operation_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err == nil || errors.Is(err, ErrSelectedS3RecoveryRequired) {
		t.Fatal("missing S3 journal treated as recoverable", err)
	}
	if _, err = db.Exec(`INSERT INTO selected_s3_uploads(operation_index,encryption_id,sealed,state) VALUES(?,?,?,?)`, index, journalID, journalSealed, journalState); err != nil {
		t.Fatal(err)
	}
	second, already, err := r.prepareSelectedCoordinated(ctx, tree, key, entry, placement, facts, 0, check, []string{checksum})
	if err != nil || !already || first != second {
		t.Fatal("retry changed S3 identity", err)
	}
	if err = r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		intent, found, e := r.readSelectedS3IntentTx(c, q, key, first.OperationID)
		if e != nil || !found || intent.BlobID != first.BlobID || intent.MemberID != member || intent.Encryption != meta {
			return errors.New("S3 journal does not match pending")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var reserved int64
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, member).Scan(&reserved); err != nil || reserved != meta.CiphertextSize {
		t.Fatal("S3 quota duplicated", reserved, err)
	}
	assertConfigFrozen := func() {
		t.Helper()
		current, e := r.S3Member(ctx, member)
		if e != nil {
			t.Fatal(e)
		}
		changed := store.S3MemberConfiguration{Name: current.Name, Location: current.Location, Quota: current.Allocation, Enabled: current.Enabled != 0}
		changed.Location.Bucket = "other-bucket"
		if _, e = r.S3ConfigureMember(ctx, member, current.Revision, changed, store.NodeAudit{}); e == nil {
			t.Fatal("selected data allowed S3 namespace replacement")
		}
		changed.Location = current.Location
		credentials := "changed-sealed-credentials"
		changed.SealedCredentials = &credentials
		if _, e = r.S3ConfigureMember(ctx, member, current.Revision, changed, store.NodeAudit{}); e == nil {
			t.Fatal("selected data allowed S3 credential replacement without drain")
		}
	}
	assertConfigFrozen()
	if _, err = db.Exec(`UPDATE s3_members SET revision=2 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3RecoveryMember(ctx, tree, key, member); err == nil {
		t.Fatal("changed bucket revision authorized recovery probe")
	}
	if _, _, err = r.prepareSelectedCoordinated(ctx, tree, key, entry, placement, facts, 0, check, []string{checksum}); err == nil {
		t.Fatal("changed bucket revision authorized old reservation")
	}
	if _, err = db.Exec(`UPDATE s3_members SET revision=1 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	controlRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer controlRoot.Close()
	if err = PrepareSelectedS3FileGate(controlRoot, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	s3Gate, err := OpenSelectedS3FileGate(controlRoot, tree, func(c context.Context) error { return c.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer s3Gate.Close()
	audit := func(c context.Context) error { return r.CheckSelectedS3Startup(c, tree, key) }
	probeMember := func(c context.Context, id string) error { return r.CheckSelectedS3RecoveryMember(c, tree, key, id) }
	if err = s3Gate.StartSelectedS3(ctx, tree, audit, probeMember, func(context.Context) error {
		return s3Gate.ConfigureSelectedS3Origins("https://admin.example", "https://public.example")
	}); err != nil {
		t.Fatal("authenticated recovery startup", err)
	}
	if _, err = s3Gate.AcquireSelectedS3Admission(ctx, tree, facts.PendingSelectedUpload.UploadID); err == nil {
		t.Fatal("recovery allowed admission")
	}
	if _, err = s3Gate.WithSelectedS3Probe(ctx, tree, member, "https://admin.example", "https://public.example", func(c context.Context) (store.S3Member, error) { return r.S3Member(c, member) }); err != nil {
		t.Fatal("bound recovery origin probe", err)
	}
	fixture := &selectedS3NetworkFixture{t: t}
	uploadRuntime := &SelectedUploadRuntime{repo: r, tree: tree, key: key, gate: selectedS3TestGate{}}
	coordinator, err := NewSelectedS3Coordinator(uploadRuntime, fixture, s3Gate)
	if err != nil {
		t.Fatal(err)
	}
	sessionHash, uploadID := facts.PendingSelectedUpload.AdminBinding, facts.PendingSelectedUpload.UploadID
	if state, e := coordinator.Begin(ctx, sessionHash, uploadID); e != nil || state != "uploading" {
		t.Fatal("S3 create", state, e)
	}
	if state, e := coordinator.Begin(ctx, sessionHash, uploadID); e != nil || state != "uploading" || fixture.creates != 1 {
		t.Fatal("create replay", state, e)
	}
	var intent selectedS3Intent
	if err = r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		var found bool
		var e error
		intent, found, e = r.readSelectedS3IntentTx(c, q, key, first.OperationID)
		if e != nil || !found {
			return store.ErrNodeState
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	grant, err := coordinator.PartGrant(ctx, sessionHash, uploadID, 1, meta.CiphertextSize, checksum)
	if err != nil || grant.URL == "" {
		t.Fatal("part grant", err)
	}
	fixture.parts = []s3store.Part{{Number: 1, Size: meta.CiphertextSize, SHA256: checksum, ETag: `"part"`}}
	if part, e := coordinator.ConfirmPart(ctx, sessionHash, uploadID, 1); e != nil || !part.Confirmed {
		t.Fatal("part confirmation", e)
	}
	if state, e := coordinator.Status(ctx, sessionHash, uploadID); e != nil || state.State != "created" || len(state.Parts) != 1 || !state.Parts[0].Confirmed {
		t.Fatal("multipart status", state, e)
	}
	composite := sha256.Sum256(partDigest[:])
	proof := s3store.Proof{Size: meta.CiphertextSize, ETag: `"object"`, VersionID: "version-1", ChecksumType: "COMPOSITE", ChecksumSHA256: base64.StdEncoding.EncodeToString(composite[:]) + "-1", Metadata: map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": intent.Owner}}
	fixture.proof = proof
	if _, err = db.Exec(`CREATE TRIGGER fail_s3_settlement BEFORE UPDATE OF used_bytes ON cluster_storage_members BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Complete(ctx, sessionHash, uploadID); err == nil {
		t.Fatal("failed settlement published S3")
	}
	var pending int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_pending_files WHERE operation_id=?`, first.OperationID).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("failed settlement changed pending", pending, err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_s3_settlement`); err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Complete(ctx, sessionHash, uploadID)
	if err != nil || state.State != "published" {
		t.Fatal("finalize", state, err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err != nil {
		t.Fatal("completed selected S3 startup", err)
	}
	admission, err := s3Gate.AcquireSelectedS3Admission(ctx, tree, facts.PendingSelectedUpload.UploadID)
	if err != nil {
		t.Fatal("recovery gate did not return to normal", err)
	}
	admission.Release()
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=0,used_bytes=0 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err == nil {
		t.Fatal("startup accepted mismatched settled quota")
	}
	if err = r.CheckSelectedS3MemberUnused(ctx, tree, key, member); err == nil {
		t.Fatal("selected history allowed member removal")
	}
	if err = r.CheckSelectedS3MemberNoHistory(ctx, tree, key, member); err == nil {
		t.Fatal("selected history allowed member disable")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=1,used_bytes=? WHERE member_id=?`, meta.CiphertextSize, member); err != nil {
		t.Fatal(err)
	}
	state, err = coordinator.Complete(ctx, sessionHash, uploadID)
	if err != nil || state.State != "published" || fixture.completes != 1 {
		t.Fatal("completion retry", state, err)
	}
	var remainingParts int
	if err = db.QueryRow(`SELECT COUNT(*) FROM selected_s3_parts`).Scan(&remainingParts); err != nil || remainingParts != 0 {
		t.Fatal("terminal parts not released", remainingParts, err)
	}
	wrongProof := proof
	wrongProof.ETag = `"other"`
	if _, err = r.finalizeSelectedS3(ctx, tree, key, facts.PendingSelectedUpload.UploadID, wrongProof, func(context.Context) error { return nil }); err == nil {
		t.Fatal("changed completed provider proof accepted")
	}
	var used int64
	if err = db.QueryRow(`SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, member).Scan(&used, &reserved); err != nil || used != meta.CiphertextSize || reserved != 0 {
		t.Fatal("quota settlement", used, reserved, err)
	}
	assertConfigFrozen()
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=0 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	if _, err = r.S3RecoveryCredentials(ctx, member, 1, "changed-sealed-credentials", 0, store.NodeAudit{}); err == nil {
		t.Fatal("selected data allowed recovery credentials without reconciliation")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET storage_enabled=1 WHERE member_id=?`, member); err != nil {
		t.Fatal(err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := tree.ReadS3ListingObjectWithLease(ctx, lease, entry.ObjectID, false)
	lease.Release()
	if err != nil || view.Placement.Proof.VersionID != proof.VersionID || view.Placement.Proof.Key != intent.Key {
		t.Fatal("authenticated S3 placement", err)
	}
	func() {
		if _, err := db.Exec(`INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,0,0,0,0,'offline',0,1)`, master); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(`DELETE FROM cluster_storage_members WHERE member_id=?`, master); err != nil {
				t.Error(err)
			}
		}()
		nodeVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		expectedObjects := buildRecoveryExpectationsFixture(t, ctx, r, tree, key, nodeVault)
		if expectedObjects.Accounting.Media != 1 || expectedObjects.Accounting.Recordings != 0 || len(expectedObjects.Owners) != 2 ||
			expectedObjects.Owners[0].ID != master || expectedObjects.Owners[0].Objects != 0 ||
			expectedObjects.Owners[1].ID != member || expectedObjects.Owners[1].Bytes != meta.CiphertextSize || len(expectedObjects.Owners[1].S3) != 1 {
			t.Fatal("grouped recovery expectations did not match settled provider placement")
		}
		got := expectedObjects.Owners[1].S3[0]
		if got.ObjectID != view.Placement.ObjectID || got.ObjectRevision != view.Placement.ObjectRevision ||
			got.Location != view.Placement.Location || got.Proof != view.Placement.Proof || got.Encryption == nil || *got.Encryption != meta {
			t.Fatal("private S3 point read did not preserve the exact sealed placement")
		}
	}()
	if _, err = coordinator.Cancel(ctx, sessionHash, uploadID); err == nil {
		t.Fatal("published object cancelled")
	}
	t.Run("durable S3 deletion and quota settlement", func(t *testing.T) {
		target := store.SelectedMediaDeleteTarget{Path: "music/category/private.mp3", ResourceID: entry.ObjectID}
		bad := target
		bad.Path = "lyrics/default.lrc"
		if _, e := coordinator.QueueMediaDeletion(ctx, sessionHash, bad, store.AdminAudit{}); e == nil {
			t.Fatal("mismatched protected path queued deletion")
		}
		queued, e := coordinator.QueueMediaDeletion(ctx, sessionHash, target, store.AdminAudit{})
		if e != nil || queued.State != store.SelectedMediaDeletePending || !nodeIDPattern.MatchString(queued.OperationID) || queued.OperationID == uploadID || fixture.deletes != 0 {
			t.Fatal("S3 deletion was not durably queued without a provider call", queued, e)
		}
		target.OperationID = queued.OperationID
		if again, e := coordinator.QueueMediaDeletion(ctx, sessionHash, target, store.AdminAudit{}); e != nil || again != queued {
			t.Fatal("queued deletion retry changed its identity", again, e)
		}
		assertUsed := func(want int64) {
			t.Helper()
			var got int64
			if e := db.QueryRow(`SELECT used_bytes FROM cluster_storage_members WHERE member_id=?`, member).Scan(&got); e != nil || got != want {
				t.Fatal("S3 used quota", got, want, e)
			}
		}
		assertUsed(meta.CiphertextSize)
		if _, e = tree.Check(ctx); e != nil {
			t.Fatal("pending S3 corrupts sealed tree check", e)
		}
		if e = r.CheckSelectedS3Startup(ctx, tree, key); e != nil {
			t.Fatal("restart cannot authenticate queued S3 deletion", e)
		}
		lease, e := tree.AcquireReadFence(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, visibleErr := tree.ReadS3ListingObjectWithLease(ctx, lease, entry.ObjectID, true)
		adminPage, _, pageErr := tree.ListCatalogPageWithLease(ctx, lease, category.ObjectID, "", 10, true)
		nativePending, _, nativeErr := tree.ListOpaqueRevocationsWithLease(ctx, lease, "", 10)
		lease.Release()
		if visibleErr == nil || pageErr != nil || len(adminPage) != 0 || nativeErr != nil || len(nativePending) != 0 {
			t.Fatal("pending S3 still visible or treated as native", visibleErr, pageErr, nativeErr)
		}
		resumed, e := NewSelectedS3Coordinator(uploadRuntime, fixture, s3Gate)
		if e != nil {
			t.Fatal(e)
		}
		pending, _, e := resumed.scanMediaDeletions(ctx, "")
		if e != nil || len(pending) != 1 || pending[0].Intent.OperationID != queued.OperationID || pending[0].ObjectID != entry.ObjectID || pending[0].Path != target.Path {
			t.Fatal("S3 deletion not recoverable from durable state", e)
		}
		if e = resumed.settleMediaDeletion(ctx, pending[0], time.Now()); !errors.Is(e, s3media.ErrPending) || fixture.deletes != 0 {
			t.Fatal("S3 deletion crossed live bearer drain", e)
		}
		drained := time.Now().Add(-selectedS3DeletionDrain)
		fixture.proof.ChecksumSHA256 = "foreign"
		if e = resumed.settleMediaDeletion(ctx, pending[0], drained); !errors.Is(e, s3media.ErrProof) || fixture.deletes != 0 {
			t.Fatal("S3 deletion accepted changed provider proof", e)
		}
		fixture.proof = proof
		if _, e = db.Exec(`CREATE TRIGGER fail_s3_delete_refund BEFORE UPDATE OF used_bytes ON cluster_storage_members BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
			t.Fatal(e)
		}
		if e = resumed.settleMediaDeletion(ctx, pending[0], drained); e == nil || fixture.deletes != 1 {
			t.Fatal("failed quota settlement should retain pending after physical deletion", e)
		}
		assertUsed(meta.CiphertextSize)
		if e = r.CheckSelectedS3Startup(ctx, tree, key); e != nil {
			t.Fatal("restart after lost delete reply and SQL rollback", e)
		}
		if _, e = db.Exec(`DROP TRIGGER fail_s3_delete_refund`); e != nil {
			t.Fatal(e)
		}
		if e = resumed.settleMediaDeletion(ctx, pending[0], drained); e != nil || fixture.deletes != 1 {
			t.Fatal("proven absence did not settle without repeating DELETE", e)
		}
		assertUsed(0)
		if e = resumed.settleMediaDeletion(ctx, pending[0], drained); e != nil {
			t.Fatal("settled deletion retry", e)
		}
		assertUsed(0)
		if e = r.CheckSelectedS3Startup(ctx, tree, key); e != nil {
			t.Fatal("settled S3 deletion startup", e)
		}
		if done, e := coordinator.QueueMediaDeletion(ctx, sessionHash, target, store.AdminAudit{}); e != nil || done.State != store.SelectedMediaDeleteDeleted || done.OperationID != queued.OperationID {
			t.Fatal("terminal S3 retry", done, e)
		}
		for _, retry := range []func(context.Context, string, string) (SelectedS3Status, error){
			coordinator.Status, coordinator.BeginOrRecover, coordinator.Complete, coordinator.Cancel,
		} {
			if state, e := retry(ctx, sessionHash, uploadID); e != nil || state.State != "deleted" || fixture.deletes != 1 || fixture.completes != 1 {
				t.Fatal("old upload retry must report deleted without provider mutation", state, e)
			}
		}
		bad = target
		bad.Path = "music/category/replacement.mp3"
		if _, e = coordinator.QueueMediaDeletion(ctx, sessionHash, bad, store.AdminAudit{}); e == nil {
			t.Fatal("wrong path matched the terminal deletion")
		}
		target.OperationID = strings.Repeat("e", 32)
		if _, e = coordinator.QueueMediaDeletion(ctx, sessionHash, target, store.AdminAudit{}); e == nil {
			t.Fatal("foreign operation ID matched terminal object")
		}
	})

	makePending := func(objectDigit, uploadDigit string) (string, *SelectedS3Coordinator, *selectedS3NetworkFixture) {
		t.Helper()
		objectID, id := strings.Repeat(objectDigit, 64), strings.Repeat(uploadDigit, 32)
		entry := sealedtree.Entry{ParentID: category.ObjectID, ObjectID: objectID, Kind: "audio", Name: objectDigit + ".mp3"}
		metadata, e := mediacrypto.NewMetadata(101)
		if e != nil {
			t.Fatal(e)
		}
		placement := sealedtree.Placement{ObjectID: objectID, NativeObjectID: objectID, OwnerID: member, Bytes: metadata.CiphertextSize, SHA256: strings.Repeat("9", 64), Encryption: &metadata, State: "active"}
		facts := sealedtree.Facts{ObjectID: objectID, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: id, AdminBinding: sessionHash, Policy: "S3", Revision: 1}}
		if _, _, e = r.prepareSelectedCoordinated(ctx, tree, key, entry, placement, facts, 0, check, []string{checksum}); e != nil {
			t.Fatal("second reservation", e)
		}
		provider := &selectedS3NetworkFixture{t: t}
		c, e := NewSelectedS3Coordinator(uploadRuntime, provider, s3Gate)
		if e != nil {
			t.Fatal(e)
		}
		return id, c, provider
	}
	secondID, secondCoordinator, secondProvider := makePending("7", "6")
	if _, err = secondCoordinator.Begin(ctx, sessionHash, secondID); err != nil {
		t.Fatal("begin cancel fixture", err)
	}
	cancelled, err := secondCoordinator.Cancel(ctx, sessionHash, secondID)
	if err != nil || cancelled.State != "cancelled" || secondProvider.aborts != 1 {
		t.Fatal("exact S3 cancellation", cancelled, err)
	}
	if err = r.CheckSelectedS3Startup(ctx, tree, key); err != nil {
		t.Fatal("cancelled selected S3 startup", err)
	}
	cancelled, err = secondCoordinator.Cancel(ctx, sessionHash, secondID)
	if err != nil || cancelled.State != "cancelled" || secondProvider.aborts != 1 {
		t.Fatal("cancellation retry", cancelled, err)
	}
	thirdID, thirdCoordinator, thirdProvider := makePending("6", "7")
	if _, err = thirdCoordinator.Begin(ctx, sessionHash, thirdID); err != nil {
		t.Fatal(err)
	}
	thirdMeta, err := mediacrypto.NewMetadata(101)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = thirdCoordinator.PartGrant(ctx, sessionHash, thirdID, 1, thirdMeta.CiphertextSize, checksum); err != nil {
		t.Fatal(err)
	}
	if _, err = thirdCoordinator.Cancel(ctx, sessionHash, thirdID); !errors.Is(err, s3media.ErrPending) || thirdProvider.aborts != 0 {
		t.Fatal("live grant cleanup not deferred", err)
	}
	if state, e := thirdCoordinator.Status(ctx, sessionHash, thirdID); e != nil || state.State != "aborting" {
		t.Fatal("cancel status", state, e)
	}
	if _, err = thirdCoordinator.Begin(ctx, sessionHash, thirdID); err == nil {
		t.Fatal("cancelled intent accepted new create")
	}
}
