package business_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type s3SQLFixture struct {
	ctx  context.Context
	db   store.Store
	raw  *sql.DB
	pool store.PoolRepository
	repo store.S3Repository
}

func newS3SQL(t *testing.T, master bool) *s3SQLFixture {
	t.Helper()
	db := database(t)
	f := &s3SQLFixture{ctx: context.Background(), db: db, raw: db.(interface{ Database() *sql.DB }).Database(), pool: db.Pool(), repo: db.Pool().(store.S3Repository)}
	if _, err := db.Nodes().InitializeIdentity(f.ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "sealed-fixture", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if master {
		if _, err := db.Nodes().PromoteIdentity(f.ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 20 * store.GiB, PhysicalFree: 5 * store.GiB}, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func s3SQLConfig(prefix string) store.S3MemberConfiguration {
	sealed := "opaque-sealed-fixture"
	return store.S3MemberConfiguration{Name: "S3 fixture", Location: store.S3Location{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "fc-fixture", Region: "us-east-1", Prefix: prefix, Style: "path"}, Quota: 20 * store.GiB, SealedCredentials: &sealed}
}

func (f *s3SQLFixture) add(t *testing.T, prefix string, enabled bool) store.S3Member {
	t.Helper()
	c := s3SQLConfig(prefix)
	v, err := f.repo.S3AddMember(f.ctx, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return v
	}
	p, err := f.repo.S3StartProbe(f.ctx, v.ID, v.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	v, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, store.S3ProbeResult{Key: p.Key, ProviderUploadID: "probe-upload", VersionID: "probe-version", ETag: "probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	c.SealedCredentials = nil
	c.Enabled = true
	v, err = f.repo.S3ConfigureMember(f.ctx, v.ID, v.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *s3SQLFixture) reserve(t *testing.T, name string, size int64, encryption *mediacrypto.Metadata) store.S3Upload {
	t.Helper()
	v, err := f.pool.(store.EncryptionRepository).ReserveEncryptedUpload(f.ctx, name, "s3", size, 0, store.AdminAudit{}, encryption)
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.repo.S3Upload(f.ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *s3SQLFixture) created(t *testing.T, u store.S3Upload) store.S3Upload {
	t.Helper()
	u, err := f.repo.S3StartCreate(f.ctx, u.Reservation.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	u, err = f.repo.S3FinishCreate(f.ctx, u.Reservation.ID, u.Revision, "provider-upload", "created", "")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func s3SQLChecksum(number int) string {
	sum := sha256.Sum256([]byte(fmt.Sprint("part-", number)))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (f *s3SQLFixture) completing(t *testing.T, u store.S3Upload) (store.S3Upload, store.S3ObjectProof) {
	t.Helper()
	u = f.created(t, u)
	hash := sha256.New()
	count := int((u.Reservation.ExpectedBytes + store.S3PartBytes - 1) / store.S3PartBytes)
	for number := 1; number <= count; number++ {
		size := min(store.S3PartBytes, u.Reservation.ExpectedBytes-int64(number-1)*store.S3PartBytes)
		part, err := f.repo.S3IssuePart(f.ctx, u.Reservation.ID, number, s3SQLChecksum(number), size)
		if err != nil {
			t.Fatal(err)
		}
		part.ETag = fmt.Sprintf("etag-%d", number)
		u, err = f.repo.S3ConfirmPart(f.ctx, u.Reservation.ID, part)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := base64.StdEncoding.DecodeString(part.SHA256)
		hash.Write(digest)
	}
	u, err := f.repo.S3StartComplete(f.ctx, u.Reservation.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	proof := store.S3ObjectProof{Key: u.Key, SessionID: u.Reservation.ID, ObjectID: u.ObjectID, MemberID: u.Reservation.MemberID, MediaID: u.Reservation.MediaID, Bytes: u.Reservation.ExpectedBytes, ETag: "object-etag", VersionID: "object-version", CompositeSHA256: base64.StdEncoding.EncodeToString(hash.Sum(nil)) + fmt.Sprint("-", count)}
	return u, proof
}

func s3SQLAbsence(u store.S3Upload) store.S3AbsenceProof {
	return store.S3AbsenceProof{Key: u.Key, SessionID: u.Reservation.ID, ObjectID: u.ObjectID, MemberID: u.Reservation.MemberID, MediaID: u.Reservation.MediaID, ProviderUploadID: u.ProviderUploadID, ObjectAbsent: true, MultipartAbsent: true}
}

func requireS3State(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("expected S3 state refusal, got %v", err)
	}
}

func TestS3SQLMasterOnlyProbeAndNativeCapabilities(t *testing.T) {
	f := newS3SQL(t, false)
	_, err := f.repo.S3AddMember(f.ctx, s3SQLConfig("tenant"), store.NodeAudit{})
	requireS3State(t, err)
	if _, err = f.repo.S3Members(f.ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("Standalone exposed S3", err)
	}
	if _, err = f.db.Nodes().PromoteIdentity(f.ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 20 * store.GiB, PhysicalFree: 5 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	v := f.add(t, "tenant", false)
	if v.Enabled != 0 || v.Writable != 0 || v.ProbeState != "unchecked" || v.RelationshipID != nil || v.Transport != "S3" {
		t.Fatal("unexpected native capabilities", v)
	}
	_, err = f.repo.S3ProbeMember(f.ctx, v.ID, v.Revision, "", store.NodeAudit{})
	requireS3State(t, err)
	c := s3SQLConfig("tenant")
	c.Enabled = true
	c.SealedCredentials = nil
	_, err = f.repo.S3ConfigureMember(f.ctx, v.ID, v.Revision, c, store.NodeAudit{})
	requireS3State(t, err)
	if err = f.pool.ConfigureMember(f.ctx, v.ID, store.ResourceConfiguration{}, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native config accepted S3", err)
	}
	if _, err = f.pool.MemberConfiguration(f.ctx, v.ID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native backup/compute config accepted S3", err)
	}
	for _, table := range []string{"cluster_compute_members", "cluster_backup_members", "node_relationships"} {
		var count int
		query := "SELECT COUNT(*) FROM " + table + " WHERE member_id=?"
		if table == "node_relationships" {
			query = "SELECT COUNT(*) FROM node_relationships WHERE peer_id=?"
		}
		if err = f.raw.QueryRow(query, v.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("invented native capability", table, count, err)
		}
	}
	p, err := f.repo.S3StartProbe(f.ctx, v.ID, v.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, store.S3ProbeResult{Key: "wrong-key", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	requireS3State(t, err)
	// A metadata-only configuration CAS is allowed during the network probe,
	// but its later result cannot grant confidence to this newer revision.
	c.Enabled = false
	c.Name = "renamed"
	v, err = f.repo.S3ConfigureMember(f.ctx, v.ID, v.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	v, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, store.S3ProbeResult{Key: p.Key, ProviderUploadID: "probe-1", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if v.ProbeState == "ready" || v.ProbeRevision != 0 || v.Writable != 0 {
		t.Fatal("late probe trusted newer revision", v)
	}
	_, err = f.repo.S3ConfigureMember(f.ctx, v.ID, v.Revision-1, c, store.NodeAudit{})
	requireS3State(t, err)
	_, err = f.repo.S3StartProbe(f.ctx, v.ID, v.Revision, store.NodeAudit{})
	requireS3State(t, err)
}

func TestS3SQLNamespaceAliasesSerialized(t *testing.T) {
	f := newS3SQL(t, true)
	configs := []store.S3MemberConfiguration{s3SQLConfig("tenant"), s3SQLConfig("tenant/child")}
	configs[1].Location.Endpoint = "https://s3.amazonaws.com"
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, config := range configs {
		wg.Go(func() { _, err := f.repo.S3AddMember(f.ctx, config, store.NodeAudit{}); errs <- err })
	}
	wg.Wait()
	close(errs)
	accepted, refused := 0, 0
	for err := range errs {
		if err == nil {
			accepted++
		} else if errors.Is(err, store.ErrNodeState) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatal("overlap raced namespace lock", accepted, refused)
	}
	if _, err := f.repo.S3AddMember(f.ctx, s3SQLConfig("tenant2"), store.NodeAudit{}); err != nil {
		t.Fatal("segment sibling falsely overlaps", err)
	}
	config := s3SQLConfig("tenant")
	config.Location.Bucket = "different-bucket"
	if _, err := f.repo.S3AddMember(f.ctx, config, store.NodeAudit{}); err != nil {
		t.Fatal("independent bucket refused", err)
	}
}

func TestS3SQLSettledProbeIsImmutable(t *testing.T) {
	f := newS3SQL(t, true)
	v := f.add(t, "probe-immutable", false)
	p, err := f.repo.S3StartProbe(f.ctx, v.ID, v.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	proof := store.S3ProbeResult{Key: p.Key, ProviderUploadID: "probe-upload", VersionID: "probe-version", ETag: "probe-etag", ChecksPassed: true, CleanupSettled: true}
	v, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, proof, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, proof, store.NodeAudit{}); err != nil {
		t.Fatal("lost probe response not idempotent", err)
	}
	proof.ChecksPassed = false
	proof.ErrorCode = "failed_later"
	_, err = f.repo.S3FinishProbe(f.ctx, p.ID, p.Revision, proof, store.NodeAudit{})
	requireS3State(t, err)
	current, err := f.repo.S3Member(f.ctx, v.ID)
	if err != nil || current.ProbeState != "ready" || current.ProbeRevision != p.Revision {
		t.Fatal("terminal probe reused", current, err)
	}
}

func TestS3SQLConcurrentQuotaCannotOversell(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "quota-race", true)
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for index := range 16 {
		wg.Go(func() {
			_, err := f.pool.ReserveUpload(f.ctx, fmt.Sprintf("music/S3Concurrent/%d.mp3", index), "s3", 2*store.GiB, 0, store.AdminAudit{})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			requireS3State(t, err)
		}
	}
	if accepted != 10 {
		t.Fatal("quota admitted wrong total", accepted)
	}
	member, err := f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Reserved != 20*store.GiB || member.Available != 0 {
		t.Fatal("quota oversold", member, err)
	}
	var sessions, journals int
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM cluster_upload_sessions WHERE state='reserved'").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM s3_uploads WHERE state='reserved'").Scan(&journals); err != nil || sessions != 10 || journals != sessions {
		t.Fatal("reservation/journal transaction split", sessions, journals, err)
	}
}

func TestS3SQLQuotaAffinityCryptoAndAdmission(t *testing.T) {
	f := newS3SQL(t, true)
	first := f.add(t, "first", true)
	f.add(t, "second", true)
	meta, err := mediacrypto.NewMetadata(2*store.S3PartBytes + 3)
	if err != nil {
		t.Fatal(err)
	}
	u := f.reserve(t, "music/S3Affinity/a.mp3", meta.CiphertextSize, &meta)
	if u.Reservation.Encryption == nil || u.State != "reserved" || u.GrantUntil != 0 || u.CreateUncertain || u.AbsoluteExpiresAt-u.Reservation.CreatedAt != store.S3AbsoluteSeconds || u.Reservation.ExpiresAt-u.Reservation.CreatedAt != store.S3IdleSeconds {
		t.Fatal("reservation/crypto/deadline binding", u)
	}
	v := f.reserve(t, "music/S3Affinity/b.mp3", 1, nil)
	if u.Reservation.MemberID != v.Reservation.MemberID {
		t.Fatal("same parent split owners")
	}
	member, err := f.repo.S3Member(f.ctx, u.Reservation.MemberID)
	if err != nil {
		t.Fatal(err)
	}
	if member.Reserved != meta.CiphertextSize+1 || member.Used != 0 {
		t.Fatal("quota not durable", member)
	}
	c := s3SQLConfig(member.Location.Prefix)
	c.SealedCredentials = nil
	c.Enabled = false
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.ReserveUpload(f.ctx, "music/S3Affinity/c.mp3", "s3", 1, 0, store.AdminAudit{})
	requireS3State(t, err)
	if _, err = f.pool.ReserveUpload(f.ctx, "music/S3TooLarge/a.mp3", "s3", store.S3MaxObjectBytes+1, 0, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("oversized object", err)
	}
	c.SealedCredentials = new(string)
	*c.SealedCredentials = "replacement"
	_, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	requireS3State(t, err)
	c.SealedCredentials = nil
	c.Location.Prefix = "moved"
	_, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	requireS3State(t, err)
	if _, err = f.pool.FinalizeUpload(f.ctx, u.Reservation.ID, u.ObjectID, u.Reservation.ExpectedBytes, "etag", store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native finalize bypassed provider", err)
	}
	if _, err = f.pool.FinalizeRecoveredUpload(f.ctx, u.Reservation.ID, u.ObjectID, u.Reservation.ExpectedBytes, "etag", store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native recovered finalize bypassed provider", err)
	}
	if err = f.pool.ReleaseCleanedUpload(f.ctx, u.Reservation.ID, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native release bypassed provider", err)
	}
	if expired, err := f.pool.ExpiredUploads(f.ctx, 100); err != nil || len(expired) != 0 {
		t.Fatal("S3 leaked into native expiry sweep", expired, err)
	}
	if _, err = f.pool.(store.MigrationRepository).MigrationCatalog(f.ctx, first.ID, member.ID); !errors.Is(err, store.ErrMigrationState) {
		t.Fatal("S3 entered native migration", err)
	}
}

func TestS3SQLImmutablePartsAndCompletion(t *testing.T) {
	f := newS3SQL(t, true)
	f.add(t, "uploads", true)
	u := f.created(t, f.reserve(t, "music/S3Parts/a.mp3", 2*store.S3PartBytes+3, nil))
	if _, err := f.repo.S3StartComplete(f.ctx, u.Reservation.ID, u.Revision); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("missing parts accepted", err)
	}
	part1, err := f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 1, s3SQLChecksum(1), store.S3PartBytes)
	if err != nil {
		t.Fatal(err)
	}
	if part1.GrantUntil <= time.Now().Unix() || part1.GrantUntil > time.Now().Unix()+store.S3GrantSeconds {
		t.Fatal("unbounded grant", part1)
	}
	_, err = f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 1, s3SQLChecksum(9), store.S3PartBytes)
	requireS3State(t, err)
	_, err = f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 2, s3SQLChecksum(2), store.S3PartBytes-1)
	requireS3State(t, err)
	if _, err = f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 2, s3SQLChecksum(2), store.S3PartBytes); err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 3, s3SQLChecksum(3), 3)
	requireS3State(t, err)
	part1.ETag = "part-one"
	u, err = f.repo.S3ConfirmPart(f.ctx, u.Reservation.ID, part1)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := u.ConfirmedBytes
	u, err = f.repo.S3ConfirmPart(f.ctx, u.Reservation.ID, part1)
	if err != nil || u.ConfirmedBytes != confirmed {
		t.Fatal("duplicate confirm changed quota", u, err)
	}
	part1.ETag = "different"
	_, err = f.repo.S3ConfirmPart(f.ctx, u.Reservation.ID, part1)
	requireS3State(t, err)
	if _, err = f.repo.S3IssuePart(f.ctx, u.Reservation.ID, 3, s3SQLChecksum(3), 3); err != nil {
		t.Fatal("confirmed grant did not free window", err)
	}
	for _, number := range []int{2, 3} {
		part := store.S3Part{Number: number, Bytes: store.S3PartBytes, SHA256: s3SQLChecksum(number), ETag: fmt.Sprint("part-", number)}
		if number == 3 {
			part.Bytes = 3
		}
		u, err = f.repo.S3ConfirmPart(f.ctx, u.Reservation.ID, part)
		if err != nil {
			t.Fatal(err)
		}
	}
	oldRev := u.Revision
	u, err = f.repo.S3StartComplete(f.ctx, u.Reservation.ID, oldRev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3StartComplete(f.ctx, u.Reservation.ID, oldRev); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale complete token accepted", err)
	}
	same, err := f.repo.S3StartComplete(f.ctx, u.Reservation.ID, u.Revision)
	if err != nil || same.Revision != u.Revision {
		t.Fatal("lost Complete cannot resume Head", same, err)
	}
	hash := sha256.New()
	for n := 1; n <= 3; n++ {
		digest, _ := base64.StdEncoding.DecodeString(s3SQLChecksum(n))
		hash.Write(digest)
	}
	proof := store.S3ObjectProof{Key: u.Key, SessionID: u.Reservation.ID, ObjectID: u.ObjectID, MemberID: u.Reservation.MemberID, MediaID: u.Reservation.MediaID, Bytes: u.Reservation.ExpectedBytes, ETag: "completed-etag", VersionID: "version-1", CompositeSHA256: base64.StdEncoding.EncodeToString(hash.Sum(nil)) + "-3"}
	for _, field := range []string{"key", "session", "object", "member", "media", "size", "checksum"} {
		bad := proof
		switch field {
		case "key":
			bad.Key += "x"
		case "session":
			bad.SessionID += "x"
		case "object":
			bad.ObjectID += "x"
		case "member":
			bad.MemberID += "x"
		case "media":
			bad.MediaID += "x"
		case "size":
			bad.Bytes++
		case "checksum":
			bad.CompositeSHA256 += "x"
		}
		if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, bad, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid binding accepted", field, err)
		}
	}
	media, err := f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if media.Transport != "S3" || media.RelationshipID != nil || media.Bytes != proof.Bytes {
		t.Fatal(media)
	}
	if again, err := f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err != nil || again.ID != media.ID {
		t.Fatal("completion retry not idempotent", again, err)
	}
	member, err := f.repo.S3Member(f.ctx, media.MemberID)
	if err != nil || member.Used != proof.Bytes || member.Reserved != 0 {
		t.Fatal("publication did not atomically exchange quota", member, err)
	}
	object, err := f.repo.S3Object(f.ctx, media.ID)
	if err != nil || object.Proof != proof || object.GrantUntil < part1.GrantUntil {
		t.Fatal("object proof/grant lost", object, err)
	}
}

func TestS3SQLUnknownCreationAndAbortProof(t *testing.T) {
	f := newS3SQL(t, true)
	f.add(t, "abort", true)
	u := f.reserve(t, "music/S3Abort/never-created.mp3", 7, nil)
	u, err := f.repo.S3RequestAbort(f.ctx, u.Reservation.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	bad := s3SQLAbsence(u)
	bad.MemberID = "wrong"
	_, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, bad, store.AdminAudit{})
	requireS3State(t, err)
	u, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, s3SQLAbsence(u), store.AdminAudit{})
	if err != nil || u.State != "aborted" || u.Reservation.State != "cancelled" {
		t.Fatal(u, err)
	}
	if _, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, s3SQLAbsence(u), store.AdminAudit{}); err != nil {
		t.Fatal("abort retry failed", err)
	}
	unknown := f.reserve(t, "music/S3Abort/unknown.mp3", 9, nil)
	unknown, err = f.repo.S3StartCreate(f.ctx, unknown.Reservation.ID, unknown.Revision)
	if err != nil || !unknown.CreateUncertain {
		t.Fatal(unknown, err)
	}
	if _, err = f.repo.S3StartCreate(f.ctx, unknown.Reservation.ID, unknown.Revision); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("repeated unknown Create accepted", err)
	}
	unknown, err = f.repo.S3FinishCreate(f.ctx, unknown.Reservation.ID, unknown.Revision, "", "unknown", "timeout")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3FinishCreate(f.ctx, unknown.Reservation.ID, unknown.Revision, "", "rejected", "")
	requireS3State(t, err)
	unknown, err = f.repo.S3RequestAbort(f.ctx, unknown.Reservation.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3FinishAbort(f.ctx, unknown.Reservation.ID, unknown.Revision, s3SQLAbsence(unknown), store.AdminAudit{})
	requireS3State(t, err)
	unknown, err = f.repo.S3FinishCreate(f.ctx, unknown.Reservation.ID, unknown.Revision, "exact-discovered-upload", "created", "")
	if err != nil || unknown.State != "aborting" || unknown.CreateUncertain {
		t.Fatal("exact upload recovery reopened writes", unknown, err)
	}
	if _, err = f.repo.S3IssuePart(f.ctx, unknown.Reservation.ID, 1, s3SQLChecksum(1), 9); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("aborting upload granted part", err)
	}
	unknown, err = f.repo.S3FinishAbort(f.ctx, unknown.Reservation.ID, unknown.Revision, s3SQLAbsence(unknown), store.AdminAudit{})
	if err != nil || unknown.State != "aborted" {
		t.Fatal(unknown, err)
	}
	member, err := f.repo.S3Member(f.ctx, unknown.Reservation.MemberID)
	if err != nil || member.Reserved != 0 || member.Used != 0 {
		t.Fatal("abort accounting", member, err)
	}
}

func TestS3SQLAtomicReservationAndPublication(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST") != "" {
		t.Skip("SQLite trigger injects deterministic transaction failure; native MySQL lifecycle runs separately")
	}
	f := newS3SQL(t, true)
	member := f.add(t, "atomic", true)
	if _, err := f.raw.Exec("CREATE TRIGGER fail_s3_reserve BEFORE INSERT ON s3_uploads BEGIN SELECT RAISE(ABORT,'fixture reserve failure'); END"); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.(store.EncryptionRepository).ReserveEncryptedUpload(f.ctx, "music/S3Atomic/a.mp3", "s3", meta.CiphertextSize, 0, store.AdminAudit{}, &meta); err == nil {
		t.Fatal("injected reservation succeeded")
	}
	for _, table := range []string{"cluster_upload_sessions", "media_encryption", "s3_uploads"} {
		var count int
		if err = f.raw.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("reservation partially committed", table, count, err)
		}
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Reserved != 0 {
		t.Fatal("failed reservation leaked quota", member, err)
	}
	if _, err = f.raw.Exec("DROP TRIGGER fail_s3_reserve"); err != nil {
		t.Fatal(err)
	}
	u, proof := f.completing(t, f.reserve(t, "music/S3Atomic/a.mp3", meta.CiphertextSize, &meta))
	if _, err = f.raw.Exec("CREATE TRIGGER fail_s3_publish BEFORE INSERT ON s3_objects BEGIN SELECT RAISE(ABORT,'fixture publication failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err == nil {
		t.Fatal("injected publication succeeded")
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Used != 0 || member.Reserved != proof.Bytes {
		t.Fatal("publication partially changed quota", member, err)
	}
	var count int
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM global_media_objects").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial global catalog", count, err)
	}
	current, err := f.repo.S3Upload(f.ctx, u.Reservation.ID)
	if err != nil || current.State != "completing" || current.Reservation.State != "reserved" || current.Reservation.Encryption == nil {
		t.Fatal("completion rollback lost journal/crypto", current, err)
	}
	if _, err = f.raw.Exec("DROP TRIGGER fail_s3_publish"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err != nil {
		t.Fatal("same-proof retry after SQL fault", err)
	}
}

func TestS3SQLLogicalRenameReadAndDeleteFences(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "rename", true)
	u, proof := f.completing(t, f.reserve(t, "music/S3Before/a.mp3", 7, nil))
	media, err := f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	op, err := f.pool.PrepareGlobalRename(f.ctx, "music/S3Before", "music/S3After", store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.pool.CompleteGlobalRename(f.ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.CompleteGlobalRenameCleanup(f.ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	object, err := f.repo.S3Object(f.ctx, media.ID)
	if err != nil || object.Proof.Key != proof.Key || object.Media.Path != "music/S3After/a.mp3" {
		t.Fatal("logical rename moved provider identity", object, err)
	}
	c := s3SQLConfig("rename")
	c.SealedCredentials = nil
	c.Enabled = false
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+30); err != nil {
		t.Fatal("placement disable broke existing reads", err)
	}
	if _, err = f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+store.S3GrantSeconds+5); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unbounded read accepted", err)
	}
	deleting, err := f.repo.S3StartDelete(f.ctx, media.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+30); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("delete admitted read", err)
	}
	if err = f.pool.CompleteGlobalDelete(f.ctx, media.ID, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("native deletion bypassed S3 proof", err)
	}
	if pending, err := f.pool.PendingGlobalDeletes(f.ctx, 50); err != nil || len(pending) != 0 {
		t.Fatal("S3 leaked into native deletion recovery", pending, err)
	}
	absence := s3SQLAbsence(u)
	absence.VersionID = proof.VersionID
	absence.ETag = proof.ETag
	if err = f.repo.S3FinishDelete(f.ctx, media.ID, deleting.Revision, absence, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("live upload/read grants released quota", err)
	}
	if pending, err := f.repo.S3PendingDeletes(f.ctx, 50); err != nil || len(pending) != 1 {
		t.Fatal("delete intent not recoverable", pending, err)
	}
}

func TestS3SQLActualGrantSettlement(t *testing.T) {
	if os.Getenv("FC_S3_SQL_SETTLEMENT_ACCEPTANCE") != "1" {
		t.Skip("development-only actual 300-second grant settlement; no clock/deadline manipulation")
	}
	f := newS3SQL(t, true)
	member := f.add(t, "settlement", true)
	u, proof := f.completing(t, f.reserve(t, "music/S3Settlement/a.mp3", 7, nil))
	media, err := f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	deleting, err := f.repo.S3StartDelete(f.ctx, media.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	absence := s3SQLAbsence(u)
	absence.ETag = proof.ETag
	absence.VersionID = proof.VersionID
	requireS3State(t, f.repo.S3FinishDelete(f.ctx, media.ID, deleting.Revision, absence, store.AdminAudit{}))
	meta, err := mediacrypto.NewMetadata(11)
	if err != nil {
		t.Fatal(err)
	}
	aborting := f.created(t, f.reserve(t, "music/S3Settlement/aborting.mp3", meta.CiphertextSize, &meta))
	if _, err = f.repo.S3IssuePart(f.ctx, aborting.Reservation.ID, 1, s3SQLChecksum(1), meta.CiphertextSize); err != nil {
		t.Fatal(err)
	}
	aborting, err = f.repo.S3RequestAbort(f.ctx, aborting.Reservation.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3FinishAbort(f.ctx, aborting.Reservation.ID, aborting.Revision, s3SQLAbsence(aborting), store.AdminAudit{})
	requireS3State(t, err)
	c := s3SQLConfig("settlement")
	c.SealedCredentials = nil
	c.Enabled = false
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "cleanup-only-sealed", 0, store.NodeAudit{})
	requireS3State(t, err)
	wait := time.Until(time.Unix(max(deleting.GrantUntil, aborting.GrantUntil)+1, 0))
	if wait < 0 || wait > 301*time.Second {
		t.Fatal("unexpected real grant horizon", wait)
	}
	t.Logf("waiting for real durable grant expiry %s", wait)
	select {
	case <-time.After(wait):
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	member, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "cleanup-only-sealed", 0, store.NodeAudit{})
	if err != nil || !member.CleanupOnly {
		t.Fatal("settled recovery rotation", member, err)
	}
	_, err = f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	requireS3State(t, err)
	aborting, err = f.repo.S3Upload(f.ctx, aborting.Reservation.ID)
	if err != nil || aborting.CredentialRevision != member.CredentialRevision {
		t.Fatal("cleanup rotation lost durable generation", aborting, err)
	}
	aborting, err = f.repo.S3FinishAbort(f.ctx, aborting.Reservation.ID, aborting.Revision, s3SQLAbsence(aborting), store.AdminAudit{})
	if err != nil || aborting.State != "aborted" || aborting.Reservation.Encryption != nil {
		t.Fatal("settled encrypted abort", aborting, err)
	}
	var retained int
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM media_encryption WHERE file_id=? AND descriptor_json IS NULL", meta.FileID).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("abort lost nonce/file identity tombstone", retained, err)
	}
	bad := absence
	bad.ETag = "replaced-object"
	requireS3State(t, f.repo.S3FinishDelete(f.ctx, media.ID, deleting.Revision, bad, store.AdminAudit{}))
	if err = f.repo.S3FinishDelete(f.ctx, media.ID, deleting.Revision, absence, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = f.repo.S3FinishDelete(f.ctx, media.ID, deleting.Revision, absence, store.AdminAudit{}); err != nil {
		t.Fatal("idempotent deletion", err)
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Reserved != 0 || member.Used != 0 {
		t.Fatal("settled delete did not refund once", member, err)
	}
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err == nil {
		t.Fatal("old completion resurrected deleted catalog")
	}
	c = s3SQLConfig("settlement")
	c.SealedCredentials = nil
	c.Enabled = false
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, c, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.repo.S3RemoveMember(f.ctx, member.ID, member.Revision, store.NodeAudit{}); err != nil {
		t.Fatal("settled empty member removal", err)
	}
}
