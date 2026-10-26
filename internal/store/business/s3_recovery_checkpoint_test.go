package business_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestS3SQLDeleteRetryRotatesWithoutChangingAuthority(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "delete-fairness", true)
	for i := 0; i < 9; i++ {
		u, proof := f.completing(t, f.reserve(t, fmt.Sprintf("music/DeleteFairness/%d.mp3", i), 7, nil))
		media, err := f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.repo.S3StartDelete(f.ctx, media.ID, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := f.repo.S3PendingDeletes(f.ctx, 9)
	if err != nil || len(all) != 9 {
		t.Fatal(all, err)
	}
	first, ninth := all[0], all[8]
	var auditBefore, updatedBefore int64
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM admin_audit_log").Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	if err = f.raw.QueryRow("SELECT updated_at FROM s3_objects WHERE media_id=?", first.Media.ID).Scan(&updatedBefore); err != nil {
		t.Fatal(err)
	}
	memberBefore, err := f.repo.S3Member(f.ctx, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Queue timestamps are seconds. Let genuine wall time advance, without
	// changing a grant, SQL deadline, or clock, before retrying the oldest row.
	time.Sleep(1050 * time.Millisecond)
	again, err := f.repo.S3StartDelete(f.ctx, first.Media.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatal("retry changed deletion authority", again, first)
	}
	var auditAfter, updatedAfter int64
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM admin_audit_log").Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if err = f.raw.QueryRow("SELECT updated_at FROM s3_objects WHERE media_id=?", first.Media.ID).Scan(&updatedAfter); err != nil {
		t.Fatal(err)
	}
	if auditAfter != auditBefore || updatedAfter <= updatedBefore {
		t.Fatal("retry duplicated audit or did not rotate", auditBefore, auditAfter, updatedBefore, updatedAfter)
	}
	memberAfter, err := f.repo.S3Member(f.ctx, member.ID)
	if err != nil || !reflect.DeepEqual(memberBefore, memberAfter) {
		t.Fatal("retry changed quota/member facts", memberBefore, memberAfter, err)
	}
	batch, err := f.repo.S3PendingDeletes(f.ctx, 8)
	if err != nil || len(batch) != 8 {
		t.Fatal(batch, err)
	}
	foundNinth := false
	for _, item := range batch {
		if item.Media.ID == first.Media.ID {
			t.Fatal("failed first row still starves later pending work")
		}
		foundNinth = foundNinth || item.Media.ID == ninth.Media.ID
	}
	if !foundNinth {
		t.Fatal("ninth pending object did not advance into the bounded batch")
	}
}

func TestS3SQLLongETagProbeAndUnpublishedCleanupKeepCatalogBound(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "long-etag-probe", false)
	probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "long-probe-upload"); err != nil {
		t.Fatal(err)
	}
	long := `"` + strings.Repeat("e", 510) + `"`
	if len(long) != 512 {
		t.Fatal("wrong ETag fixture width")
	}
	bad := store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "long-probe-upload", VersionID: "long-version", ETag: long + "x", CleanupSettled: true, ErrorCode: "probe_etag_unsupported"}
	if _, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, bad, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unbounded probe ETag accepted", err)
	}
	bad.ETag = long
	member, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, bad, store.NodeAudit{})
	if err != nil || member.ProbeState != "failed" || member.ProbeRevision != 0 {
		t.Fatal("long ETag cleanup could not settle safely", member, err)
	}
	var stored, state string
	var until int64
	if err = f.raw.QueryRow("SELECT etag,state,grant_until FROM s3_probe_journal WHERE probe_id=?", probe.ID).Scan(&stored, &state, &until); err != nil || stored != long || state != "settled" || until != probe.GrantUntil {
		t.Fatal("long ETag cleanup lost proof/horizon", len(stored), state, until, err)
	}

	// An unpublished owned key may be discovered during abort even when no
	// part bearer was issued. Supply only exact bounded provider observations.
	f.add(t, "long-etag-objects", true)
	u := f.created(t, f.reserve(t, "music/LongETag/unpublished.mp3", 7, nil))
	u, err = f.repo.S3RequestAbort(f.ctx, u.Reservation.ID, store.AdminAudit{})
	if err != nil || u.GrantUntil != 0 {
		t.Fatal(u, err)
	}
	absence := s3SQLAbsence(u)
	absence.VersionID, absence.ETag = "unpublished-version", long
	wrong := absence
	wrong.Key += "-foreign"
	if _, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, wrong, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("long proof weakened exact key ownership", err)
	}
	tooLong := absence
	tooLong.ETag += "x"
	if _, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, tooLong, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unbounded abort ETag accepted", err)
	}
	u, err = f.repo.S3FinishAbort(f.ctx, u.Reservation.ID, u.Revision, absence, store.AdminAudit{})
	if err != nil || u.State != "aborted" {
		t.Fatal("exact long ETag cleanup remained stuck", u, err)
	}
	owner, err := f.repo.S3Member(f.ctx, u.Reservation.MemberID)
	if err != nil || owner.Used != 0 || owner.Reserved != 0 {
		t.Fatal("abort did not refund only its exact reservation", owner, err)
	}

	u, proof := f.completing(t, f.reserve(t, "music/LongETag/published.mp3", 7, nil))
	proof.ETag = strings.Repeat("e", 129)
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("published catalog exceeded its historical 128-byte bound", err)
	}
	proof.ETag = strings.Repeat("e", 128)
	if _, err = f.repo.S3FinalizeUpload(f.ctx, u.Reservation.ID, u.Revision, proof, store.AdminAudit{}); err != nil {
		t.Fatal("128-byte catalog boundary no longer accepted", err)
	}
	partUpload := f.created(t, f.reserve(t, "music/LongETag/part.mp3", 7, nil))
	part, err := f.repo.S3IssuePart(f.ctx, partUpload.Reservation.ID, 1, s3SQLChecksum(1), 7)
	if err != nil {
		t.Fatal(err)
	}
	part.ETag = strings.Repeat("e", 129)
	if _, err = f.repo.S3ConfirmPart(f.ctx, partUpload.Reservation.ID, part); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("part proof exceeded its historical 128-byte bound", err)
	}
}

func TestS3SQLProbeCheckpointCASAndIdentityAreDurable(t *testing.T) {
	f := newS3SQL(t, true)
	member := f.add(t, "probe-checkpoint", false)
	probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	beforeMember, err := f.repo.S3Member(f.ctx, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	var auditsBefore int64
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM node_audit").Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		id       string
		revision int64
		uid      string
	}{
		{probe.ID, probe.Revision, ""}, {probe.ID, probe.Revision, strings.Repeat("u", 2049)},
		{probe.ID, probe.Revision + 1, "wrong-cas"}, {strings.Repeat("f", 32), probe.Revision, "missing-intent"},
	} {
		if err = f.repo.S3CheckpointProbe(f.ctx, test.id, test.revision, test.uid); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid checkpoint accepted", test, err)
		}
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "exact-upload"); err != nil {
		t.Fatal(err)
	}
	read := func() store.S3Probe {
		t.Helper()
		rows, err := f.repo.S3RecoveryProbes(f.ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ID == probe.ID {
				return row
			}
		}
		t.Fatal("checkpoint lost pending durable probe")
		return store.S3Probe{}
	}
	after := read()
	expected := probe
	expected.ProviderUploadID, expected.UpdatedAt = "exact-upload", after.UpdatedAt
	if !reflect.DeepEqual(expected, after) {
		t.Fatal("checkpoint changed fields beyond UID/update time", expected, after)
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "exact-upload"); err != nil {
		t.Fatal("same UID retry failed", err)
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "foreign-upload"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("checkpoint replaced the Create identity", err)
	}
	afterMember, err := f.repo.S3Member(f.ctx, member.ID)
	var auditsAfter int64
	if err != nil || !reflect.DeepEqual(beforeMember, afterMember) {
		t.Fatal("checkpoint changed member/secret/capacity", beforeMember, afterMember, err)
	}
	if err = f.raw.QueryRow("SELECT COUNT(*) FROM node_audit").Scan(&auditsAfter); err != nil || auditsAfter != auditsBefore {
		t.Fatal("checkpoint manufactured a probe result audit", auditsBefore, auditsAfter, err)
	}
	if _, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ErrorCode: "probe_cleanup_pending"}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	cleanup := read()
	if cleanup.State != "cleanup" || cleanup.ProviderUploadID != "exact-upload" || cleanup.GrantUntil != probe.GrantUntil {
		t.Fatal("cleanup forgot the checkpoint", cleanup)
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "exact-upload"); err != nil {
		t.Fatal("same UID cleanup replay failed", err)
	}
	if again := read(); !reflect.DeepEqual(again, cleanup) {
		t.Fatal("idempotent cleanup replay changed pending facts", again, cleanup)
	}
	if _, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, CleanupSettled: true, ErrorCode: "probe_recovered"}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = f.repo.S3CheckpointProbe(f.ctx, probe.ID, probe.Revision, "exact-upload"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("checkpoint reopened settled intent", err)
	}
}

func TestS3SQLProbeCheckpointRequiresMaster(t *testing.T) {
	f := newS3SQL(t, false)
	if err := f.repo.S3CheckpointProbe(f.ctx, strings.Repeat("a", 32), 1, "upload"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("Standalone gained S3 checkpoint authority", err)
	}
}
