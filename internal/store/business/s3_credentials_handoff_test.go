package business_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// These are SQL observations, not provider URLs or STS credentials. The normal
// credential-expiry field bounds actual durable grants, and wall time elapses
// without changing a clock or rewriting any stored authorization deadline.
func TestS3SQLCredentialsHandoffPreservesActiveObjectsAfterActualGrantExpiry(t *testing.T) {
	f := newS3SQL(t, true)
	cfg := s3SQLConfig("credential-handoff")
	cfg.CredentialExpiresAt = time.Now().Unix() + 45
	member, err := f.repo.S3AddMember(f.ctx, cfg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	oldProbe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	member, err = f.repo.S3FinishProbe(f.ctx, oldProbe.ID, oldProbe.Revision, store.S3ProbeResult{Key: oldProbe.Key, ProviderUploadID: "old-probe-upload", VersionID: "old-probe-version", ETag: "old-probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SealedCredentials, cfg.Enabled = nil, true
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, cfg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	upload, proof := f.completing(t, f.reserve(t, "music/CredentialHandoff/original.mp3", 7, nil))
	media, err := f.repo.S3FinalizeUpload(f.ctx, upload.Reservation.ID, upload.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+store.S3GrantSeconds)
	if err != nil {
		t.Fatal(err)
	}
	pending := f.created(t, f.reserve(t, "music/CredentialHandoff/pending.mp3", 11, nil))
	part, err := f.repo.S3IssuePart(f.ctx, pending.Reservation.ID, 1, s3SQLChecksum(1), pending.Reservation.ExpectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = f.repo.S3RequestAbort(f.ctx, pending.Reservation.ID, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if read.GrantUntil != cfg.CredentialExpiresAt || part.GrantUntil != cfg.CredentialExpiresAt || oldProbe.GrantUntil != cfg.CredentialExpiresAt {
		t.Fatal("durable grants ignored normal credential expiry", read.GrantUntil, part.GrantUntil, oldProbe.GrantUntil, cfg.CredentialExpiresAt)
	}
	cfg.Enabled = false
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, cfg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "new-cleanup-sealed", 0, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("old live grants permitted key handoff", err)
	}
	original, err := f.repo.S3Object(f.ctx, media.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.repo.S3Member(f.ctx, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Used != 7 || before.Reserved != 11 {
		t.Fatal("fixture quota did not bind active and pending data", before)
	}
	wait := time.Until(time.Unix(cfg.CredentialExpiresAt+1, 0))
	if wait <= 0 || wait > 46*time.Second {
		t.Fatal("unexpected natural credential horizon", wait)
	}
	t.Logf("waiting for actual SQL read/write/probe grant expiry: %s", wait)
	select {
	case <-time.After(wait):
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	member, err = f.repo.S3RecoveryCredentials(f.ctx, member.ID, member.Revision, "new-cleanup-sealed", 0, store.NodeAudit{})
	if err != nil || !member.CleanupOnly || member.Enabled != 0 || member.Location != before.Location || member.CredentialRevision != before.CredentialRevision+1 {
		t.Fatal("cleanup handoff changed ownership or state", member, err)
	}
	if _, err = f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("pending upload was bypassed during probe", err)
	}
	if _, err = f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+store.S3GrantSeconds); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("cleanup credentials gained read authority before probe", err)
	}
	pending, err = f.repo.S3Upload(f.ctx, pending.Reservation.ID)
	if err != nil || pending.CredentialRevision != member.CredentialRevision {
		t.Fatal("pending cleanup did not receive new credential generation", pending, err)
	}
	pending, err = f.repo.S3FinishAbort(f.ctx, pending.Reservation.ID, pending.Revision, s3SQLAbsence(pending), store.AdminAudit{})
	if err != nil || pending.State != "aborted" {
		t.Fatal("exact pending abort did not settle", pending, err)
	}
	probe, err := f.repo.S3StartProbe(f.ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal("active owned object blocked planned probe", err)
	}
	if probe.GrantUntil <= time.Now().Unix() {
		t.Fatal("new probe did not retain its real signature horizon", probe)
	}
	member, err = f.repo.S3FinishProbe(f.ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "new-probe-upload", VersionID: "new-probe-version", ETag: "new-probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil || member.CleanupOnly || member.ProbeState != "ready" || member.ProbeRevision != member.Revision {
		t.Fatal("own settled probe horizon prevented credential recovery", member, err)
	}
	if member.Used != 7 || member.Reserved != 0 || member.Location != before.Location {
		t.Fatal("probe changed existing media allocation", member)
	}
	cfg.Enabled = true
	member, err = f.repo.S3ConfigureMember(f.ctx, member.ID, member.Revision, cfg, store.NodeAudit{})
	if err != nil || member.Enabled != 1 || member.Writable != 1 {
		t.Fatal("successful handoff could not resume placement", member, err)
	}
	after, err := f.repo.S3IssueReadGrant(f.ctx, media.ID, time.Now().Unix()+store.S3GrantSeconds)
	if err != nil {
		t.Fatal("successful handoff could not resume existing reads", err)
	}
	if !reflect.DeepEqual(after.Proof, original.Proof) || after.Media.ID != original.Media.ID || after.Media.ObjectID != original.Media.ObjectID || after.Media.MemberID != original.Media.MemberID || after.Media.Path != original.Media.Path || after.Media.Bytes != original.Media.Bytes || after.Media.ETag != original.Media.ETag || after.State != "active" {
		t.Fatal("credential handoff changed original provider identity", after, original)
	}
	if _, err = f.pool.ReserveUpload(f.ctx, "music/CredentialHandoff/next.mp3", "s3", 13, 0, store.AdminAudit{}); err != nil {
		t.Fatal("new placement remained unavailable", err)
	}
	member, err = f.repo.S3Member(f.ctx, member.ID)
	if err != nil || member.Used != 7 || member.Reserved != 13 {
		t.Fatal("restored placement altered committed quota", member, err)
	}
}
