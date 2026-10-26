package s3media

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type cleanupRepository struct {
	*serviceRepository
	finished int
	deleted  int
	absence  store.S3AbsenceProof
}

func (r *cleanupRepository) S3RequestAbort(context.Context, string, store.AdminAudit) (store.S3Upload, error) {
	if r.upload.State != "aborted" {
		r.upload.State = "aborting"
	}
	return r.upload, nil
}
func (r *cleanupRepository) S3FinishAbort(_ context.Context, _ string, revision int64, proof store.S3AbsenceProof, _ store.AdminAudit) (store.S3Upload, error) {
	if revision != r.upload.Revision {
		return r.upload, store.ErrNodeState
	}
	r.finished++
	r.absence = proof
	r.upload.State = "aborted"
	return r.upload, nil
}
func (r *cleanupRepository) S3StartDelete(context.Context, string, store.AdminAudit) (store.S3Object, error) {
	r.object.State = "deleting"
	return r.object, nil
}
func (r *cleanupRepository) S3FinishDelete(_ context.Context, _ string, revision int64, proof store.S3AbsenceProof, _ store.AdminAudit) error {
	if revision != r.object.Revision {
		return store.ErrNodeState
	}
	r.deleted++
	r.absence = proof
	return nil
}

type cleanupProvider struct {
	*serviceProvider
	object                         *s3store.Proof
	aborted, deletes, enumerations int
	listing                        s3store.UploadListing
	abortError, deleteError        error
	headGrant                      func(context.Context, string, string, string, time.Duration) (s3store.Grant, error)
	afterAbort                     func() ([]s3store.Part, error)
}

func (p *cleanupProvider) Abort(context.Context, string, string) error {
	p.aborted++
	return p.abortError
}
func (p *cleanupProvider) ListParts(context.Context, string, string) ([]s3store.Part, error) {
	if p.aborted == 0 {
		return nil, ErrProof
	}
	if p.afterAbort != nil {
		return p.afterAbort()
	}
	return nil, s3store.ErrNotFound
}
func (p *cleanupProvider) Head(context.Context, string, string) (s3store.Proof, error) {
	if p.object == nil {
		return s3store.Proof{}, s3store.ErrNotFound
	}
	return *p.object, nil
}
func (p *cleanupProvider) Delete(_ context.Context, _ string, version, etag string) error {
	if p.object == nil || p.object.VersionID != version || p.object.ETag != etag {
		return ErrProof
	}
	p.deletes++
	p.object = nil
	return p.deleteError
}
func (p *cleanupProvider) ListUploads(context.Context, string) (s3store.UploadListing, error) {
	p.enumerations++
	return p.listing, nil
}
func (p *cleanupProvider) PresignHead(ctx context.Context, key, version, etag string, expiry time.Duration) (s3store.Grant, error) {
	return p.headGrant(ctx, key, version, etag, expiry)
}

func cleanupFixture(t *testing.T) (*Service, *cleanupRepository, *cleanupProvider) {
	s, repository, provider, _, _ := serviceFixture(t)
	r := &cleanupRepository{serviceRepository: repository}
	p := &cleanupProvider{serviceProvider: provider}
	s.repository = r
	s.factory = func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) { return p, func() {}, nil }
	return s, r, p
}

func TestCancelNeverRefundsLiveGrantUnknownCreateOrForeignObject(t *testing.T) {
	for _, mode := range []string{"live-grant", "unknown-empty", "unknown-truncated", "unknown-many", "foreign-object", "abort-denied"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p := cleanupFixture(t)
			switch mode {
			case "live-grant":
				r.upload.GrantUntil = time.Now().Unix() + 60
			case "unknown-empty", "unknown-truncated", "unknown-many":
				r.upload.CreateUncertain = true
				r.upload.ProviderUploadID = ""
				r.upload.Reservation.CreatedAt = time.Now().Unix()
				p.listing.Complete = mode != "unknown-truncated"
				if mode == "unknown-many" {
					p.listing.Uploads = []s3store.MultipartUpload{{UploadID: "one", InitiatedAt: time.Now().Unix()}, {UploadID: "two", InitiatedAt: time.Now().Unix()}}
				}
			case "foreign-object":
				proof := completedServiceProof(r.upload)
				proof.Metadata["fc-session"] = "foreign"
				p.object = &proof
			case "abort-denied":
				p.abortError = s3store.ErrDenied
			}
			got, err := s.Cancel(context.Background(), "session1", store.AdminAudit{})
			if err == nil || got.State != "aborting" || r.finished != 0 || p.deletes != 0 {
				t.Fatal("unproven cleanup released reservation", mode, got, err, r.finished, p.deletes)
			}
			if mode == "live-grant" && p.aborted != 0 {
				t.Fatal("live bearer raced physical cleanup")
			}
		})
	}
}

func TestCancelRecoversLostDeleteReplyUsingExactOwnedVersion(t *testing.T) {
	s, r, p := cleanupFixture(t)
	proof := completedServiceProof(r.upload)
	p.object = &proof
	p.deleteError = &s3store.OperationError{Code: s3store.ErrNetwork, Uncertain: true}
	got, err := s.Cancel(context.Background(), "session1", store.AdminAudit{})
	if err != nil || got.State != "aborted" || r.finished != 1 || p.aborted != 1 || p.deletes != 1 {
		t.Fatal("known cleanup failed", got, err)
	}
	if !r.absence.ObjectAbsent || !r.absence.MultipartAbsent || r.absence.VersionID != "version1" || r.absence.ETag != proof.ETag || r.absence.Key != r.upload.Key || r.absence.MemberID != "member1" || r.absence.MediaID != "media1" {
		t.Fatal("refund lost exact identity", r.absence)
	}
}

func TestKnownAbortRequiresAcknowledgementForEmptyPartsProof(t *testing.T) {
	for _, mode := range []string{"acknowledged-empty", "acknowledged-inflight", "uncertain-empty", "denied-empty", "unavailable-list"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p := cleanupFixture(t)
			p.afterAbort = func() ([]s3store.Part, error) {
				if mode == "acknowledged-inflight" {
					return []s3store.Part{{Number: 1}}, nil
				}
				if mode == "unavailable-list" {
					return nil, s3store.ErrNetwork
				}
				return nil, nil
			}
			if mode == "uncertain-empty" {
				p.abortError = &s3store.OperationError{Code: s3store.ErrNetwork, Uncertain: true}
			}
			if mode == "denied-empty" {
				p.abortError = s3store.ErrDenied
			}
			got, err := s.Cancel(context.Background(), "session1", store.AdminAudit{})
			if mode == "acknowledged-empty" {
				if err != nil || got.State != "aborted" || r.finished != 1 || !r.absence.MultipartAbsent {
					t.Fatal("S3 acknowledged abort and empty parts did not settle", got, err)
				}
			} else if err == nil || got.State != "aborting" || r.finished != 0 {
				t.Fatal("ambiguous cleanup refunded quota", mode, got, err)
			}
		})
	}
}

func TestDeleteWaitsForReadAndCannotDeleteDifferentETag(t *testing.T) {
	for _, mode := range []string{"live", "wrong-etag", "ready"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p := cleanupFixture(t)
			r.object.Proof = store.S3ObjectProof{Key: r.upload.Key, SessionID: "session1", ObjectID: "object1", MemberID: "member1", MediaID: "media1", ETag: `"opaque-object"`, VersionID: "version1"}
			r.object.GrantUntil = 0
			proof := completedServiceProof(r.upload)
			p.object = &proof
			if mode == "live" {
				r.object.GrantUntil = time.Now().Unix() + 60
			}
			if mode == "wrong-etag" {
				p.object.ETag = `"replacement"`
			}
			err := s.Delete(context.Background(), "media1", store.AdminAudit{})
			if mode == "ready" {
				if err != nil || r.deleted != 1 || p.deletes != 1 || s.Generation() != 1 {
					t.Fatal("proven delete failed", err, r.deleted)
				}
			} else if err == nil || r.deleted != 0 || p.deletes != 0 || s.Generation() != 0 {
				t.Fatal("unsafe deletion committed", mode, err)
			}
		})
	}
}

func TestSourceRequiresOneDurableGrantBeforeGETAndHEAD(t *testing.T) {
	s, r, p := cleanupFixture(t)
	r.object.Media.ObjectID = "object1"
	r.object.Proof.Bytes = 7
	var get, head bool
	p.read = func(_ context.Context, _ string, _ string, etag, filename string, expiry time.Duration) (s3store.Grant, error) {
		if !r.authorized || etag != `"opaque-object"` || filename != "song.mp3" || expiry%time.Second != 0 {
			t.Fatal("GET escaped grant or identity")
		}
		get = true
		return s3store.Grant{URL: "https://s3.fixture.test/object", Headers: map[string]string{"If-Match": etag}, ExpiresAt: time.Now().Add(expiry).Unix()}, nil
	}
	p.headGrant = func(_ context.Context, _ string, _ string, etag string, expiry time.Duration) (s3store.Grant, error) {
		if !r.authorized || !get || expiry <= 0 || expiry%time.Second != 0 {
			t.Fatal("HEAD escaped durable authorization")
		}
		head = true
		return s3store.Grant{URL: "https://s3.fixture.test/object-head", Headers: map[string]string{"If-Match": etag}, ExpiresAt: time.Now().Add(expiry).Unix()}, nil
	}
	got, err := s.ReadSource(context.Background(), "media1", "song.mp3")
	if err != nil || !get || !head || got.ObjectID != "object1" || got.SizeBytes != 7 || got.GET.Headers["If-Match"] != got.HEAD.Headers["If-Match"] {
		t.Fatal("source lost signed headers", got, err)
	}
	r.issueErr = store.ErrNodeState
	get, head = false, false
	_, err = s.ReadSource(context.Background(), "media1", "song.mp3")
	if !errors.Is(err, store.ErrNodeState) || get || head {
		t.Fatal("rejected source obtained a bearer", err)
	}
}
