package s3media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Embedding the repository contracts deliberately leaves unrelated methods
// unimplemented: a test panics if this narrow service path acquires authority
// or touches persistence outside its specified journal operation.
type serviceRepository struct {
	store.S3Repository
	member                                    store.S3Member
	upload                                    store.S3Upload
	object                                    store.S3Object
	issueErr, startErr                        error
	authorized, completeStarted, probeStarted bool
	part                                      store.S3Part
	confirmed                                 store.S3Part
	finalProof                                store.S3ObjectProof
	finalized                                 int
	createStarts, createFinishes              int
	createFinishContextErr                    error
	createOutcome, createCode                 string
	probeResult                               store.S3ProbeResult
	probeCheckpoints                          []string
	checkpointError                           error
}

func (r *serviceRepository) S3Member(context.Context, string) (store.S3Member, error) {
	return r.member, nil
}
func (r *serviceRepository) S3Upload(context.Context, string) (store.S3Upload, error) {
	return r.upload, nil
}
func (r *serviceRepository) S3IssuePart(context.Context, string, int, string, int64) (store.S3Part, error) {
	if r.issueErr != nil {
		return store.S3Part{}, r.issueErr
	}
	r.authorized = true
	return r.part, nil
}
func (r *serviceRepository) S3IssueReadGrant(context.Context, string, int64) (store.S3Object, error) {
	if r.issueErr != nil {
		return store.S3Object{}, r.issueErr
	}
	r.authorized = true
	return r.object, nil
}
func (r *serviceRepository) S3StartCreate(context.Context, string, int64) (store.S3Upload, error) {
	if r.startErr != nil {
		return r.upload, r.startErr
	}
	if r.upload.State != "reserved" {
		return r.upload, store.ErrNodeState
	}
	r.createStarts++
	r.upload.Revision++
	r.upload.State = "creating"
	return r.upload, nil
}
func (r *serviceRepository) S3FinishCreate(ctx context.Context, _ string, revision int64, id, outcome, code string) (store.S3Upload, error) {
	r.createFinishContextErr = ctx.Err()
	r.createFinishes++
	r.createOutcome, r.createCode = outcome, code
	if revision != r.upload.Revision {
		return r.upload, store.ErrNodeState
	}
	r.upload.ProviderUploadID = id
	r.upload.State = outcome
	r.upload.CreateUncertain = outcome == "unknown"
	r.upload.Revision++
	return r.upload, nil
}
func (r *serviceRepository) S3StartComplete(context.Context, string, int64) (store.S3Upload, error) {
	if r.startErr != nil {
		return r.upload, r.startErr
	}
	r.completeStarted = true
	r.upload.Revision++
	r.upload.State = "completing"
	return r.upload, nil
}
func (r *serviceRepository) S3FinalizeUpload(_ context.Context, _ string, revision int64, proof store.S3ObjectProof, _ store.AdminAudit) (store.GlobalMedia, error) {
	if revision != r.upload.Revision {
		return store.GlobalMedia{}, store.ErrNodeState
	}
	r.finalized++
	r.finalProof = proof
	return r.object.Media, nil
}
func (r *serviceRepository) S3ConfirmPart(_ context.Context, _ string, part store.S3Part) (store.S3Upload, error) {
	r.confirmed = part
	return r.upload, nil
}
func (r *serviceRepository) S3StartProbe(context.Context, string, int64, store.NodeAudit) (store.S3Probe, error) {
	r.probeStarted = true
	return store.S3Probe{ID: "probe1", Revision: 7, Key: "probes/member1/probe1"}, nil
}
func (r *serviceRepository) S3CheckpointProbe(_ context.Context, id string, revision int64, providerID string) error {
	if r.checkpointError != nil {
		return r.checkpointError
	}
	if id != "probe1" || revision != 7 || !r.probeStarted || providerID == "" {
		return ErrProof
	}
	r.probeCheckpoints = append(r.probeCheckpoints, providerID)
	return nil
}
func (r *serviceRepository) S3FinishProbe(_ context.Context, _ string, _ int64, result store.S3ProbeResult, _ store.NodeAudit) (store.S3Member, error) {
	r.probeResult = result
	return r.member, nil
}

type serviceNodes struct {
	store.NodeRepository
	role string
}

func (n *serviceNodes) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	return store.NodeIdentity{ID: "master1", Role: n.role}, nil
}

type serviceProvider struct {
	s3store.Provider
	create   func(context.Context, string, map[string]string) (string, error)
	part     func(context.Context, string, string, int32, int64, string, time.Duration) (s3store.Grant, error)
	list     func(context.Context, string, string) ([]s3store.Part, error)
	head     func(context.Context, string, string) (s3store.Proof, error)
	complete func(context.Context, string, string, []s3store.Part) (s3store.Proof, error)
	read     func(context.Context, string, string, string, string, time.Duration) (s3store.Grant, error)
	probe    func(context.Context, string, string) (s3store.TestReport, error)
	journal  func(context.Context, string, string, func(string) error) (s3store.TestReport, error)
}

func (p *serviceProvider) CreateMultipart(ctx context.Context, k string, m map[string]string) (string, error) {
	return p.create(ctx, k, m)
}
func (p *serviceProvider) PresignPart(ctx context.Context, k, u string, n int32, b int64, h string, d time.Duration) (s3store.Grant, error) {
	return p.part(ctx, k, u, n, b, h, d)
}
func (p *serviceProvider) ListParts(ctx context.Context, k, u string) ([]s3store.Part, error) {
	return p.list(ctx, k, u)
}
func (p *serviceProvider) Head(ctx context.Context, k, v string) (s3store.Proof, error) {
	return p.head(ctx, k, v)
}
func (p *serviceProvider) Complete(ctx context.Context, k, u string, parts []s3store.Part) (s3store.Proof, error) {
	return p.complete(ctx, k, u, parts)
}
func (p *serviceProvider) PresignGet(ctx context.Context, k, v, e, f string, d time.Duration) (s3store.Grant, error) {
	return p.read(ctx, k, v, e, f, d)
}
func (p *serviceProvider) TestKey(ctx context.Context, o, k string) (s3store.TestReport, error) {
	return p.probe(ctx, o, k)
}
func (p *serviceProvider) TestKeyWithCheckpoint(ctx context.Context, o, k string, checkpoint func(string) error) (s3store.TestReport, error) {
	if p.journal != nil {
		return p.journal(ctx, o, k, checkpoint)
	}
	report, err := p.probe(ctx, o, k)
	if report.UploadID != "" {
		if checkpointErr := checkpoint(report.UploadID); checkpointErr != nil {
			return report, checkpointErr
		}
	}
	return report, err
}

func serviceFixture(t *testing.T) (*Service, *serviceRepository, *serviceProvider, *serviceNodes, s3store.Credentials) {
	t.Helper()
	private, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	credentials := s3store.Credentials{AccessKey: "EXAMPLEACCESSKEY", SecretKey: "test-only-service-credential"}
	raw, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := private.Seal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	r := &serviceRepository{member: store.S3Member{StorageMember: store.StorageMember{ID: "member1", Kind: "S3"}, Revision: 1, CredentialRevision: 3, SealedCredentials: sealed,
		Location: store.S3Location{Endpoint: "https://s3.fixture.test", Bucket: "frontiercloud-media", Region: "us-east-1", Prefix: "managed", Style: "path"}}}
	r.upload = store.S3Upload{Reservation: store.UploadReservation{ID: "session1", MemberID: "member1", MediaID: "media1", Path: "music/artist/song.mp3", ExpectedBytes: 7}, Key: "objects/immutable1", ObjectID: "object1", ProviderUploadID: "provider-upload1", State: "created", Revision: 5, CredentialRevision: 3,
		Parts: []store.S3Part{{Number: 1, Bytes: 7, SHA256: checksum, ETag: `"opaque-part"`, Confirmed: true}}}
	r.part = r.upload.Parts[0]
	r.part.GrantUntil = time.Now().Unix() + 300
	r.object = store.S3Object{Media: store.GlobalMedia{ID: "media1", MemberID: "member1", Path: "music/artist/song.mp3"}, Proof: store.S3ObjectProof{Key: r.upload.Key, VersionID: "version1", ETag: `"opaque-object"`}, GrantUntil: time.Now().Unix() + 300}
	p := &serviceProvider{}
	n := &serviceNodes{role: "Master"}
	s := newService(r, n, private, func(s3store.Config, s3store.Credentials) (s3store.Provider, func(), error) { return p, func() {}, nil })
	return s, r, p, n, credentials
}

func completedServiceProof(upload store.S3Upload) s3store.Proof {
	decoded, _ := base64.StdEncoding.DecodeString(upload.Parts[0].SHA256)
	sum := sha256.Sum256(decoded)
	return s3store.Proof{Size: 7, ETag: `"opaque-object"`, VersionID: "version1", ChecksumSHA256: base64.StdEncoding.EncodeToString(sum[:]) + "-1", ChecksumType: "COMPOSITE",
		Metadata: map[string]string{"fc-session": "session1", "fc-object": "object1", "fc-member": "member1", "fc-media": "media1"}}
}

func TestServiceDurableGrantAuthorizationPrecedesSigning(t *testing.T) {
	for _, kind := range []string{"part", "read"} {
		for _, denied := range []bool{false, true} {
			t.Run(kind+map[bool]string{true: "/denied", false: "/allowed"}[denied], func(t *testing.T) {
				s, r, p, _, credentials := serviceFixture(t)
				calls := 0
				if denied {
					r.issueErr = store.ErrNodeState
				}
				grant := s3store.Grant{URL: "https://provider.fixture.test/signed", Headers: map[string]string{"If-Match": `"opaque-object"`}, ExpiresAt: time.Now().Unix() + 299}
				check := func(duration time.Duration) error {
					calls++
					if !r.authorized {
						t.Fatal("bearer was signed before durable authorization")
					}
					_, err := credentials.GrantDuration(time.Now(), duration)
					return err
				}
				p.part = func(_ context.Context, key, id string, n int32, size int64, checksum string, duration time.Duration) (s3store.Grant, error) {
					if key != r.upload.Key || id != r.upload.ProviderUploadID || n != 1 || size != 7 || checksum != r.part.SHA256 {
						t.Fatal("upload grant escaped durable object identity")
					}
					if err := check(duration); err != nil {
						return s3store.Grant{}, err
					}
					return grant, nil
				}
				p.read = func(_ context.Context, key, version, etag, filename string, duration time.Duration) (s3store.Grant, error) {
					if key != r.object.Proof.Key || version != "version1" || etag != `"opaque-object"` || filename != "song.mp3" {
						t.Fatal("read grant escaped owned key/version/ETag")
					}
					if err := check(duration); err != nil {
						return s3store.Grant{}, err
					}
					return grant, nil
				}
				var result s3store.Grant
				var err error
				if kind == "part" {
					result, err = s.PartGrant(context.Background(), "session1", 1, 7, r.part.SHA256)
				} else {
					result, err = s.ReadGrant(context.Background(), "media1", "song.mp3")
				}
				if denied {
					if !errors.Is(err, store.ErrNodeState) || calls != 0 {
						t.Fatal("denied journal produced a bearer", err, calls)
					}
				} else {
					if err != nil || calls != 1 || result.Headers["If-Match"] != grant.Headers["If-Match"] {
						t.Fatal("signed headers/duration were lost at service boundary", err, calls)
					}
				}
			})
		}
	}
}

func TestServiceNonMasterCannotIssueS3Authority(t *testing.T) {
	s, _, p, n, _ := serviceFixture(t)
	n.role = "Storage"
	p.part = func(context.Context, string, string, int32, int64, string, time.Duration) (s3store.Grant, error) {
		t.Fatal("non-Master reached signing")
		return s3store.Grant{}, nil
	}
	if _, err := s.PartGrant(context.Background(), "session1", 1, 7, "checksum"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("storage node acquired S3 control authority", err)
	}
}

func TestUnknownCreateIsJournaledAfterCancellationAndNeverRepeated(t *testing.T) {
	s, r, p, _, _ := serviceFixture(t)
	r.upload.State = "reserved"
	r.upload.ProviderUploadID = ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	p.create = func(_ context.Context, key string, meta map[string]string) (string, error) {
		calls++
		if r.createStarts != 1 || r.upload.State != "creating" || key != r.upload.Key || meta["fc-session"] != "session1" {
			t.Fatal("Create preceded durable intent")
		}
		cancel()
		return "", &s3store.OperationError{Code: s3store.ErrNetwork, Uncertain: true}
	}
	upload, err := s.Begin(ctx, "session1")
	if !s3store.IsUncertain(err) || upload.State != "unknown" || !upload.CreateUncertain || r.createOutcome != "unknown" || r.createCode != s3store.ErrNetwork.Error() || r.createFinishContextErr != nil || r.createFinishes != 1 {
		t.Fatal("unknown mutation was canceled out of the durable journal", err)
	}
	if _, err = s.Begin(context.Background(), "session1"); !errors.Is(err, store.ErrNodeState) || calls != 1 {
		t.Fatal("uncertain Create was replayed", err, calls)
	}
}

func TestCompleteRecoversLostReplyOnlyWithExactOwnedCompositeProof(t *testing.T) {
	for _, mode := range []string{"valid", "foreign-metadata", "extra-metadata", "full-checksum", "wrong-size", "unconfirmed"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p, _, _ := serviceFixture(t)
			proof := completedServiceProof(r.upload)
			switch mode {
			case "foreign-metadata":
				proof.Metadata["fc-session"] = "foreign"
			case "extra-metadata":
				proof.Metadata["other"] = "unexpected"
			case "full-checksum":
				proof.ChecksumSHA256 = r.upload.Parts[0].SHA256
			case "wrong-size":
				proof.Size = 8
			case "unconfirmed":
				r.upload.Parts[0].Confirmed = false
			}
			p.head = func(_ context.Context, key, version string) (s3store.Proof, error) {
				if !r.completeStarted || key != r.upload.Key || version != "" {
					t.Fatal("HEAD escaped completion journal/key")
				}
				return proof, nil
			}
			p.complete = func(context.Context, string, string, []s3store.Part) (s3store.Proof, error) {
				t.Fatal("lost response was retried despite an existing object")
				return s3store.Proof{}, nil
			}
			_, err := s.Complete(context.Background(), "session1", store.AdminAudit{})
			if mode == "valid" {
				if err != nil || r.finalized != 1 || r.finalProof.MemberID != "member1" || r.finalProof.MediaID != "media1" || r.finalProof.Key != r.upload.Key || r.finalProof.VersionID != "version1" {
					t.Fatal("valid exact proof lost publication identity", err)
				}
			} else if !errors.Is(err, ErrProof) || r.finalized != 0 {
				t.Fatal("foreign/incomplete/full-hash material reached publication", err)
			}
		})
	}
}

func TestCompleteComparesEveryProviderPartBeforeMutation(t *testing.T) {
	for _, mode := range []string{"valid", "etag", "sha256", "size", "number", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p, _, _ := serviceFixture(t)
			expected := r.upload.Parts[0]
			actual := s3store.Part{Number: 1, Size: expected.Bytes, SHA256: expected.SHA256, ETag: expected.ETag}
			calls := 0
			switch mode {
			case "etag":
				actual.ETag = `"different"`
			case "sha256":
				actual.SHA256 = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "size":
				actual.Size++
			case "number":
				actual.Number++
			}
			p.head = func(context.Context, string, string) (s3store.Proof, error) {
				return s3store.Proof{}, s3store.ErrNotFound
			}
			p.list = func(context.Context, string, string) ([]s3store.Part, error) {
				if mode == "missing" {
					return nil, nil
				}
				return []s3store.Part{actual}, nil
			}
			p.complete = func(context.Context, string, string, []s3store.Part) (s3store.Proof, error) {
				calls++
				return completedServiceProof(r.upload), nil
			}
			_, err := s.Complete(context.Background(), "session1", store.AdminAudit{})
			if mode == "valid" {
				if err != nil || calls != 1 || r.finalized != 1 {
					t.Fatal("valid completion refused", err)
				}
			} else if err == nil || calls != 0 || r.finalized != 0 {
				t.Fatal("unproved provider part reached Complete", err, calls)
			}
		})
	}
}

func TestProbeRecordsIntentBeforeNetworkAndPersistsNoMutationFact(t *testing.T) {
	for _, mode := range []string{"success", "precondition", "missing-head", "foreign-key", "long-etag"} {
		t.Run(mode, func(t *testing.T) {
			s, r, p, _, _ := serviceFixture(t)
			p.probe = func(_ context.Context, _ string, key string) (s3store.TestReport, error) {
				if !r.probeStarted || key != "probes/member1/probe1" {
					t.Fatal("probe mutated before planned key journal")
				}
				report := s3store.TestReport{ProbeKey: key, UploadID: "probe-provider1", Read: true, Head: true, Write: true, Delete: true, Multipart: true, Range: true, CORS: true, Cleanup: true}
				switch mode {
				case "precondition":
					report = s3store.TestReport{ProbeKey: key, NoMutation: true}
					return report, s3store.ErrConfig
				case "missing-head":
					report.Head = false
				case "foreign-key":
					report.ProbeKey = "probes/foreign"
				case "long-etag":
					report.ETag = `"` + string(bytes.Repeat([]byte{'x'}, 180)) + `"`
				}
				return report, nil
			}
			_, err := s.Probe(context.Background(), "member1", 1, "https://browser.fixture.test", store.NodeAudit{})
			switch mode {
			case "success":
				if err != nil || !r.probeResult.ChecksPassed || !r.probeResult.CleanupSettled {
					t.Fatal("complete capability proof refused", err)
				}
			case "precondition":
				if !errors.Is(err, s3store.ErrConfig) || !r.probeResult.NoMutation || !r.probeResult.CleanupSettled || r.probeResult.ChecksPassed {
					t.Fatal("known precondition lost NoMutation fact", err)
				}
			case "long-etag":
				if !errors.Is(err, ErrProof) || r.probeResult.ChecksPassed || !r.probeResult.CleanupSettled || len(r.probeResult.ETag) <= publishedETagBytes {
					t.Fatal("unsupported ETag either enabled admission or lost cleanup proof", err)
				}
			default:
				if err == nil || r.probeResult.ChecksPassed {
					t.Fatal("incomplete/foreign probe authorized a member", err)
				}
			}
		})
	}
}

func TestProbeCheckpointCommitsBeforeProviderContinuation(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "denied"}[denied], func(t *testing.T) {
			s, r, p, _, _ := serviceFixture(t)
			if denied {
				r.checkpointError = store.ErrNodeState
			}
			continued := false
			p.journal = func(_ context.Context, _ string, key string, checkpoint func(string) error) (s3store.TestReport, error) {
				report := s3store.TestReport{ProbeKey: key, UploadID: "durable-upload", Cleanup: true}
				if err := checkpoint(report.UploadID); err != nil {
					return report, err
				}
				if len(r.probeCheckpoints) != 1 || r.probeCheckpoints[0] != report.UploadID {
					t.Fatal("provider continued without durable upload identity")
				}
				continued = true
				report.Read, report.Head, report.Write, report.Delete, report.Multipart, report.Range, report.CORS = true, true, true, true, true, true, true
				return report, nil
			}
			_, err := s.Probe(context.Background(), "member1", 1, "https://browser.fixture.test", store.NodeAudit{})
			if denied {
				if !errors.Is(err, store.ErrNodeState) || continued || r.probeResult.ChecksPassed || !r.probeResult.CleanupSettled {
					t.Fatal("rejected checkpoint granted upload authority or lost cleanup", err)
				}
			} else if err != nil || !continued || !r.probeResult.ChecksPassed {
				t.Fatal("valid durable checkpoint could not continue", err)
			}
		})
	}
}
