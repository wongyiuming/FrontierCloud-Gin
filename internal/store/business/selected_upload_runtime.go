package business

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationpaths"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// SelectedUploadRuntimeGate is owned by the trusted startup/recovery
// coordinator, never by an HTTP request. Its lease must exclude maintenance,
// restoration, incomplete historical import and Owner reconciliation until
// Release. It must not hold or reacquire the Owner, ingress or tree locks used
// below; the established order is readiness, then Owner, ingress and tree.
// Check must fail if those proofs cease to hold. No production
// implementation currently grants such a lease.
type SelectedUploadRuntimeGate interface {
	AcquireSelectedUpload(context.Context, *sealedtree.SQLStore) (SelectedUploadRuntimeLease, error)
}
type SelectedUploadRuntimeLease interface {
	Check(context.Context) error
	Release()
}

func selectedNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// SelectedUploadRuntime composes the actual Master transactions. It is not a
// readiness proof: startup must supply the real gate and the exact fenced tree,
// capacity key and vault of this repository. It never creates a tree or key.
type SelectedRelaySender interface {
	ForwardSelectedRelay(context.Context, string, string, io.Reader, int64) (map[string]any, error)
	RecoverSelectedRelay(context.Context, string, string) (map[string]any, error)
	CleanupSelectedRelay(context.Context, string, string) (map[string]any, error)
}

type SelectedLocalOwner interface {
	SelectedLocalFree(context.Context) (int64, error)
	SelectedLocalOperation(context.Context, protocol.SelectedStorageUpload, selectedupload.ReadDeadline, io.ReadCloser, string) (protocol.OpaqueCapacityReceipt, string, error)
}

type SelectedUploadRuntime struct {
	repo        *Repository
	tree        *sealedtree.SQLStore
	key         []byte
	crypto      *mediacrypto.Manager
	vault       *vault.Vault
	gate        SelectedUploadRuntimeGate
	relay       SelectedRelaySender
	local       SelectedLocalOwner
	s3          *SelectedS3Coordinator
	adminOrigin string
}

// ConfigureSelectedS3 is startup-only. A coordinator constructed with a real
// recovery/configuration gate is required; an absent gate leaves S3 closed.
func (s *SelectedUploadRuntime) ConfigureSelectedS3(coordinator *SelectedS3Coordinator) error {
	if s == nil || coordinator == nil || coordinator.upload != s || selectedNil(coordinator.provider) || selectedNil(coordinator.ready) || s.s3 != nil {
		return store.ErrNodeState
	}
	s.s3 = coordinator
	return nil
}

func (s *SelectedUploadRuntime) SelectedS3() *SelectedS3Coordinator {
	if s == nil {
		return nil
	}
	return s.s3
}

func NewSelectedUploadRuntime(repo *Repository, tree *sealedtree.SQLStore, key []byte, crypto *mediacrypto.Manager, nodeVault *vault.Vault, adminOrigin string, gate SelectedUploadRuntimeGate) (*SelectedUploadRuntime, error) {
	if repo == nil || repo.backend != "sqlite" || tree == nil || !validCapacityKey(key) || crypto == nil || nodeVault == nil || !validPublicOrigin(adminOrigin) || selectedNil(gate) {
		return nil, store.ErrNodeState
	}
	return &SelectedUploadRuntime{repo: repo, tree: tree, key: append([]byte(nil), key...), crypto: crypto, vault: nodeVault, gate: gate, adminOrigin: adminOrigin}, nil
}

// ConfigureRelaySender is startup-only, before this runtime serves requests.
// Relay remains unavailable until the paired Owner route is actually installed.
func (s *SelectedUploadRuntime) ConfigureRelaySender(sender SelectedRelaySender) error {
	if s == nil || selectedNil(sender) || !selectedNil(s.relay) {
		return store.ErrNodeState
	}
	s.relay = sender
	return nil
}

// ConfigureLocalOwner is startup-only and must be tied to the actual Master
// volume and Owner fence; absent that binding Local remains unavailable.
func (s *SelectedUploadRuntime) ConfigureLocalOwner(owner SelectedLocalOwner) error {
	if s == nil || selectedNil(owner) || !selectedNil(s.local) {
		return store.ErrNodeState
	}
	s.local = owner
	return nil
}

// Matches prevents the Admin handler from mixing a different tree, crypto
// manager or management origin with the coordinator configured at startup.
func (s *SelectedUploadRuntime) Matches(tree *sealedtree.SQLStore, crypto *mediacrypto.Manager, adminOrigin string) bool {
	return s != nil && s.tree == tree && s.crypto == crypto && s.adminOrigin == adminOrigin && !selectedNil(s.gate)
}

// ReservePreparation runs before a browser receives its encryption key. The
// historical proof is the startup-owned value, never supplied by a request.
func (s *SelectedUploadRuntime) ReservePreparation(ctx context.Context, sessionHash string, meta mediacrypto.Metadata) error {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer lease.Release()
	if err = s.tree.ReserveNewMediaPreparation(ctx, meta, "admin:"+sessionHash); err != nil {
		return err
	}
	return lease.Check(ctx)
}

type SelectedPrepareRequest struct {
	UploadID     string               `json:"upload_id"`
	ParentPath   string               `json:"parent_path"`
	Filename     string               `json:"filename"`
	MemberID     string               `json:"storage_member_id"`
	CipherSHA256 string               `json:"cipher_sha256"`
	Encryption   mediacrypto.Metadata `json:"encryption"`
	Preparation  string               `json:"preparation_token"`
	S3PartSHA256 []string             `json:"s3_part_sha256,omitempty"`
}
type SelectedDirectTicket struct {
	UploadID    string `json:"upload_id"`
	MemberID    string `json:"member_id"`
	Transport   string `json:"transport"`
	URL         string `json:"upload_url"`
	RecoveryURL string `json:"recovery_url,omitempty"`
	Capability  string `json:"capability"`
}
type SelectedRuntimeStatus struct {
	State     string                          `json:"state"`
	Receipt   *protocol.OpaqueCapacityReceipt `json:"receipt,omitempty"`
	Signature string                          `json:"signature,omitempty"`
}

func (s *SelectedUploadRuntime) lease(ctx context.Context, sessionHash string) (SelectedUploadRuntimeLease, error) {
	if s == nil || s.repo == nil || s.tree == nil || selectedNil(s.gate) || ctx == nil || ctx.Err() != nil || !nodeHashPattern.MatchString(sessionHash) {
		return nil, store.ErrNodeState
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, store.ErrNodeState
	}
	l, err := s.gate.AcquireSelectedUpload(ctx, s.tree)
	if err != nil || selectedNil(l) {
		return nil, store.ErrNodeState
	}
	if l.Check(ctx) != nil {
		l.Release()
		return nil, store.ErrNodeState
	}
	return l, nil
}

// SetTrackLyric retains the Owner and ingress writer fences across the tree's
// own fenced SQL transaction, so a new source cannot be issued midway through
// the binding change. The tree resolves both paths inside that transaction.
func (s *SelectedUploadRuntime) SetTrackLyric(ctx context.Context, sessionHash, track, lyric string, audit store.AdminAudit) error {
	return s.withTreeWrite(ctx, sessionHash, func(heldCtx context.Context) error {
		return s.tree.ApplyNativeTrackLyricPath(heldCtx, track, lyric, audit)
	})
}

func (s *SelectedUploadRuntime) PatchLyricTracks(ctx context.Context, sessionHash, lyric string, linked, unlinked []string, audit store.AdminAudit) error {
	return s.withTreeWrite(ctx, sessionHash, func(heldCtx context.Context) error {
		return s.tree.ApplyNativeLyricPathPatch(heldCtx, lyric, linked, unlinked, audit)
	})
}

func (s *SelectedUploadRuntime) AutoLyricTracks(ctx context.Context, sessionHash, trackScope, lyricScope string, audit store.AdminAudit) (result store.AutoLyricResult, err error) {
	err = s.withTreeWrite(ctx, sessionHash, func(heldCtx context.Context) error {
		var err error
		result, err = s.tree.ApplyNativeLyricAuto(heldCtx, trackScope, lyricScope, audit)
		return err
	})
	return result, err
}

func (s *SelectedUploadRuntime) SetPriority(ctx context.Context, sessionHash, path, resourceID string, value int, directory bool) (result store.PlaybackResult, err error) {
	err = s.withTreeWrite(ctx, sessionHash, func(heldCtx context.Context) error {
		var err error
		result, err = s.tree.SetNativePriority(heldCtx, path, resourceID, value, directory)
		return err
	})
	return result, err
}

func (s *SelectedUploadRuntime) withTreeWrite(ctx context.Context, sessionHash string, mutate func(context.Context) error) error {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer lease.Release()
	return s.repo.WithOwnerControlExclusive(ctx, func(heldCtx context.Context) error {
		held, ok := heldCtx.Value(ownerControlContextKey{}).(*ownerControlContext)
		if !ok || held == nil || held.repository != s.repo || !validOwnerControlLease(held.lease) || held.lease.Check(heldCtx) != nil {
			return store.ErrNodeState
		}
		release, err := s.repo.ingressLease(heldCtx, true)
		if err != nil {
			return err
		}
		defer release()
		if lease.Check(heldCtx) != nil || s.repo.checkOwnerControlMarker(heldCtx, s.repo.db, held.lease) != nil {
			return store.ErrNodeState
		}
		return mutate(heldCtx)
	})
}

// WithAdminTreeCatalog lends a bounded authenticated tree snapshot to the Admin
// catalog projection. It cannot authorize reading a blob or expose a key.
func (s *SelectedUploadRuntime) WithAdminTreeCatalog(ctx context.Context, sessionHash string, fn func(*sealedtree.SQLStore, *sealedtree.TreeLease) error) error {
	if fn == nil {
		return store.ErrNodeState
	}
	ready, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer ready.Release()
	fence, err := s.tree.AcquireReadFence(ctx)
	if err != nil {
		return err
	}
	defer fence.Release()
	if err = fn(s.tree, fence); err != nil {
		return err
	}
	return ready.Check(ctx)
}

// ObserveUploadDestination reports the selected owner's current policy without
// issuing a grant, making a reservation or probing a remote endpoint.
func (s *SelectedUploadRuntime) ObserveUploadDestination(ctx context.Context, memberID string) error {
	if s == nil || ctx == nil {
		return store.ErrNodeState
	}
	_, _, _, _, err := s.observeNative(ctx, memberID)
	return err
}

// observeNative is advisory. Reservation and capability issuance recheck every
// selected Owner, relation, receipt, revision and capacity in their own fenced
// transactions; a change after this read causes rejection, never reassignment.
func (s *SelectedUploadRuntime) observeNative(ctx context.Context, memberID string) (int64, string, string, int64, error) {
	if !nodeIDPattern.MatchString(memberID) {
		return 0, "", "", 0, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return 0, "", "", 0, store.ErrNodeState
	}
	if memberID == identity.ID {
		if selectedNil(s.local) {
			return 0, "", "", 0, store.ErrNodeState
		}
		free, e := s.local.SelectedLocalFree(ctx)
		if e != nil || free < 0 {
			return 0, "", "", 0, store.ErrNodeState
		}
		return 1, "Local", "", free, nil
	}
	m, err := scanMember(s.repo.db.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?", memberID))
	if err == nil && m.Kind == "S3" {
		if s.s3 == nil || selectedNil(s.s3.ready) || selectedNil(s.s3.provider) {
			return 0, "", "", 0, store.ErrNodeState
		}
		member, e := s.repo.s3Member(ctx, s.repo.db, memberID, "")
		if e != nil {
			return 0, "", "", 0, store.ErrNodeState
		}
		if _, e = selectedS3MemberBinding(s.key, member, time.Now().Unix()); e != nil {
			return 0, "", "", 0, e
		}
		if s.s3.ready.CheckSelectedS3Member(ctx, s.tree, member) != nil {
			return 0, "", "", 0, store.ErrNodeState
		}
		return member.Revision, "S3", "", 0, nil
	}
	if err != nil || m.Kind != "Follower" || m.RelationshipID == nil {
		return 0, "", "", 0, store.ErrNodeState
	}
	relation, err := s.repo.Relationship(ctx, *m.RelationshipID)
	now := time.Now().Unix()
	if err != nil || relation.PeerID != memberID || relation.Direction != "downstream" || relation.State != "active" || relation.Status != "online" || relation.Protocol != protocol.Version || relation.LastHeartbeat <= 0 || now < relation.LastHeartbeat || now-relation.LastHeartbeat >= 120 {
		return 0, "", "", 0, store.ErrNodeState
	}
	var configured string
	var revision int64
	if s.repo.db.QueryRowContext(ctx, "SELECT configured_transport,revision FROM native_transport_policy WHERE member_id=?", memberID).Scan(&configured, &revision) != nil || (configured != "Direct" && configured != "Relay") || configured == "Relay" && selectedNil(s.relay) || revision < 1 {
		return 0, "", "", 0, store.ErrNodeState
	}
	raw, err := json.Marshal(relation.Summary[nativeTransportReceiptKey])
	var receipt nativeTransportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Transport != configured || receipt.Revision != revision || !validSelectedTransport(configured, receipt.Origin) || configured == "Direct" && relation.Summary["native_resource_origin"] != receipt.Origin {
		return 0, "", "", 0, store.ErrNodeState
	}
	return revision, configured, receipt.Origin, 0, nil
}

func (s *SelectedUploadRuntime) pendingForRetry(ctx context.Context, sessionHash string, request SelectedPrepareRequest, parentID string, parts []string) (sealedtree.SelectedPending, bool, error) {
	var pending sealedtree.SelectedPending
	var found bool
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, _, exists, e := s.repo.selectedIntentAnyTx(c, q, s.key, request.UploadID)
		if e != nil {
			return e
		}
		if !exists {
			return nil
		}
		if selected.State != "pending" || selected.CancelRequested {
			return store.ErrNodeState
		}
		pending, e = m.ReadSelectedFileTx(c, q, selected.Capacity.OperationID)
		if e != nil || verifySelectedPendingBinding(s.key, selected, pending) != nil {
			return store.ErrNodeState
		}
		if pending.ParentID != parentID || pending.Name != request.Filename || pending.Placement.OwnerID != request.MemberID || pending.Admission.AdminBinding != sessionHash || pending.Placement.SHA256 != request.CipherSHA256 || pending.Placement.Encryption == nil || !reflect.DeepEqual(*pending.Placement.Encryption, request.Encryption) || m.CheckSelectedParentPathTx(c, q, parentID, parts) != nil {
			return store.ErrNodeState
		}
		found = true
		return nil
	})
	return pending, found, err
}

// selectedUploadKind validates the supported logical namespace without
// accepting a caller-supplied object kind. Lyrics are Master-owned and their
// local-only placement is checked separately against the observed owner.
func selectedUploadKind(parent, filename string, plainBytes, cipherBytes int64) (string, bool) {
	full := parent + "/" + filename
	if path.Clean(parent) != parent {
		return "", false
	}
	if parent == "lyrics" || strings.HasPrefix(parent, "lyrics/") {
		parts := strings.Split(parent, "/")
		if len(parts) < 1 || len(parts) > 3 || !strings.EqualFold(path.Ext(filename), ".lrc") || full == "lyrics/default.lrc" || plainBytes <= 0 || plainBytes > 2*1024*1024 {
			return "", false
		}
		for _, part := range parts {
			if !migrationpaths.ValidComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
				return "", false
			}
		}
		if !migrationpaths.ValidComponent(filename) || strings.HasPrefix(filename, ".") || strings.Contains(filename, ":") {
			return "", false
		}
		return "lyric", true
	}
	kind := "audio"
	if strings.HasPrefix(full, "vido/") {
		kind = "video"
	}
	if !poolPath(store.LocalMedia{MediaObject: store.MediaObject{Path: full, Kind: kind}, Bytes: cipherBytes}) {
		return "", false
	}
	return kind, true
}

// PrepareAndIssue accepts only a previously authenticated Admin session hash.
// upload_id is a client-stable random ID for resolving uncertain commits; all
// object, operation, blob and alias IDs are generated independently by Master.
func (s *SelectedUploadRuntime) PrepareAndIssue(ctx context.Context, sessionHash string, req SelectedPrepareRequest) (result SelectedDirectTicket, failure error) {
	var zero SelectedDirectTicket
	stage := "readiness"
	defer func() {
		if failure != nil {
			failure = &selectedPrepareFailure{stage: stage, err: failure}
		}
	}()
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return zero, fmt.Errorf("selected readiness: %w", err)
	}
	defer lease.Release()
	stage = "input"
	if !nodeIDPattern.MatchString(req.UploadID) || !nodeIDPattern.MatchString(req.MemberID) || !nodeHashPattern.MatchString(req.CipherSHA256) || req.Encryption.Validate() != nil || req.Preparation == "" || !utf8.ValidString(req.ParentPath) || !utf8.ValidString(req.Filename) || utf8.RuneCountInString(req.Filename) > 255 || len(req.Filename) > 255 || !migrationpaths.ValidComponent(req.Filename) || strings.Contains(req.Filename, ":") {
		return zero, fmt.Errorf("selected input: %w", store.ErrNodeState)
	}
	stage = "path"
	kind, ok := selectedUploadKind(req.ParentPath, req.Filename, req.Encryption.PlaintextSize, req.Encryption.CiphertextSize)
	if !ok {
		return zero, fmt.Errorf("selected path: %w", store.ErrNodeState)
	}
	parts := strings.Split(req.ParentPath, "/")
	for _, part := range parts {
		if !migrationpaths.ValidComponent(part) {
			return zero, store.ErrNodeState
		}
	}
	stage = "prepare_proof"
	if s.crypto.VerifyTransientPreparation("admin:"+sessionHash, req.Preparation, req.Encryption) != nil {
		return zero, fmt.Errorf("selected prepare proof: %w", store.ErrNodeState)
	}
	stage = "policy"
	revision, policy, origin, localFree, err := s.observeNative(ctx, req.MemberID)
	if err != nil {
		return zero, fmt.Errorf("selected policy: %w", err)
	}
	if kind == "lyric" && policy != "Local" {
		return zero, fmt.Errorf("selected lyric owner: %w", store.ErrNodeState)
	}
	if policy == "S3" {
		if _, err = selectedS3Commitment(req.Encryption.CiphertextSize, req.S3PartSHA256); err != nil {
			return zero, store.ErrNodeState
		}
	} else if len(req.S3PartSHA256) != 0 {
		return zero, store.ErrNodeState
	}
	var s3Admission SelectedUploadRuntimeLease
	if policy == "S3" {
		if s.s3 == nil {
			return zero, store.ErrNodeState
		}
		s3Admission, err = s.s3.ready.AcquireSelectedS3Admission(ctx, s.tree, req.UploadID)
		if err != nil || selectedNil(s3Admission) {
			return zero, store.ErrNodeState
		}
		defer s3Admission.Release()
		if s3Admission.Check(ctx) != nil {
			return zero, store.ErrNodeState
		}
		member, e := s.repo.S3Member(ctx, req.MemberID)
		if e != nil || s.s3.ready.CheckSelectedS3Member(ctx, s.tree, member) != nil {
			return zero, store.ErrNodeState
		}
	}
	stage = "directory"
	parentID, err := s.tree.EnsureSelectedDirectories(ctx, req.ParentPath)
	if err != nil {
		return zero, fmt.Errorf("selected directory: %w", err)
	}
	stage = "pending"
	pending, exists, err := s.pendingForRetry(ctx, sessionHash, req, parentID, parts)
	if err != nil {
		return zero, fmt.Errorf("selected pending: %w", err)
	}
	stage = "reservation"
	var entry sealedtree.Entry
	var placement sealedtree.Placement
	var facts sealedtree.Facts
	if exists {
		if pending.Admission.Policy != policy || pending.Admission.Revision != revision || pending.Admission.Origin != origin {
			return zero, store.ErrNodeState
		}
		entry = sealedtree.Entry{ParentID: pending.ParentID, ObjectID: pending.ObjectID, Kind: kind, Name: pending.Name}
		placement = pending.Placement
		facts = sealedtree.Facts{ObjectID: pending.ObjectID, PendingSelectedUpload: &pending.Admission}
		// The transactional retry requires fresh locator placeholders, not caller-
		// controlled physical names; it reloads and authenticates the actual pending.
		placement.BlobID, placement.ReadAlias = "", ""
	} else {
		id, e := sealedtree.NewBlobID()
		if e != nil {
			return zero, e
		}
		entry = sealedtree.Entry{ParentID: parentID, ObjectID: id, Kind: kind, Name: req.Filename}
		placement = sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: req.MemberID, Bytes: req.Encryption.CiphertextSize, SHA256: req.CipherSHA256, State: "active", Encryption: &req.Encryption}
		facts = sealedtree.Facts{ObjectID: id, PendingSelectedUpload: &sealedtree.SelectedUploadFact{UploadID: req.UploadID, AdminBinding: sessionHash, Policy: policy, Revision: revision, Origin: origin}}
	}
	var guards []func(context.Context, queryer, sealedtree.SelectedPending) error
	if policy == "S3" {
		guards = append(guards, func(c context.Context, q queryer, pending sealedtree.SelectedPending) error {
			member, e := s.repo.s3Member(c, q, pending.Placement.OwnerID, s.repo.lock())
			if e != nil || s.s3.ready.CheckSelectedS3Member(c, s.tree, member) != nil {
				return store.ErrNodeState
			}
			return s.s3.checkSelectedS3CurrentOriginTx(c, q, member)
		})
	}
	if _, _, err = s.repo.prepareAuthorizedSelected(ctx, s.tree, s.key, s.crypto, sessionHash, req.Preparation, parts, entry, placement, facts, localFree, req.S3PartSHA256, guards...); err != nil {
		return zero, fmt.Errorf("selected reservation: %w", err)
	}
	stage = "readiness"
	if lease.Check(ctx) != nil {
		return zero, store.ErrNodeState
	}
	if policy == "S3" {
		if s3Admission.Check(ctx) != nil {
			return zero, store.ErrNodeState
		}
		return SelectedDirectTicket{UploadID: req.UploadID, MemberID: req.MemberID, Transport: "S3"}, nil
	}
	check := func(c context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, _ sealedtree.SelectedPending) error {
		return lease.Check(c)
	}
	stage = "scope"
	if _, _, err = s.repo.bindSelectedCapacityScope(ctx, s.tree, s.key, req.UploadID, check); err != nil {
		return zero, fmt.Errorf("selected scope: %w", err)
	}
	stage = "capability"
	ticket, err := s.issueWithLease(ctx, sessionHash, req.UploadID, origin, req.MemberID, lease)
	if err != nil {
		return zero, fmt.Errorf("selected capability: %w", err)
	}
	return ticket, nil
}

func (s *SelectedUploadRuntime) issueWithLease(ctx context.Context, sessionHash, uploadID, origin, memberID string, lease SelectedUploadRuntimeLease) (SelectedDirectTicket, error) {
	var zero SelectedDirectTicket
	if !selectedNil(s.local) {
		claim, err := s.localClaim(ctx, uploadID, lease, false)
		if err == nil {
			if memberID != "" && claim.Owner != memberID {
				return zero, store.ErrNodeState
			}
			base := "/api/v1/media/admin/upload/selected/" + uploadID
			return SelectedDirectTicket{UploadID: uploadID, MemberID: claim.Owner, Transport: "Local", URL: base + "/bytes", RecoveryURL: base + "/recover"}, nil
		}
	}
	var policy string
	check := func(c context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending, _ string) error {
		if origin != "" && p.Admission.Origin != origin || memberID != "" && p.Placement.OwnerID != memberID {
			return store.ErrNodeState
		}
		origin, memberID, policy = p.Admission.Origin, p.Placement.OwnerID, p.Admission.Policy
		return lease.Check(c)
	}
	token, err := s.repo.issueSelectedDirectCapability(ctx, s.tree, s.key, s.vault, uploadID, sessionHash, s.adminOrigin, check)
	if err != nil {
		return zero, err
	}
	if policy == "Relay" && !selectedNil(s.relay) {
		base := "/api/v1/media/admin/upload/selected/" + uploadID
		return SelectedDirectTicket{UploadID: uploadID, MemberID: memberID, Transport: "Relay", URL: base + "/bytes", RecoveryURL: base + "/recover"}, nil
	}
	if policy != "Direct" {
		return zero, store.ErrNodeState
	}
	return SelectedDirectTicket{UploadID: uploadID, MemberID: memberID, Transport: "Direct", URL: origin + "/api/v1/node/selected-upload", RecoveryURL: origin + "/api/v1/node/selected-upload/recover", Capability: token}, nil
}

// Resume reauthenticates a pending operation with the current Admin session.
// It never changes the committed operation, Owner, descriptor or saved bytes.
func (s *SelectedUploadRuntime) Resume(ctx context.Context, sessionHash, uploadID string) (SelectedDirectTicket, error) {
	var zero SelectedDirectTicket
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return zero, err
	}
	defer lease.Release()
	if !nodeIDPattern.MatchString(uploadID) {
		return zero, store.ErrNodeState
	}
	check := func(c context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, _ sealedtree.SelectedPending) error {
		return lease.Check(c)
	}
	if _, _, err = s.repo.bindSelectedCapacityScope(ctx, s.tree, s.key, uploadID, check); err != nil {
		return zero, err
	}
	return s.issueWithLease(ctx, sessionHash, uploadID, "", "", lease)
}

func (s *SelectedUploadRuntime) Status(ctx context.Context, sessionHash, uploadID string) (SelectedRuntimeStatus, error) {
	var zero SelectedRuntimeStatus
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return zero, err
	}
	defer lease.Release()
	result, err := s.repo.selectedStatus(ctx, s.tree, s.key, s.vault, uploadID, lease.Check)
	if err != nil {
		return zero, err
	}
	return SelectedRuntimeStatus{State: result.State, Receipt: result.Receipt, Signature: result.Signature}, nil
}

// Complete persists the authenticated Owner receipt before atomically
// finalizing tree placement and quota. An error is ambiguous: Status by the
// stable upload ID is the only valid way to resolve a lost COMMIT response.
func (s *SelectedUploadRuntime) Complete(ctx context.Context, sessionHash, uploadID string, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	state, err := s.repo.selectedStatus(ctx, s.tree, s.key, s.vault, uploadID, lease.Check)
	if err != nil || state.OperationID != receipt.OperationID || state.State != "pending" && state.State != "completed" {
		return false, store.ErrNodeState
	}
	if state.State == "pending" {
		if err = s.repo.WithOwnerControlExclusive(ctx, func(c context.Context) error {
			if lease.Check(c) != nil {
				return store.ErrNodeState
			}
			_, e := s.repo.RecordOpaquePublishedReceipt(c, s.key, s.vault, receipt, signature)
			return e
		}); err != nil {
			return false, err
		}
	}
	return s.repo.finalizeSelectedSigned(ctx, s.tree, s.key, s.vault, uploadID, receipt, signature, lease.Check)
}

// Transport determines the authenticated durable operation's transport;
// it never trusts a client-supplied selection or changes the owner.
func (s *SelectedUploadRuntime) Transport(ctx context.Context, sessionHash, uploadID string) (string, error) {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return "", err
	}
	defer lease.Release()
	var policy string
	err = s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		v, _, found, e := s.repo.selectedIntentAnyTx(c, q, s.key, uploadID)
		if e != nil || !found || v.State != "pending" || lease.Check(c) != nil {
			return store.ErrNodeState
		}
		policy = v.Policy
		return c.Err()
	})
	return policy, err
}

// localClaim derives an operation only from the authenticated durable Local
// intent. Cancellation is persisted in the same transaction before the Owner
// can clean any bytes; the browser never supplies this claim.
func (s *SelectedUploadRuntime) localClaim(ctx context.Context, uploadID string, lease SelectedUploadRuntimeLease, cleanup bool) (protocol.SelectedStorageUpload, error) {
	var claim protocol.SelectedStorageUpload
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, oldID, found, err := s.repo.selectedIntentAnyTx(c, q, s.key, uploadID)
		if err != nil || !found || selected.State != "pending" || selected.Policy != "Local" || !cleanup && selected.CancelRequested || lease.Check(c) != nil {
			return store.ErrNodeState
		}
		capacity := selected.Capacity.capacity()
		pending, err := m.ReadSelectedFileTx(c, q, capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(s.key, selected, pending) != nil || pending.Placement.Encryption == nil {
			return store.ErrNodeState
		}
		if err = s.repo.selectedFinalizePolicyTx(c, q, s.key, selected); err != nil {
			return err
		}
		scope, found, err := s.repo.selectedScopeTx(c, q, s.key, selected)
		if err != nil || !found || scope.Settled || scope.CleanupSignature != "" || !cleanup && scope.PublishedSignature != "" {
			return store.ErrNodeState
		}
		if cleanup && !selected.CancelRequested {
			selected.CancelRequested = true
			raw, e := json.Marshal(selected)
			if e != nil {
				return e
			}
			defer clear(raw)
			index := opaqueCapacityIndex(s.key, capacity.OperationID)
			id, sealed, e := sealCapacityRecord(s.key, index, raw)
			if e != nil {
				return e
			}
			if _, e = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); e != nil {
				return e
			}
			result, e := q.ExecContext(c, "UPDATE selected_upload_intents SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=? AND state='pending'", id, sealed, index, oldID)
			if e != nil {
				return e
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		}
		claim = protocol.SelectedStorageUpload{Master: capacity.MasterID, Owner: capacity.MemberID, MediaID: pending.Placement.ReadAlias, ObjectID: capacity.BlobID, UploadID: selected.UploadID, OperationID: capacity.OperationID, ContentSHA256: capacity.Digest, Size: capacity.Bytes, Policy: "Local", Revision: 1, Generation: scope.Generation, StageID: scope.StageID, PublishChallenge: scope.PublishChallenge, CleanupChallenge: scope.CleanupChallenge, Encryption: pending.Placement.Encryption}
		return c.Err()
	})
	if err != nil {
		return protocol.SelectedStorageUpload{}, err
	}
	return claim, nil
}

func (s *SelectedUploadRuntime) LocalOperation(ctx context.Context, sessionHash, uploadID string, deadline selectedupload.ReadDeadline, body io.ReadCloser, action string, size int64) (map[string]any, error) {
	if s == nil || selectedNil(s.local) || body == nil || deadline == nil || (action != "upload" && action != "recover" && action != "cleanup") {
		return nil, store.ErrNodeState
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	claim, err := s.localClaim(ctx, uploadID, lease, action == "cleanup")
	if err != nil || action == "upload" && claim.Size != size {
		return nil, store.ErrNodeState
	}
	receipt, signature, err := s.local.SelectedLocalOperation(ctx, claim, deadline, body, action)
	if err != nil {
		return nil, err
	}
	if err = lease.Check(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"receipt": receipt, "signature": signature}, nil
}

// selectedRelayGrant obtains a fresh policy-bound token while authenticating
// the durable pending reservation and its exact relationship in one fenced
// transaction. The token is kept server-side, never returned to the browser.
func (s *SelectedUploadRuntime) selectedRelayGrant(ctx context.Context, sessionHash, uploadID string, lease SelectedUploadRuntimeLease, cleanup bool) (string, string, int64, error) {
	var relation string
	var size int64
	check := func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation, pending sealedtree.SelectedPending, _ string) error {
		if lease.Check(c) != nil || pending.Admission.Policy != "Relay" || pending.Admission.Origin != "" {
			return store.ErrNodeState
		}
		member, err := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+s.repo.lock(), pending.Placement.OwnerID))
		if err != nil || member.Kind != "Follower" || member.RelationshipID == nil {
			return store.ErrNodeState
		}
		relation, size = *member.RelationshipID, pending.Placement.Bytes
		return nil
	}
	var token string
	var err error
	if cleanup {
		token, err = s.repo.beginSelectedCancel(ctx, s.tree, s.key, s.vault, uploadID, sessionHash, s.adminOrigin, check)
	} else {
		token, err = s.repo.issueSelectedDirectCapability(ctx, s.tree, s.key, s.vault, uploadID, sessionHash, s.adminOrigin, check)
	}
	if err != nil || relation == "" || size <= 0 {
		return "", "", 0, store.ErrNodeState
	}
	return token, relation, size, nil
}

// RelayBytes streams a single admitted opaque upload without buffering it on
// the Master. On error the caller must query status/recover, never infer that
// an Owner publication was rolled back. The authenticated lease stays held until
// the network operation has actually returned.
func (s *SelectedUploadRuntime) RelayBytes(ctx context.Context, sessionHash, uploadID string, body io.Reader, size int64) (map[string]any, error) {
	if s == nil || selectedNil(s.relay) || body == nil || size <= 0 {
		return nil, store.ErrNodeState
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	token, relation, expected, err := s.selectedRelayGrant(ctx, sessionHash, uploadID, lease, false)
	if err != nil || expected != size {
		return nil, store.ErrNodeState
	}
	result, err := s.relay.ForwardSelectedRelay(ctx, relation, token, body, size)
	if err != nil {
		return nil, err
	}
	if err = lease.Check(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *SelectedUploadRuntime) RelayRecover(ctx context.Context, sessionHash, uploadID string) (map[string]any, error) {
	if s == nil || selectedNil(s.relay) {
		return nil, store.ErrNodeState
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	token, relation, _, err := s.selectedRelayGrant(ctx, sessionHash, uploadID, lease, false)
	if err != nil {
		return nil, err
	}
	result, err := s.relay.RecoverSelectedRelay(ctx, relation, token)
	if err != nil {
		return nil, err
	}
	if err = lease.Check(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *SelectedUploadRuntime) RelayCleanup(ctx context.Context, sessionHash, uploadID string) (map[string]any, error) {
	if s == nil || selectedNil(s.relay) {
		return nil, store.ErrNodeState
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	token, relation, _, err := s.selectedRelayGrant(ctx, sessionHash, uploadID, lease, true)
	if err != nil {
		return nil, err
	}
	result, err := s.relay.CleanupSelectedRelay(ctx, relation, token)
	if err != nil {
		return nil, err
	}
	if err = lease.Check(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// BeginCancel first durably fences Master completion. Its cleanup capability
// may be sent only to the original Owner; failures retain data for recovery.
func (s *SelectedUploadRuntime) BeginCancel(ctx context.Context, sessionHash, uploadID string) (SelectedDirectTicket, error) {
	var zero SelectedDirectTicket
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return zero, err
	}
	defer lease.Release()
	state, err := s.repo.selectedStatus(ctx, s.tree, s.key, s.vault, uploadID, lease.Check)
	if err != nil || state.State != "pending" && state.State != "cancelling" {
		return zero, store.ErrNodeState
	}
	if state.State == "pending" {
		bindCheck := func(c context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, _ sealedtree.SelectedPending) error {
			return lease.Check(c)
		}
		if _, _, err = s.repo.bindSelectedCapacityScope(ctx, s.tree, s.key, uploadID, bindCheck); err != nil {
			return zero, err
		}
	}
	if !selectedNil(s.local) {
		claim, e := s.localClaim(ctx, uploadID, lease, true)
		if e == nil {
			return SelectedDirectTicket{UploadID: uploadID, MemberID: claim.Owner, Transport: "Local", URL: "/api/v1/media/admin/upload/selected/" + uploadID + "/cleanup"}, nil
		}
	}
	var origin, memberID, policy string
	check := func(c context.Context, _ queryer, _ *sealedtree.CoordinatedMutation, p sealedtree.SelectedPending, _ string) error {
		origin, memberID, policy = p.Admission.Origin, p.Placement.OwnerID, p.Admission.Policy
		return lease.Check(c)
	}
	token, err := s.repo.beginSelectedCancel(ctx, s.tree, s.key, s.vault, uploadID, sessionHash, s.adminOrigin, check)
	if err != nil {
		return zero, err
	}
	if policy == "Relay" && !selectedNil(s.relay) {
		return SelectedDirectTicket{UploadID: uploadID, MemberID: memberID, Transport: "Relay", URL: "/api/v1/media/admin/upload/selected/" + uploadID + "/cleanup"}, nil
	}
	if policy != "Direct" {
		return zero, store.ErrNodeState
	}
	return SelectedDirectTicket{UploadID: uploadID, MemberID: memberID, Transport: "Direct", URL: origin + "/api/v1/node/selected-upload/cleanup", Capability: token}, nil
}

func (s *SelectedUploadRuntime) FinishCancel(ctx context.Context, sessionHash, uploadID string, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	state, err := s.repo.selectedStatus(ctx, s.tree, s.key, s.vault, uploadID, lease.Check)
	if err != nil || state.OperationID != receipt.OperationID || state.State != "cancelling" && state.State != "cancelled" {
		return false, store.ErrNodeState
	}
	if state.State == "cancelling" {
		if err = s.repo.WithOwnerControlExclusive(ctx, func(c context.Context) error {
			if lease.Check(c) != nil {
				return store.ErrNodeState
			}
			_, e := s.repo.RecordOpaqueCleanedReceipt(c, s.key, s.vault, receipt, signature)
			return e
		}); err != nil {
			return false, err
		}
	}
	return s.repo.finishSelectedCancel(ctx, s.tree, s.key, uploadID, receipt, signature, lease.Check, s.vault)
}
