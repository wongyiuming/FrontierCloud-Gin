//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecoveryOpaqueProof has no logical or physical path, key, bearer or raw
// owner-control binding. It is evidence of one physical read, not authorization
// to reopen service, a complete inventory, or a durable cross-node lease.
type RecoveryOpaqueProof struct {
	Version             int    `json:"version"`
	PlacementCommitment string `json:"placement_commitment"`
	ContentSHA256       string `json:"content_sha256"`
	Bytes               int64  `json:"bytes"`
	RegistryVerified    bool   `json:"registry_verified"`
}

type recoveryOwnerMarker interface {
	VerifyOwnerControlBinding(context.Context, string) error
}

// VisitRecoveryOpaqueProof visits one previously authenticated native tree
// placement. The caller must already hold the matching Owner-control lease and,
// when reading a Master tree, its tree lease in the established Owner -> tree
// -> media-volume order. A follower needs the exact authenticated alias binding;
// a Master-local placement must pass nil. The callback must not reenter this
// service. Its result remains provisional until this method returns nil and
// the caller rechecks/retains its Owner and tree authority. This method does not
// create a lock, alter a registry, or use the playback chunk cache.
//
// A revoked follower alias must carry the authenticated tree's exact durable
// revocation operation; a boolean tombstone alone is insufficient.
func (s *Service) VisitRecoveryOpaqueProof(ctx context.Context, owner store.OwnerControlLease, expected sealedtree.RecoveryMediaPlacement, binding *OpaqueOwnerBinding, visit func(RecoveryOpaqueProof) error) error {
	return s.visitRecoveryOpaqueProof(ctx, owner, expected, binding, visit, nil)
}

func (s *Service) visitRecoveryOpaqueProof(ctx context.Context, owner store.OwnerControlLease, expected sealedtree.RecoveryMediaPlacement, binding *OpaqueOwnerBinding, visit func(RecoveryOpaqueProof) error, volumeCheck func() error) error {
	if s == nil || s.root == nil || !recoveryValuePresent(s.nodes) || !recoveryValuePresent(s.repository) || s.identity == nil || ctx == nil || visit == nil || !recoveryValuePresent(owner) ||
		!((expected.Kind == "recording" && operationID.MatchString(expected.ObjectID)) || (expected.Kind != "recording" && ownedObjectID.MatchString(expected.ObjectID))) || !ownedObjectID.MatchString(expected.BlobID) || !ownedObjectID.MatchString(expected.NativeSHA256) ||
		expected.Bytes < 0 || expected.Bytes > 10*store.GiB || (expected.Kind != "audio" && expected.Kind != "video" && expected.Kind != "lyric" && expected.Kind != "recording") ||
		expected.S3CompositeSHA256 != "" || expected.S3ETag != "" || expected.S3VersionID != "" || expected.S3ObjectRevision != 0 {
		return store.ErrNodeState
	}
	if binding != nil {
		copyBinding := *binding
		binding = &copyBinding
	}
	if expected.AliasRevoked != (expected.AliasRevocationOperationID != "") || (expected.AliasRevoked && !operationID.MatchString(expected.AliasRevocationOperationID)) {
		return store.ErrNodeState
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(expected.ReadAlias, expected.BlobID, expected.NativeSHA256, expected.Descriptor, expected.Bytes)
	if err != nil || revision != expected.AliasRevision {
		return store.ErrNodeState
	}
	observer, ok := s.nodes.(recoveryOwnerMarker)
	if !ok || owner.Check(ctx) != nil {
		return store.ErrNodeState
	}
	control, err := owner.Binding(ctx)
	if err != nil || !ownedObjectID.MatchString(control) || observer.VerifyOwnerControlBinding(ctx, control) != nil || owner.Check(ctx) != nil {
		return store.ErrNodeState
	}
	identity, err := s.nodes.ReadIdentity(ctx)
	if err != nil || identity.ID != expected.OwnerID || identity.ID != s.identity.ID || (identity.Role != "Master" && identity.Role != "Follower") {
		return store.ErrNodeState
	}
	var relation store.Relationship
	if identity.Role == "Master" {
		if binding != nil || expected.AliasRevoked {
			return store.ErrNodeState
		}
	} else {
		if binding == nil || !binding.Valid() || binding.OwnerID != expected.OwnerID ||
			binding.Alias != expected.ReadAlias || binding.Blob != expected.BlobID || binding.Digest != expected.NativeSHA256 ||
			binding.Revision != expected.AliasRevision || binding.Descriptor != expected.Descriptor || binding.Size != expected.Bytes {
			return store.ErrNodeState
		}
		relation, err = s.nodes.Relationship(ctx, binding.RelationshipID)
		if err != nil || relation.ID != binding.RelationshipID || relation.PeerID != binding.MasterID || relation.Direction != "upstream" || relation.State != "active" || relation.Protocol != protocol.Version {
			return store.ErrNodeState
		}
	}
	checkOwner := func() error {
		if ctx.Err() != nil || owner.Check(ctx) != nil {
			return store.ErrNodeState
		}
		now, e := owner.Binding(ctx)
		if e != nil || now != control || observer.VerifyOwnerControlBinding(ctx, control) != nil {
			return store.ErrNodeState
		}
		current, e := s.nodes.ReadIdentity(ctx)
		if e != nil || current != identity {
			return store.ErrNodeState
		}
		if binding != nil {
			currentRel, e := s.nodes.Relationship(ctx, binding.RelationshipID)
			if e != nil || !sameRecoveryOwnerRelation(relation, currentRel) {
				return store.ErrNodeState
			}
		}
		return owner.Check(ctx)
	}
	if err = checkOwner(); err != nil {
		return err
	}
	readSlot, err := s.acquirePlainRead(ctx)
	if err != nil {
		return err
	}
	defer readSlot()
	checkVolume := volumeCheck
	if checkVolume == nil {
		release, check, e := s.recoveryOpaqueVolume(ctx)
		if e != nil {
			return e
		}
		defer release()
		checkVolume = check
	}
	check := func() error {
		if ctx.Err() != nil || checkVolume() != nil || checkOwner() != nil {
			return store.ErrNodeState
		}
		return nil
	}
	if err = s.ready(); err != nil || check() != nil {
		return store.ErrNodeState
	}
	if binding != nil && s.checkRecoveryOpaqueBindingLocked(*binding, expected.AliasRevocationOperationID) != nil {
		return store.ErrNodeState
	}
	parent, err := openOpaqueBlobParent(s.root, expected.BlobID)
	if err != nil {
		return store.ErrNodeState
	}
	defer parent.Close()
	name := expected.BlobID + ".blob"
	before, err := parent.Leaf().Lstat(name)
	if err != nil || !before.Mode().IsRegular() || !opaqueSingleLink(before) || before.Size() != expected.Bytes {
		return store.ErrNodeState
	}
	f, err := parent.Leaf().Open(name)
	if err != nil {
		return store.ErrNodeState
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameRecoveryOpaqueFile(before, opened) || check() != nil {
		return store.ErrNodeState
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var count int64
	lastLeaseCheck := time.Now()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(lastLeaseCheck) >= time.Second {
			if owner.Check(ctx) != nil || checkVolume() != nil {
				return store.ErrNodeState
			}
			lastLeaseCheck = time.Now()
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			count += int64(n)
			if count > expected.Bytes {
				return store.ErrNodeState
			}
			_, _ = h.Write(buf[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || n == 0 {
			return store.ErrNodeState
		}
	}
	digest, _ := hex.DecodeString(expected.NativeSHA256)
	if count != expected.Bytes || subtle.ConstantTimeCompare(h.Sum(nil), digest) != 1 {
		return store.ErrNodeState
	}
	verifyFile := func() error {
		after, aerr := f.Stat()
		current, cerr := parent.Leaf().Lstat(name)
		if aerr != nil || cerr != nil || !sameRecoveryOpaqueFile(before, after) || !sameRecoveryOpaqueFile(before, current) || parent.Check() != nil || check() != nil {
			return store.ErrNodeState
		}
		if binding != nil && s.checkRecoveryOpaqueBindingLocked(*binding, expected.AliasRevocationOperationID) != nil {
			return store.ErrNodeState
		}
		return nil
	}
	if err = verifyFile(); err != nil {
		return err
	}
	commitment, err := json.Marshal(struct {
		Domain   string                            `json:"domain"`
		Expected sealedtree.RecoveryMediaPlacement `json:"expected"`
		Control  string                            `json:"control"`
		Owner    string                            `json:"owner"`
		Role     string                            `json:"role"`
		Binding  *OpaqueOwnerBinding               `json:"binding,omitempty"`
	}{"frontiercloud:recovery-opaque-proof:v1", expected, control, identity.ID, identity.Role, binding})
	if err != nil {
		return store.ErrNodeState
	}
	sum := sha256.Sum256(commitment)
	proof := RecoveryOpaqueProof{Version: 1, PlacementCommitment: hex.EncodeToString(sum[:]), ContentSHA256: expected.NativeSHA256, Bytes: count, RegistryVerified: binding != nil}
	if err = visit(proof); err != nil {
		return err
	}
	if s.ready() != nil {
		return store.ErrNodeState
	}
	return verifyFile()
}

// The owner retains the original active record even after revocation. The
// encrypted tombstone adds the irreversible denial and must exactly match the
// authenticated Master operation and both original owner records.
func (s *Service) checkRecoveryOpaqueBindingLocked(binding OpaqueOwnerBinding, revokedOperation string) error {
	if revokedOperation == "" {
		return s.checkOpaqueOwnerBindingLocked(binding)
	}
	if !operationID.MatchString(revokedOperation) || !binding.Valid() || s.opaqueRegistryDir(false) != nil {
		return store.ErrNodeState
	}
	var active, reserved OpaqueOwnerBinding
	var revoked opaqueRevocation
	if s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".active"), &active) != nil || active != binding ||
		s.readOpaqueRecord(opaqueBlobReservation(binding.Blob), &reserved) != nil || reserved != binding ||
		s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".revoked"), &revoked) != nil || revoked.OperationID != revokedOperation || revoked.Binding != binding {
		return store.ErrNodeState
	}
	return nil
}

func recoveryValuePresent(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

func sameRecoveryOwnerRelation(a, b store.Relationship) bool {
	return a.ID == b.ID && a.PeerID == b.PeerID && a.Endpoint == b.Endpoint && a.PublicKey == b.PublicKey && a.Credential == b.Credential &&
		a.Direction == b.Direction && a.Mode == b.Mode && a.State == b.State && a.Protocol == b.Protocol && a.CreatedAt == b.CreatedAt
}

func sameRecoveryOpaqueFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.Mode().IsRegular() || !b.Mode().IsRegular() || !os.SameFile(a, b) ||
		a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Nlink == 1 && y.Nlink == 1 && x.Uid == y.Uid && x.Gid == y.Gid && x.Ctim == y.Ctim
}

// recoveryOpaqueVolume borrows an already initialized file lock read-only.
// Unlike the runtime acquisition path, recovery must not create or chown it.
func (s *Service) recoveryOpaqueVolume(ctx context.Context) (func(), func() error, error) {
	for !s.mutation.TryRLock() {
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
	fail := func(err error) (func(), func() error, error) { s.mutation.RUnlock(); return nil, nil, err }
	rootInfo, err := os.Lstat(s.root.Name())
	openedRoot, rootErr := s.root.Stat(".")
	if err != nil || rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, openedRoot) {
		return fail(store.ErrNodeState)
	}
	info, err := s.root.Lstat(".media-mutation.lock")
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || !opaqueSingleLink(info) {
		return fail(store.ErrNodeState)
	}
	f, err := s.root.Open(".media-mutation.lock")
	if err != nil {
		return fail(store.ErrNodeState)
	}
	opened, err := f.Stat()
	if err != nil || !sameRecoveryOpaqueFile(info, opened) {
		f.Close()
		return fail(store.ErrNodeState)
	}
	release, err := filelease.Acquire(ctx, f, false)
	if err != nil {
		return fail(err)
	}
	check := func() error {
		current, e := s.root.Lstat(".media-mutation.lock")
		actual, x := f.Stat()
		currentRoot, y := os.Lstat(s.root.Name())
		actualRoot, z := s.root.Stat(".")
		if e != nil || x != nil || y != nil || z != nil || !currentRoot.IsDir() || currentRoot.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(rootInfo, currentRoot) || !os.SameFile(rootInfo, actualRoot) || !sameRecoveryOpaqueFile(info, current) || !sameRecoveryOpaqueFile(info, actual) {
			return store.ErrNodeState
		}
		return nil
	}
	if err = check(); err != nil {
		release()
		return fail(err)
	}
	return func() { release(); s.mutation.RUnlock() }, check, nil
}
