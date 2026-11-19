//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type recoveryOwnerFixtureRepo interface {
	ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
	InitializeOwnerControlMarker(context.Context) error
	AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
}

func recoveryProofOwnerFence(t *testing.T, root string, svc *Service, owner recoveryOwnerFixtureRepo) {
	t.Helper()
	ctx := context.Background()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, opaqueRegistryDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rootHandle.Close() })
	fence, err := ownerfence.Create(rootHandle, root, svc.identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = owner.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
}

func recoveryProofPlacement(t *testing.T, root, owner string) (sealedtree.RecoveryMediaPlacement, string) {
	t.Helper()
	blob, alias := strings.Repeat("a", 64), strings.Repeat("b", 64)
	content := []byte("synthetic encrypted blob")
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(full, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	descriptor, err := protocol.IngressMediaDescriptor(int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(alias, blob, digest, descriptor, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return sealedtree.RecoveryMediaPlacement{ObjectID: strings.Repeat("c", 64), Kind: "audio", OwnerID: owner, BlobID: blob, Bytes: int64(len(content)), NativeSHA256: digest, ReadAlias: alias, AliasRevision: revision, Descriptor: descriptor}, full
}

func TestRecoveryOpaqueProofMasterPinsBytesAndLease(t *testing.T) {
	ctx := context.Background()
	root, db, svc := masterFixture(t)
	owner := db.Nodes().(recoveryOwnerFixtureRepo)
	recoveryProofOwnerFence(t, root, svc, owner)
	lease, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	expected, file := recoveryProofPlacement(t, root, svc.identity.ID)
	var got RecoveryOpaqueProof
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, nil, func(proof RecoveryOpaqueProof) error {
		got = proof
		wait, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		unlock, e := svc.acquire(wait, true)
		if e == nil {
			unlock()
			return errors.New("proof allowed a competing volume writer")
		}
		if !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Bytes != expected.Bytes || got.ContentSHA256 != expected.NativeSHA256 || len(got.PlacementCommitment) != 64 || got.RegistryVerified {
		t.Fatal("incorrect proof")
	}
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), root) || strings.Contains(string(raw), expected.BlobID) || strings.Contains(string(raw), expected.ReadAlias) {
		t.Fatal("proof exposes object path or alias")
	}
	wrong := expected
	wrong.NativeSHA256 = strings.Repeat("f", 64)
	wrong.AliasRevision, _ = protocol.OpaquePlacementRevisionFromDescriptor(wrong.ReadAlias, wrong.BlobID, wrong.NativeSHA256, wrong.Descriptor, wrong.Bytes)
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, wrong, nil, func(RecoveryOpaqueProof) error { t.Fatal("corrupt object admitted"); return nil }); err == nil {
		t.Fatal("wrong digest accepted")
	}
	// Altering and restoring bytes/mtime inside the visitor still changes ctime.
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, nil, func(RecoveryOpaqueProof) error {
		content, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		if e = os.WriteFile(file, content, 0600); e != nil {
			return e
		}
		return os.Chtimes(file, info.ModTime(), info.ModTime())
	})
	if err == nil {
		t.Fatal("visitor-time file mutation accepted")
	}
	lock := filepath.Join(root, ".media-mutation.lock")
	if err = os.Rename(lock, lock+"-held"); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, nil, func(RecoveryOpaqueProof) error { t.Fatal("missing volume lock admitted"); return nil }); err == nil {
		t.Fatal("missing volume lock accepted")
	}
	if _, err = os.Lstat(lock); !os.IsNotExist(err) {
		t.Fatal("proof created a missing volume lock", err)
	}
	if err = os.Rename(lock+"-held", lock); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, nil, func(RecoveryOpaqueProof) error {
		lease.Release()
		return nil
	}); err == nil {
		t.Fatal("visitor released owner before final check")
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, nil, func(RecoveryOpaqueProof) error { t.Fatal("released owner admitted"); return nil }); err == nil {
		t.Fatal("released owner lease accepted")
	}
}

func TestRecoveryOpaqueProofFollowerRegistryAndSymlinks(t *testing.T) {
	ctx := context.Background()
	root, db, svc, relationship := ownedFixture(t)
	svc.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	owner := db.Nodes().(recoveryOwnerFixtureRepo)
	recoveryProofOwnerFence(t, root, svc, owner)
	identity, err := db.Nodes().ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, relationship)
	if err != nil {
		t.Fatal(err)
	}
	expected, file := recoveryProofPlacement(t, root, identity.ID)
	binding := OpaqueOwnerBinding{MasterID: relation.PeerID, OwnerID: identity.ID, RelationshipID: relationship, Alias: expected.ReadAlias, Blob: expected.BlobID, Revision: expected.AliasRevision, Digest: expected.NativeSHA256, Descriptor: expected.Descriptor, Size: expected.Bytes}
	if err = svc.RegisterOpaqueOwnerBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	lease, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var proof RecoveryOpaqueProof
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, &binding, func(p RecoveryOpaqueProof) error { proof = p; return nil }); err != nil || !proof.RegistryVerified {
		t.Fatal("valid follower proof", err)
	}
	hidden := expected
	hidden.AliasRevoked = true
	hidden.AliasRevocationOperationID = strings.Repeat("1", 32)
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, hidden, &binding, func(RecoveryOpaqueProof) error { t.Fatal("active alias admitted as revoked"); return nil }); err == nil {
		t.Fatal("absent revocation accepted")
	}
	badActive := expected
	badActive.AliasRevocationOperationID = hidden.AliasRevocationOperationID
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, badActive, &binding, func(RecoveryOpaqueProof) error { t.Fatal("inconsistent active operation admitted"); return nil }); err == nil {
		t.Fatal("operation on active alias accepted")
	}
	reservation := filepath.Join(root, filepath.FromSlash(opaqueBlobReservation(binding.Blob)))
	reservationBytes, err := os.ReadFile(reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(reservation); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, &binding, func(RecoveryOpaqueProof) error { t.Fatal("missing reservation admitted"); return nil }); err == nil {
		t.Fatal("missing reservation accepted")
	}
	if err = os.WriteFile(reservation, reservationBytes, 0600); err != nil {
		t.Fatal(err)
	}
	missing := binding
	missing.RelationshipID = strings.Repeat("0", 32)
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, &missing, func(RecoveryOpaqueProof) error { t.Fatal("wrong binding admitted"); return nil }); err == nil {
		t.Fatal("wrong binding accepted")
	}
	leaf := filepath.Dir(file)
	if err = os.Rename(leaf, leaf+"-held"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(leaf+"-held", leaf); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, &binding, func(RecoveryOpaqueProof) error { t.Fatal("symlink admitted"); return nil }); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Remove(leaf); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(leaf+"-held", leaf); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err = svc.RevokeOpaqueOwnerBinding(ctx, strings.Repeat("1", 32), binding); err != nil {
		t.Fatal(err)
	}
	lease, err = owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	expected.AliasRevoked = true
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, expected, &binding, func(RecoveryOpaqueProof) error { t.Fatal("unbound revocation admitted"); return nil }); err == nil {
		t.Fatal("revoked alias without expected operation accepted")
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, hidden, &binding, func(p RecoveryOpaqueProof) error { proof = p; return nil }); err != nil || !proof.RegistryVerified {
		t.Fatal("authenticated exact revocation refused", err)
	}
	activeRecord := filepath.Join(root, filepath.FromSlash(opaqueRegistryFile(binding.Alias, ".active")))
	if err = os.Rename(activeRecord, activeRecord+"-held"); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, hidden, &binding, func(RecoveryOpaqueProof) error { t.Fatal("missing active binding admitted"); return nil }); err == nil {
		t.Fatal("missing active binding accepted")
	}
	if err = os.Rename(activeRecord+"-held", activeRecord); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(reservation); err != nil {
		t.Fatal(err)
	}
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, hidden, &binding, func(RecoveryOpaqueProof) error { t.Fatal("missing revoked reservation admitted"); return nil }); err == nil {
		t.Fatal("missing revoked reservation accepted")
	}
	if err = os.WriteFile(reservation, reservationBytes, 0600); err != nil {
		t.Fatal(err)
	}
	stale := hidden
	stale.AliasRevocationOperationID = strings.Repeat("2", 32)
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, stale, &binding, func(RecoveryOpaqueProof) error { t.Fatal("stale operation admitted"); return nil }); err == nil {
		t.Fatal("stale revocation accepted")
	}
	active := hidden
	active.AliasRevoked = false
	active.AliasRevocationOperationID = ""
	if err = svc.VisitRecoveryOpaqueProof(ctx, lease, active, &binding, func(RecoveryOpaqueProof) error { t.Fatal("revoked alias admitted as active"); return nil }); err == nil {
		t.Fatal("tombstone ignored for active alias")
	}
}
