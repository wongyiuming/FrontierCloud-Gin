package preprodimport

// Isolated one-object SSH-observed source -> Admin P-256 -> target vault.
// This is deliberately unregistered: caller/admin authorization, remaining
// objects, weak ETags, final source reconciliation, owner publication,
// rollback anchoring and runtime key resolution are not yet complete.
import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"net/http"
	"path"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type legacyCoordinatorResult struct {
	AlreadyStored        bool
	SourceSnapshotDigest string
	RuntimeReady         bool
}

func observeLegacyObject(ctx context.Context, db store.Store, nodeVault *vault.Vault, tree *sealedtree.SQLStore, treeLease *sealedtree.TreeLease, keyVault *sql.DB, keyVaultRoot []byte, envelope store.EncryptedMediaSourceSnapshot, objectProof *store.EncryptedMediaSourceSnapshot, sourceChallenge string, complete completeSnapshot, key keyScope, client *http.Client, cookie, csrf string) (legacyCoordinatorResult, error) {
	var empty legacyCoordinatorResult
	// This experimental path takes tree before ingress. Keep it unavailable
	// until it follows Owner -> ingress -> tree -> SQL; timeouts do not fix it.
	const orderedLockingImplemented = false
	if !orderedLockingImplemented {
		return empty, invalid("legacy coordinator requires ordered locks")
	}
	if ctx == nil || db == nil || nodeVault == nil || tree == nil || treeLease == nil || keyVault == nil || client == nil || treeLease.Check(ctx) != nil {
		return empty, invalid("legacy coordinator input")
	}
	nodes := db.Nodes()
	routing, ok := nodes.(store.PublicRoutingRepository)
	if nodes == nil || !ok {
		return empty, invalid("legacy coordinator routing")
	}
	_, ingress, err := routing.AcquireCurrentIngress(ctx)
	if err != nil || ingress == nil {
		return empty, invalid("legacy coordinator ingress")
	}
	defer ingress.Release()
	identity, err := nodes.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return empty, invalid("legacy coordinator identity")
	}
	pin, err := loadSourceAuthority(ctx, nodes, nodeVault, identity)
	if err != nil || pin.AuthorityKind != "ssh-collector-v1" || pin.TargetNode != identity.ID {
		return empty, invalid("legacy coordinator authority")
	}
	encoded, err := nodeVault.Unseal(identity.PrivateKey)
	if err != nil {
		return empty, invalid("legacy coordinator identity")
	}
	seed, err := protocol.Decode(encoded)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return empty, invalid("legacy coordinator identity")
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer clear(signer)
	if subtle.ConstantTimeCompare(signer.Public().(ed25519.PublicKey), pin.TargetMasterPublic) != 1 {
		return empty, invalid("legacy coordinator target key")
	}
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), pin.TargetX25519) != 1 {
		return empty, invalid("legacy coordinator receiver")
	}
	now := time.Now()
	signed, sourceDigest, err := authenticateCompleteSource(envelope, receiver, pin, sourceChallenge, now, complete)
	if err != nil {
		return empty, err
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil || generation != pin.Generation || key.Snapshot != generation || key.SourceNode != pin.SourceNode || key.SourceKeyID != pin.SourceKeyID || key.TargetNode != identity.ID || !key.valid(now) || key.ExpiresUnix > signed.Snapshot.ExpiresUnix {
		return empty, invalid("legacy coordinator snapshot binding")
	}
	media, etag, err := matchLegacySourceObject(signed.Snapshot, complete.Projection, key)
	if err != nil {
		return empty, err
	}
	proofScope := objectProofScope{TargetOwnerID: key.TargetOwnerID, TargetBlobID: key.TargetBlobID, TargetReadAlias: key.TargetReadAlias, Challenge: key.Challenge}
	weakETag := etag != "\""+media.SHA256+"\""
	if weakETag {
		if objectProof == nil || verifySSHObjectProof(*objectProof, receiver, pin, signed.Snapshot, sourceDigest, media, proofScope, time.Now()) != nil {
			return empty, invalid("legacy weak etag requires SSH byte proof")
		}
	}
	pending, found, err := tree.FindPendingObjectWithLease(ctx, treeLease, media.MediaID)
	if err != nil || !found {
		return empty, invalid("legacy coordinator pending")
	}
	parent, err := tree.ResolveDirectoryForRecoveryWithLease(ctx, treeLease, pending.Entry.ParentID)
	if err != nil || pending.Entry.ObjectID != media.MediaID || pending.Entry.Kind != media.Kind || path.Join(parent, pending.Entry.Name) != media.Path || pending.Placement.ObjectID != media.MediaID || pending.Placement.NativeObjectID != media.ObjectID || pending.Placement.OwnerID != key.TargetOwnerID || pending.Placement.BlobID != key.TargetBlobID || pending.Placement.ReadAlias != key.TargetReadAlias || pending.Placement.Bytes != media.Size || pending.Placement.SHA256 != media.SHA256 || pending.Placement.State != "active" || pending.Placement.ETag != etag || !reflect.DeepEqual(pending.Placement.Encryption, media.Encryption) {
		return empty, invalid("legacy coordinator target intent")
	}
	var placementFact *sourcePlacementFact
	for i := range complete.Facts.Placements {
		if complete.Facts.Placements[i].MediaID == media.MediaID {
			placementFact = &complete.Facts.Placements[i]
			break
		}
	}
	if placementFact == nil || placementFact.ETag != etag || placementFact.State != "active" || pending.Placement.CreatedAt != placementFact.CreatedAt || pending.Placement.UpdatedAt != placementFact.UpdatedAt {
		return empty, invalid("legacy coordinator placement facts")
	}
	resolution, err := sourceLyricResolution(complete, media, sourceDigest, generation)
	if err != nil {
		return empty, err
	}
	if err = reconcileSourceObjectFacts(complete, media, pending.Facts, resolution); err != nil {
		return empty, err
	}
	if err = treeLease.Check(ctx); err != nil {
		return empty, err
	}
	scope := legacyObservationScope{Key: key, Kind: media.Kind, SourceSnapshotDigest: sourceDigest, SourceHostPin: pin.SourceSSHHostKeySHA256, SourceTLSPin: pin.SourceTLSSPKISHA256, TargetSigningKey: append([]byte(nil), pin.TargetMasterPublic...)}
	guard := func(c context.Context) error {
		if c.Err() != nil || treeLease.Check(c) != nil || time.Now().Unix() >= key.ExpiresUnix || time.Now().Unix() >= signed.Snapshot.ExpiresUnix {
			return invalid("legacy coordinator lease")
		}
		if weakETag && (objectProof == nil || verifySSHObjectProof(*objectProof, receiver, pin, signed.Snapshot, sourceDigest, media, proofScope, time.Now()) != nil) {
			return invalid("legacy coordinator SSH proof expired")
		}
		return nil
	}
	checkTarget := func(c context.Context) error {
		if err := guard(c); err != nil {
			return err
		}
		current, e := nodes.ReadIdentity(c)
		if e != nil || current != identity {
			return invalid("legacy coordinator identity changed")
		}
		currentPin, e := loadSourceAuthority(c, nodes, nodeVault, current)
		if e != nil || !reflect.DeepEqual(currentPin, pin) {
			return invalid("legacy coordinator pin changed")
		}
		return nil
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	// Keep the original authenticated collector evidence and full projection
	// encrypted before any key request. This separate commit is recoverable,
	// not atomic with the tree or the subsequent vault-key transaction.
	evidence, err := saveSourceEvidence(ctx, keyVault, keyVaultRoot, receiver, pin, envelope, sourceChallenge, complete, time.Now(), guard)
	if err != nil || evidence.Digest != sourceDigest {
		return empty, invalid("legacy coordinator source evidence")
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	consumed, err := ensureLegacyAuthorizedRequest(ctx, keyVault, keyVaultRoot, scope, time.Now(), guard)
	if err != nil {
		return empty, err
	}
	if consumed {
		// The same transaction already revalidated the exact request and
		// stored signed key evidence. A lost response does not justify
		// contacting the legacy source for the key again.
		if err = checkTarget(ctx); err != nil {
			return empty, err
		}
		if err = ingress.Commit(); err != nil {
			return empty, invalid("legacy coordinator ingress lost")
		}
		return legacyCoordinatorResult{AlreadyStored: true, SourceSnapshotDigest: sourceDigest, RuntimeReady: false}, nil
	}
	old, err := fetchLegacyAdminEnvelope(ctx, client, pin.SourceTLSOrigin, cookie, csrf, pin.SourceTLSSPKISHA256, media.Path, media.MediaID, *media.Encryption)
	if err != nil {
		return empty, err
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	already, err := observeLegacyKeyAndStoreGuarded(ctx, keyVault, keyVaultRoot, scope, old.receiver, old.grant, old.metadata, old.envelope, signer, time.Now(), guard)
	if err != nil {
		return empty, err
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	if err = ingress.Commit(); err != nil {
		return empty, invalid("legacy coordinator ingress lost")
	}
	return legacyCoordinatorResult{AlreadyStored: already, SourceSnapshotDigest: sourceDigest, RuntimeReady: false}, nil
}
