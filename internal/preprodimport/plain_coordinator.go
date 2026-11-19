package preprodimport

// This isolated coordinator authenticates a plain media or lyric observation
// against the current target Master and its durable source pin. It does not
// publish an owner blob or make a pending tree object visible. Ingress Commit
// releases the identity fence, so the returned value is a historical observation,
// not a claim that the identity is still current or a reusable publish permit.
// Long evidence validation under tree/ingress fences and the missing owner-first
// fence make this unsuitable for a runtime entry until the protocol is complete.
import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type plainCoordinatorResult struct {
	SourceSnapshotDigest string
	Pending              pendingObservation
}

func observePlainOrLyric(ctx context.Context, db store.Store, nodeVault *vault.Vault, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, evidenceDB *sql.DB, evidenceRoot []byte, sourceEnvelope, objectProof store.EncryptedMediaSourceSnapshot, sourceChallenge string, complete completeSnapshot, objectID string, scope objectProofScope) (plainCoordinatorResult, error) {
	var empty plainCoordinatorResult
	// This experimental path takes tree before ingress. Keep it unavailable
	// until it follows Owner -> ingress -> tree -> SQL; timeouts do not fix it.
	const orderedLockingImplemented = false
	if !orderedLockingImplemented {
		return empty, invalid("plain coordinator requires ordered locks")
	}
	if ctx == nil || db == nil || nodeVault == nil || tree == nil || lease == nil || evidenceDB == nil || lease.Check(ctx) != nil {
		return empty, invalid("plain coordinator input")
	}
	nodes := db.Nodes()
	routing, ok := nodes.(store.PublicRoutingRepository)
	if nodes == nil || !ok {
		return empty, invalid("plain coordinator routing")
	}
	_, ingress, err := routing.AcquireCurrentIngress(ctx)
	if err != nil || ingress == nil {
		return empty, invalid("plain coordinator ingress")
	}
	defer ingress.Release()
	identity, err := nodes.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return empty, invalid("plain coordinator identity")
	}
	pin, err := loadSourceAuthority(ctx, nodes, nodeVault, identity)
	if err != nil || pin.AuthorityKind != "ssh-collector-v1" || pin.TargetNode != identity.ID {
		return empty, invalid("plain coordinator authority")
	}
	encoded, err := nodeVault.Unseal(identity.PrivateKey)
	if err != nil {
		return empty, invalid("plain coordinator identity")
	}
	seed, err := protocol.Decode(encoded)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return empty, invalid("plain coordinator identity")
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil || subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), pin.TargetMasterPublic) != 1 || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), pin.TargetX25519) != 1 {
		return empty, invalid("plain coordinator target pin")
	}
	signed, digest, err := authenticateCompleteSource(sourceEnvelope, receiver, pin, sourceChallenge, time.Now(), complete)
	if err != nil {
		return empty, err
	}
	guard := func(c context.Context) error {
		if c.Err() != nil || lease.Check(c) != nil || time.Now().Unix() >= signed.Snapshot.ExpiresUnix {
			return invalid("plain coordinator lease")
		}
		return nil
	}
	checkTarget := func(c context.Context) error {
		if err := guard(c); err != nil {
			return err
		}
		current, e := nodes.ReadIdentity(c)
		if e != nil || current != identity {
			return invalid("plain coordinator identity changed")
		}
		currentPin, e := loadSourceAuthority(c, nodes, nodeVault, current)
		if e != nil || !reflect.DeepEqual(currentPin, pin) {
			return invalid("plain coordinator pin changed")
		}
		return nil
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	observed, err := reconcilePlainOrLyric(ctx, tree, lease, receiver, pin, sourceEnvelope, objectProof, sourceChallenge, complete, objectID, scope, time.Now())
	if err != nil {
		return empty, err
	}
	ref, err := saveSourceEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEnvelope, sourceChallenge, complete, time.Now(), guard)
	if err != nil || ref.Digest != digest {
		return empty, invalid("plain coordinator evidence")
	}
	if err = checkTarget(ctx); err != nil {
		return empty, err
	}
	again, err := reconcilePlainOrLyric(ctx, tree, lease, receiver, pin, sourceEnvelope, objectProof, sourceChallenge, complete, objectID, scope, time.Now())
	if err != nil || again != observed {
		return empty, invalid("plain coordinator pending changed")
	}
	if err = ingress.Commit(); err != nil {
		return empty, invalid("plain coordinator ingress lost")
	}
	if err = guard(ctx); err != nil {
		return empty, err
	}
	// A commit may take long enough for the independently signed object proof
	// to expire. The result is an observation, and must still be current when
	// returned; it never grants permission to publish the object.
	again, err = reconcilePlainOrLyric(ctx, tree, lease, receiver, pin, sourceEnvelope, objectProof, sourceChallenge, complete, objectID, scope, time.Now())
	if err != nil || again != observed {
		return empty, invalid("plain coordinator proof expired")
	}
	// Read the already-authenticated proof's expiry again after verification;
	// a large source snapshot may have taken substantial time to validate.
	proofRaw, err := snapshotcrypt.OpenObjectProof(objectProof, receiver)
	if err != nil {
		return empty, invalid("plain coordinator proof")
	}
	var signedProof signedSSHObjectProof
	err = json.Unmarshal(proofRaw, &signedProof)
	clear(proofRaw)
	if err != nil || time.Now().Unix() >= signedProof.Proof.ExpiresUnix || guard(ctx) != nil {
		return empty, invalid("plain coordinator proof expired")
	}
	return plainCoordinatorResult{SourceSnapshotDigest: digest, Pending: observed}, nil
}
