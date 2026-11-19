package preprodimport

// This unregistered Master-side admission uses actual node/pool repositories,
// the existing node vault and a separately provisioned sealed source pin. It
// does not send a request, create trust, export production secrets or publish.
import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// authorizeOwnerPublish is disabled: its experimental implementation holds the
// tree before the ingress lease, in the opposite order from selected-upload
// mutations. It must not acquire either lock until it is redesigned and tested
// against the shared Owner -> ingress -> tree -> SQL order.
//
// The retained experiment verifies the independent
// sealed source pin and real paired target owner identities, checks the full
// new signed plan and (for encrypted media) consumed vault request, and signs
// one exact operation. Plaintext content retains its existing semantics.
// Trust provisioning, source snapshot completeness, source-key entropy,
// caller authorization, durable cross-store coordinator, trusted expiry
// renewal and real owner route remain mandatory external gates.
func authorizeOwnerPublish(ctx context.Context, db store.Store, nodeVault *vault.Vault, tree *sealedtree.SQLStore, treeLease *sealedtree.TreeLease, keyVault *sql.DB, keyVaultRoot []byte, s completeSnapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, receipts map[string]signedStageReceipt, mediaID string, scope *keyScope) (signedStagePublishRequest, error) {
	var empty signedStagePublishRequest
	// No configuration or caller-provided callback can enable this path. Do
	// not convert this to a timeout: a timeout would only mask the lock cycle.
	const orderedLockingImplemented = false
	if !orderedLockingImplemented {
		return empty, invalid("owner admission requires ordered lock implementation")
	}
	if ctx == nil || db == nil || nodeVault == nil || tree == nil || treeLease == nil {
		return empty, invalid("owner admission input")
	}
	if err := treeLease.Check(ctx); err != nil {
		return empty, err
	}
	nodes := db.Nodes()
	if nodes == nil {
		return empty, invalid("owner admission repository")
	}
	routing, ok := nodes.(store.PublicRoutingRepository)
	if !ok {
		return empty, invalid("owner admission ingress")
	}
	_, ingressLease, err := routing.AcquireCurrentIngress(ctx)
	if err != nil || ingressLease == nil {
		return empty, invalid("owner admission ingress")
	}
	defer ingressLease.Release()
	identity, err := nodes.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return empty, invalid("owner admission master identity")
	}
	pin, err := loadSourceAuthority(ctx, nodes, nodeVault, identity)
	if err != nil || identity.ID != pin.TargetNode || pin.SourceNode != trust.SourceNode || pin.SourceKeyID != trust.SourceKeyID || pin.TargetNode != trust.TargetNode || pin.Generation != trust.Generation || subtle.ConstantTimeCompare(pin.SourcePublic, trust.SourcePublic) != 1 || subtle.ConstantTimeCompare(pin.TargetX25519, trust.TargetPublic) != 1 {
		return empty, invalid("owner admission source pin")
	}
	encoded, err := nodeVault.Unseal(identity.PrivateKey)
	if err != nil {
		return empty, invalid("owner admission master key")
	}
	seed, err := protocol.Decode(encoded)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return empty, invalid("owner admission master key")
	}
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), pin.TargetX25519) != 1 {
		return empty, invalid("owner admission receiver pin")
	}
	masterKey := ed25519.NewKeyFromSeed(seed)
	defer clear(masterKey)
	masterPublic := masterKey.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(masterPublic, pin.TargetMasterPublic) != 1 {
		return empty, invalid("owner admission master pin")
	}
	pool := db.Pool()
	if pool == nil {
		return empty, invalid("owner admission pool")
	}
	members, err := pool.Members(ctx)
	if err != nil {
		return empty, err
	}
	byID := map[string]store.StorageMember{}
	for _, member := range members {
		if _, exists := byID[member.ID]; exists {
			return empty, invalid("owner admission duplicate member")
		}
		byID[member.ID] = member
	}
	var media Media
	foundMedia := false
	for _, m := range s.Projection.Media {
		if m.MediaID == mediaID {
			media = m
			foundMedia = true
			break
		}
	}
	if !foundMedia {
		return empty, invalid("owner admission media")
	}
	if media.Encryption != nil {
		if scope == nil || scope.MediaID != mediaID {
			return empty, invalid("owner admission key scope")
		}
	} else if scope != nil {
		return empty, invalid("owner admission plaintext scope")
	}
	pins := map[string]ed25519.PublicKey{}
	var selected Mapping
	for _, mapping := range s.Projection.Mappings {
		member, exists := byID[mapping.TargetID]
		if !exists || member.Enabled != 1 {
			return empty, invalid("owner admission member")
		}
		if mapping.Role == "master" {
			if mapping.TargetID != identity.ID || member.Kind != "MasterLocal" || member.RelationshipID != nil {
				return empty, invalid("owner admission local member")
			}
			pins[mapping.Role] = append(ed25519.PublicKey(nil), masterPublic...)
		} else {
			if member.Kind != "Follower" || member.RelationshipID == nil {
				return empty, invalid("owner admission peer member")
			}
			relation, e := nodes.Relationship(ctx, *member.RelationshipID)
			if e != nil || relation.State != "active" || relation.Direction != "downstream" || relation.PeerID != mapping.TargetID {
				return empty, invalid("owner admission peer relationship")
			}
			key, e := protocol.Decode(relation.PublicKey)
			if e != nil || len(key) != ed25519.PublicKeySize {
				return empty, invalid("owner admission peer pin")
			}
			pins[mapping.Role] = ed25519.PublicKey(key)
		}
		if mapping.SourceID == media.SourceID {
			selected = mapping
		}
	}
	if selected.TargetID == "" {
		return empty, invalid("owner admission selected owner")
	}
	if selected.Role != "master" {
		policy, e := routing.NativeTransport(ctx, selected.TargetID)
		wanted := "Direct"
		if selected.Role == "relay" {
			wanted = "Relay"
		}
		if e != nil || policy.State != "applied" || policy.AppliedTransport != wanted {
			return empty, invalid("owner admission transport")
		}
	}
	now := time.Now()
	var obs pendingObservation
	if scope != nil {
		obs, err = reconcilePendingEncryptedMediaAndVault(ctx, tree, treeLease, keyVault, keyVaultRoot, s, trust, plan, batches, locators, stages, challenges, receipts, pins, *scope, now)
		if err == nil && !obs.VaultAuthenticated {
			return empty, invalid("owner admission missing key")
		}
	} else {
		obs, err = reconcilePendingMedia(ctx, tree, treeLease, s, trust, plan, batches, locators, stages, challenges, receipts, pins, mediaID, now)
	}
	if err != nil || obs.RuntimeReady {
		return empty, invalid("owner admission pending")
	}
	var challenge [32]byte
	if _, err = io.ReadFull(rand.Reader, challenge[:]); err != nil {
		return empty, err
	}
	expires := now.Add(3 * time.Minute).Unix()
	if scope != nil && scope.ExpiresUnix < expires {
		expires = scope.ExpiresUnix
	}
	if plan.Body.ExpiresUnix < expires {
		expires = plan.Body.ExpiresUnix
	}
	for _, receipt := range receipts {
		if receipt.Body.ExpiresUnix < expires {
			expires = receipt.Body.ExpiresUnix
		}
	}
	request := stagePublishRequest{Version: 1, MasterID: identity.ID, OwnerID: selected.TargetID, Role: selected.Role, Generation: trust.Generation, PlanDigest: trust.PlanDigest, OperationID: obs.OperationID, StageID: stages[mediaID], BlobID: obs.BlobID, SHA256: media.SHA256, Challenge: hex.EncodeToString(challenge[:]), Size: media.Size, IssuedUnix: now.Unix(), ExpiresUnix: expires}
	signed, err := signSyntheticStagePublishRequest(request, masterKey, time.Now())
	if err != nil {
		return empty, err
	}
	if err = treeLease.Check(ctx); err != nil {
		return empty, err
	}
	if err = ingressLease.Commit(); err != nil {
		return empty, err
	}
	if time.Now().Unix() >= request.ExpiresUnix {
		return empty, invalid("owner admission expired")
	}
	return signed, nil
}
