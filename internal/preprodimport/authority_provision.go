package preprodimport

// This unregistered seam receives an independently authenticated source pin.
// It never derives trust from a plan and does not enable export or publication.
import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// The store method obtains the exclusive ingress lock itself, so the caller
// must not hold a shared ingress lease while invoking this function.
func provisionSourceAuthority(ctx context.Context, db store.Store, v *vault.Vault, pin sourceAuthorityPin) error {
	if ctx == nil || db == nil || v == nil || !validSourceAuthority(pin) || pin.AuthorityKind == "ssh-collector-v1" && (pin.ImportScope == nil || !sourceScopeMatches(pin.ImportScope, Snapshot{Mappings: pin.ImportScope.Mappings, ExcludedSourceIDs: []string{pin.ImportScope.ExcludedTencentSourceID}})) {
		return invalid("source authority provisioning input")
	}
	nodes := db.Nodes()
	repo, ok := nodes.(sourcePinRepository)
	if nodes == nil || !ok {
		return invalid("source authority provisioning repository")
	}
	identity, err := nodes.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != pin.TargetNode {
		return invalid("source authority provisioning identity")
	}
	encoded, err := v.Unseal(identity.PrivateKey)
	if err != nil {
		return invalid("source authority provisioning key")
	}
	seed, err := protocol.Decode(encoded)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return invalid("source authority provisioning key")
	}
	receiver, err := receiverFromMasterSeed(seed)
	if err != nil || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), pin.TargetX25519) != 1 {
		return invalid("source authority provisioning receiver")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if subtle.ConstantTimeCompare(private.Public().(ed25519.PublicKey), pin.TargetMasterPublic) != 1 {
		return invalid("source authority provisioning master pin")
	}
	raw, err := json.Marshal(pin)
	if err != nil {
		return err
	}
	sealed, err := v.Seal(string(raw))
	if err != nil {
		return err
	}
	// The repository transaction rechecks the complete identity and stores
	// only one immutable pin. An identical retry returns the original value.
	stored, _, err := repo.StoreOpaqueSourcePin(ctx, identity, v, sealed)
	if err != nil {
		return err
	}
	existing, err := decodeSourceAuthority(v, stored)
	if err != nil || !reflect.DeepEqual(existing, pin) {
		return invalid("source authority existing pin")
	}
	return nil
}
