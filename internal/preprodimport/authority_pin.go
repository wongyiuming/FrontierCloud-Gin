package preprodimport

// A source pin is supplied independently of the plan, sealed by the target
// Master vault and stored transactionally alongside the target identity.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"

	"encoding/json"
	"io"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type sourceAuthorityPin = sourceauth.AuthorityPin
type sourceImportScope = sourceauth.ImportScope
type sourceOwnerPin = sourceauth.OwnerPin

func sourceScopeMatches(scope *sourceImportScope, projection Snapshot) bool {
	return sourceauth.SourceScopeMatches(scope, projection)
}

// validatePinnedSourceLyricsTx binds the complete decision batch to the
// independently vault-sealed source pin and the current target identity in
// the SAME transaction that reads the pending tree facts. The caller must
// hold Owner -> ingress -> tree fences, check again immediately before its
// commit, and independently authorize publication; this does not commit or
// authorize anything by itself.
func validatePinnedSourceLyricsTx(ctx context.Context, tx *sql.Tx, v *vault.Vault, tree *sealedtree.SQLStore, batch *sourceauth.DecisionBatch, expected sourceAuthorityPin, envelope store.EncryptedMediaSourceSnapshot, version int64, operations []string) error {
	if ctx == nil || tx == nil || v == nil || tree == nil || batch == nil || ctx.Err() != nil {
		return invalid("pinned source transaction input")
	}
	checkPin := func() error {
		var identity store.NodeIdentity
		if err := tx.QueryRowContext(ctx, "SELECT node_id,`role`,endpoint,private_key,created_at FROM node_identity WHERE singleton=1").Scan(&identity.ID, &identity.Role, &identity.Endpoint, &identity.PrivateKey, &identity.CreatedAt); err != nil || identity.Role != "Master" || identity.ID != expected.TargetNode {
			return invalid("pinned source target identity")
		}
		var sealed []byte
		if err := tx.QueryRowContext(ctx, "SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1").Scan(&sealed); err != nil {
			return invalid("pinned source missing")
		}
		actual, err := decodeSourceAuthority(v, string(sealed))
		if err != nil || !reflect.DeepEqual(actual, expected) {
			return invalid("pinned source mismatch")
		}
		encoded, err := v.Unseal(identity.PrivateKey)
		if err != nil {
			return invalid("pinned source target vault")
		}
		seed, err := protocol.Decode(encoded)
		if err != nil || len(seed) != ed25519.SeedSize {
			clear(seed)
			return invalid("pinned source target key")
		}
		defer clear(seed)
		signing := ed25519.NewKeyFromSeed(seed)
		defer clear(signing)
		receiver, err := receiverFromMasterSeed(seed)
		if err != nil || subtle.ConstantTimeCompare(signing.Public().(ed25519.PublicKey), expected.TargetMasterPublic) != 1 || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), expected.TargetX25519) != 1 {
			return invalid("pinned source target key mismatch")
		}
		return nil
	}
	if err := checkPin(); err != nil {
		return err
	}
	if err := tree.ValidatePendingSourceLyricsTx(ctx, tx, batch, expected, envelope, version, operations); err != nil {
		return err
	}
	if err := checkPin(); err != nil {
		return err
	}
	if err := batch.CheckForCommit(expected, envelope, version); err != nil || ctx.Err() != nil {
		return invalid("pinned source freshness")
	}
	return nil
}

type sourcePinRepository interface {
	StoreOpaqueSourcePin(context.Context, store.NodeIdentity, *vault.Vault, string) (string, bool, error)
	LoadOpaqueSourcePin(context.Context, store.NodeIdentity, *vault.Vault) (string, bool, error)
}

func validSourceAuthority(p sourceAuthorityPin) bool { return sourceauth.ValidSourceAuthority(p) }

func decodeSourceAuthority(v *vault.Vault, sealed string) (sourceAuthorityPin, error) {
	var empty sourceAuthorityPin
	if v == nil || len(sealed) == 0 || len(sealed) > 8192 {
		return empty, invalid("source authority vault")
	}
	plain, err := v.Unseal(sealed)
	if err != nil {
		return empty, invalid("source authority authentication")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(plain))
	decoder.DisallowUnknownFields()
	var p sourceAuthorityPin
	if decoder.Decode(&p) != nil {
		return empty, invalid("source authority format")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !validSourceAuthority(p) {
		return empty, invalid("source authority binding")
	}
	return p, nil
}

// The caller must already hold the current ingress read lease, from reading
// identity through its final authorization decision.
func loadSourceAuthority(ctx context.Context, nodes store.NodeRepository, v *vault.Vault, identity store.NodeIdentity) (sourceAuthorityPin, error) {
	repo, ok := nodes.(sourcePinRepository)
	if ctx == nil || !ok || v == nil {
		return sourceAuthorityPin{}, invalid("source authority repository")
	}
	sealed, found, err := repo.LoadOpaqueSourcePin(ctx, identity, v)
	if err != nil || !found {
		return sourceAuthorityPin{}, invalid("source authority missing")
	}
	return decodeSourceAuthority(v, sealed)
}
