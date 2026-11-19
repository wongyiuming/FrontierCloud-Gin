package preprodimport

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// importHistoricalIDsOffline connects only the isolated source-ID phase. The
// supplied identity, pin and scope must originate from trusted target setup;
// the same database transaction revalidates them against the target Vault and
// the maintenance lease. Source capture consistency, Owner reconciliation,
// publication and activation remain separate mandatory phases.
func importHistoricalIDsOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, target *sealedtree.SQLStore, v *vault.Vault, identity store.NodeIdentity, pin sourceAuthorityPin, scopeDigest string, signed signedSourceStream, intent sourceCaptureIntent, receiver *ecdh.PrivateKey, stage *os.File) error {
	if ctx == nil || gate == nil || target == nil || v == nil || receiver == nil || stage == nil || !validSourceAuthority(pin) || !id64.MatchString(scopeDigest) {
		return invalid("historical target coordinator")
	}
	// Pin contains slices and an optional scope pointer. Freeze caller-owned
	// data before taking the maintenance lease and checking any source proof.
	raw, err := json.Marshal(pin)
	if err != nil || len(raw) > 8192 {
		return invalid("historical target coordinator pin")
	}
	var pinned sourceAuthorityPin
	if err = json.Unmarshal(raw, &pinned); err != nil || !validSourceAuthority(pinned) {
		return invalid("historical target coordinator pin")
	}
	return gate.InspectSQLite(ctx, dataRoot, databasePath, func(held context.Context, check func() error) error {
		guard := historicalTargetGuard{path: databasePath, identity: identity, pin: pinned, scopeDigest: scopeDigest, vault: v, check: check}
		if !guard.matchesSource(intent, protocol.Encode(pinned.SourcePublic), receiver.PublicKey().Bytes()) {
			return invalid("historical target coordinator authority")
		}
		return withAuthenticatedSourceIDCompletion(held, signed, intent, protocol.Encode(pinned.SourcePublic), receiver, stage, func(proof *SourceIDBatch) error {
			return applySourceIDBatchToGuardedTree(held, target, guard, proof)
		}, func(proof *SourceIDCompletion) error {
			return completeSourceIDsInGuardedTree(held, target, guard, proof)
		})
	})
}
