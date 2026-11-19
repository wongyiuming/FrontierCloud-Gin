package preprodimport

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// applySourceIDBatchToTree is deliberately private: it accepts only a live
// proof produced by the authenticated source replay, not an HTTP request or a
// caller-asserted manifest. The tree applies it under its real writer fence.
// Completing batches alone is not an import-readiness or product-enable gate.
func applySourceIDBatchToTree(ctx context.Context, target *sealedtree.SQLStore, proof *SourceIDBatch) error {
	if ctx == nil || target == nil || proof == nil {
		return invalid("source ID batch target")
	}
	view, err := proof.View()
	if err != nil || view.Index < 0 {
		return invalid("source ID batch target")
	}
	return target.ApplyHistoricalMediaIDBatch(ctx, view.ManifestDigest, uint64(view.Index), view.Last, view.Digest, view.IDs, proof.CheckForCommit)
}

type historicalSourceScope struct {
	SourceNode, TargetNode, SourceKeyID, ScopeDigest string
}

// completeSourceIDsInTree may be called only from the authenticated complete-
// replay callback. Expected scope must come from the trusted target coordinator,
// never from an untrusted caller or from the proof being checked.
func completeSourceIDsInTree(ctx context.Context, target *sealedtree.SQLStore, expected historicalSourceScope, proof *SourceIDCompletion) error {
	if ctx == nil || target == nil || proof == nil || !id32.MatchString(expected.SourceNode) || !id32.MatchString(expected.TargetNode) || !id64.MatchString(expected.SourceKeyID) || !id64.MatchString(expected.ScopeDigest) {
		return invalid("source ID completion target")
	}
	view, err := proof.View()
	if err != nil || view.SourceNode != expected.SourceNode || view.TargetNode != expected.TargetNode || view.SourceKeyID != expected.SourceKeyID || view.ScopeDigest != expected.ScopeDigest || view.BatchCount < 0 {
		return invalid("source ID completion target")
	}
	return target.CompleteHistoricalMediaIDs(ctx, view.ManifestDigest, uint64(view.BatchCount), view.Empty, view.FinalBatchDigest, func() error {
		return proof.CheckForCommit(view)
	})
}

// These guarded variants are the narrow offline target-coordinator path. They
// add same-transaction target identity/source-pin validation to source proofs;
// none of them establishes Owner readiness or exposes a product endpoint.
func applySourceIDBatchToGuardedTree(ctx context.Context, target *sealedtree.SQLStore, guard historicalTargetGuard, proof *SourceIDBatch) error {
	if ctx == nil || target == nil || proof == nil {
		return invalid("source ID guarded batch")
	}
	view, err := proof.View()
	if err != nil || view.Index < 0 {
		return invalid("source ID guarded batch")
	}
	proof.mu.Lock()
	err = proof.checkLocked()
	match := guard.matchesSource(proof.intent, proof.public, proof.receiver)
	proof.mu.Unlock()
	if err != nil || !match {
		return invalid("source ID guarded batch authority")
	}
	return target.ApplyHistoricalMediaIDBatchGuarded(ctx, view.ManifestDigest, uint64(view.Index), view.Last, view.Digest, view.IDs, guard.validate, proof.CheckForCommit)
}

func completeSourceIDsInGuardedTree(ctx context.Context, target *sealedtree.SQLStore, guard historicalTargetGuard, proof *SourceIDCompletion) error {
	if ctx == nil || target == nil || proof == nil {
		return invalid("source ID guarded completion")
	}
	view, err := proof.View()
	if err != nil || view.BatchCount < 0 {
		return invalid("source ID guarded completion")
	}
	proof.mu.Lock()
	err = proof.checkLocked()
	match := guard.matchesSource(proof.intent, proof.public, proof.receiver)
	proof.mu.Unlock()
	if err != nil || !match {
		return invalid("source ID guarded completion authority")
	}
	return target.CompleteHistoricalMediaIDsGuarded(ctx, view.ManifestDigest, uint64(view.BatchCount), view.Empty, view.FinalBatchDigest, guard.validate, func() error { return proof.CheckForCommit(view) })
}
