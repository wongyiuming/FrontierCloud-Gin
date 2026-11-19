package preprodimport

// Historical source authentication for a single tree lyric decision. This
// helper is deliberately not registered as a runtime authority: the separate
// vault's inode/rollback fence and the target's atomic commit proof must first
// be bound to the admission lease. Historical source signatures must not be
// required to remain fresh after a completed migration.

import (
	"context"
	"crypto/ecdh"
	"database/sql"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// verifyHistoricalSourceLyric checks the original signed projection, rather
// than treating its digest as a signature. The current one-record budget is a
// temporary fail-closed bound until authenticated chunked evidence is wired;
// this function does not grant access or prove that migration committed.
func verifyHistoricalSourceLyric(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, trackID string, selected sealedtree.LyricSelection) error {
	if ctx == nil || db == nil || receiver == nil || selected.Origin != "" || !id64.MatchString(selected.SourceDigest) || !id64.MatchString(selected.SourceGeneration) || !id64.MatchString(trackID) {
		return invalid("historical lyric evidence input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if requireSyntheticJournalDurability(ctx, tx) != nil || requireSourceEvidenceConstraints(ctx, tx) != nil || requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode) != nil {
		return invalid("historical lyric evidence vault")
	}
	tag, err := sourceEvidenceTag(root, selected.SourceDigest)
	if err != nil {
		return err
	}
	var size int64
	if tx.QueryRowContext(ctx, "SELECT length(cipher) FROM preprod_source_evidence WHERE evidence_tag=?", tag).Scan(&size) != nil || size <= 0 || size > 4*1024*1024 {
		return invalid("historical lyric evidence budget")
	}
	record, signed, err := readSourceEvidenceTx(ctx, tx, root, receiver, pin, sourceEvidenceRef{Digest: selected.SourceDigest})
	if err != nil {
		return err
	}
	// readSourceEvidenceTx verifies the original signed envelope and projection
	// at its signed issuance time; acceptance/publication are separate facts.
	if signed.Snapshot.IssuedUnix <= 0 || signed.Snapshot.ExpiresUnix <= signed.Snapshot.IssuedUnix {
		return invalid("historical lyric evidence time")
	}
	generation, err := completeSnapshotDigest(record.Complete)
	if err != nil || generation != selected.SourceGeneration || generation != pin.Generation {
		return invalid("historical lyric generation")
	}
	track, err := evidenceObjectMedia(record.Complete, pin, trackID)
	if err != nil || track.Kind != "audio" {
		return invalid("historical lyric track")
	}
	resolution, err := sourceLyricResolution(record.Complete, track, selected.SourceDigest, generation)
	if err != nil || resolution == nil || resolution.Evidence != selected.Evidence || resolution.SourceDigest != selected.SourceDigest || resolution.SourceGeneration != selected.SourceGeneration {
		return invalid("historical lyric resolution")
	}
	if resolution.State == "explicit" {
		if selected.BuiltinFallback || selected.ExplicitLyricID == "" {
			return invalid("historical lyric selection")
		}
		found := false
		for _, link := range record.Complete.Facts.LyricLinks {
			if link.MediaID == trackID && link.LyricID == selected.ExplicitLyricID {
				found = true
			}
		}
		if !found {
			return invalid("historical lyric association")
		}
	} else if !selected.BuiltinFallback || selected.ExplicitLyricID != "" {
		return invalid("historical lyric fallback")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tx.Commit()
}
