package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// localLyricEvidence is issued only after the same fenced SQLite transaction
// has compared the complete local legacy relation, including an absent row.
// Its domain does not claim a remote signed snapshot or a native user action.
func (s *SQLStore) localLyricEvidence(f Facts) (string, error) {
	r := f.LyricResolution
	if r == nil || r.Origin != "local" || (r.State != "none" && r.State != "explicit" && r.State != "default") || !hexID(r.OperationID) {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(struct {
		Lyric   *LyricFact        `json:"lyric"`
		Default *DefaultLyricFact `json:"default"`
	}{f.Lyric, f.InternalDefaultLyric})
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return s.listingMAC("local-legacy-lyric", f.ObjectID, r.State, r.OperationID, hex.EncodeToString(digest[:])), nil
}

// sourceLyricAttestation binds the original authenticated source decision and
// every preserved relation field using the existing tree key. It is private:
// a source digest or caller-provided pin alone must never mint this proof.
func (s *SQLStore) sourceLyricAttestation(f Facts) (string, error) {
	r := f.LyricResolution
	if r == nil || r.Origin != "" || r.SourceDigest == "" || r.SourceGeneration == "" || !validFacts(f) {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(struct {
		Lyric   *LyricFact        `json:"lyric"`
		Default *DefaultLyricFact `json:"default"`
	}{f.Lyric, f.InternalDefaultLyric})
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return s.listingMAC("source-lyric-import", f.ObjectID, r.SourceDigest, r.SourceGeneration, r.State, r.Evidence, hex.EncodeToString(digest[:])), nil
}

// VerifyCatalogLyricFactsWithLease accepts native and authenticated local
// decisions and only source decisions carrying the matching tree-keyed import attestation. Existing
// unmarked historical records remain unavailable. The attestation minting
// path is deliberately not connected until source pin, import transaction and
// commit-time freshness are jointly verified.
func (s *SQLStore) VerifyCatalogLyricFactsWithLease(ctx context.Context, lease *TreeLease, items []CatalogItem) error {
	if !s.valid() || ctx == nil || lease == nil || len(items) > 257 {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return err
	}
	for _, item := range items {
		if item.Entry.Kind != "audio" {
			continue
		}
		facts := item.Facts
		if !factsCompatible(item.Entry, facts) || !validFacts(facts) || facts.LyricResolution == nil {
			return ErrInvalid
		}
		r := facts.LyricResolution
		var expected string
		var err error
		if r.Origin == "native" {
			expected, err = s.nativeLyricEvidence(facts)
			if err != nil || !hmac.Equal([]byte(expected), []byte(r.Evidence)) {
				return ErrInvalid
			}
		} else if r.Origin == "local" {
			expected, err = s.localLyricEvidence(facts)
			if err != nil || !hmac.Equal([]byte(expected), []byte(r.Evidence)) {
				return ErrInvalid
			}
		} else {
			if r.SourceProof == "" {
				return ErrInvalid
			}
			expected, err = s.sourceLyricAttestation(facts)
			if err != nil || !hmac.Equal([]byte(expected), []byte(r.SourceProof)) {
				return ErrInvalid
			}
		}
	}
	return lease.checkLocked(ctx)
}

// VerifyNativeCatalogLyricFactsWithLease checks native-operation lyric facts
// already read from a catalog page under the same tree lease. It does not
// authenticate source-import evidence, establish that arbitrary caller data
// came from that page, or authorize a resource. The caller must separately
// check the catalog scope through admission. Unknown/source decisions fail
// closed until their independently authenticated snapshot is connected.
func (s *SQLStore) VerifyNativeCatalogLyricFactsWithLease(ctx context.Context, lease *TreeLease, items []CatalogItem) error {
	if !s.valid() || ctx == nil || lease == nil || len(items) > 257 {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return err
	}
	for _, item := range items {
		if item.Entry.Kind != "audio" {
			continue
		}
		if err := s.verifyNativeCatalogLyricFact(item); err != nil {
			return err
		}
	}
	return lease.checkLocked(ctx)
}

func (s *SQLStore) verifyNativeCatalogLyricFact(item CatalogItem) error {
	facts := item.Facts
	if !factsCompatible(item.Entry, facts) || !validFacts(facts) || facts.LyricResolution == nil || facts.LyricResolution.Origin != "native" {
		return ErrInvalid
	}
	evidence, err := s.nativeLyricEvidence(facts)
	if err != nil || !hmac.Equal([]byte(evidence), []byte(facts.LyricResolution.Evidence)) {
		return ErrInvalid
	}
	return nil
}

// MaxLyricScopeEntries bounds the Admin catalog work shared by both panes.
const MaxLyricScopeEntries = 4096

// ErrLyricScopeLimit means no complete subtree result was returned.
var ErrLyricScopeLimit = errors.New("lyric catalog subtree exceeds the entry limit")

// NativeLyricScopeItem holds verified Admin catalog metadata and an optional
// relation identity. The caller separately authorizes any byte reads.
type NativeLyricScopeItem struct {
	Path, ID, LinkedLyricID string
}

// ReadNativeLyricScopeWithLease reads a complete bounded business subtree.
// The count includes entries visited for the budget, including directories.
func (s *SQLStore) ReadNativeLyricScopeWithLease(ctx context.Context, lease *TreeLease, scope, root string, budget int) ([]NativeLyricScopeItem, int, error) {
	if !s.valid() || ctx == nil || lease == nil || budget < 0 || budget > MaxLyricScopeEntries ||
		(root != "music" && root != "lyrics") || !validLyricAutoScope(scope, root) {
		return nil, 0, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return nil, 0, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return nil, 0, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, 0, err
	}
	remaining := budget
	rows := []NativeLyricScopeItem{}
	err = s.walkLyricScopeTx(ctx, tx, scope, root, &remaining, func(name string, item CatalogItem) error {
		row := NativeLyricScopeItem{Path: name, ID: item.Entry.ObjectID}
		if root == "music" {
			if err := s.verifyNativeCatalogLyricFact(item); err != nil {
				return err
			}
			if item.Facts.Lyric != nil {
				row.LinkedLyricID = item.Facts.Lyric.LyricID
			}
		}
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		return nil, budget - remaining, err
	}
	if err = tx.Commit(); err != nil {
		return nil, budget - remaining, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return nil, budget - remaining, err
	}
	return rows, budget - remaining, nil
}
