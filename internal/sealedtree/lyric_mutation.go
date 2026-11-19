package sealedtree

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// NativeLyricChange is a trusted Master application request, not an HTTP
// credential. The application must first authenticate the existing Admin
// session/CSRF and identify the complete affected set under a compatible
// fence. Empty LyricID unbinds to the built-in fallback.
type NativeLyricChange struct {
	TrackID               string
	ExpectedFactsRevision int64
	LyricID               string
}

type NativeLyricOperation struct {
	OriginID  string
	TargetIDs []string
	Changes   []NativeLyricChange
}

// MaxNativeLyricPatchTracks bounds work in one Admin path-based mutation.
const MaxNativeLyricPatchTracks = 200

func (s *SQLStore) pathEntryTx(ctx context.Context, tx treeQuery, path string) (Entry, string, error) {
	if len(path) > 4096 || !utf8.ValidString(path) || utf8.RuneCountInString(path) > 1024 {
		return Entry{}, "", ErrInvalid
	}
	parts := strings.Split(path, "/")
	if len(parts) > 128 {
		return Entry{}, "", ErrInvalid
	}
	if err := s.requireListingReady(ctx, tx); err != nil {
		return Entry{}, "", err
	}
	parent := s.rootID
	var entry Entry
	var index string
	for i, part := range parts {
		if !validComponent(part) {
			return Entry{}, "", ErrInvalid
		}
		group, err := s.tree.ParentIndex(parent)
		if err != nil {
			return Entry{}, "", ErrInvalid
		}
		lookup, err := s.tree.Lookup(parent, part)
		if err != nil {
			return Entry{}, "", ErrInvalid
		}
		record, err := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, group, lookup))
		if err != nil {
			return Entry{}, "", err
		}
		if err = verifyNameReservation(ctx, tx, record); err != nil {
			return Entry{}, "", err
		}
		entry, err = s.tree.Open(parent, record)
		if err != nil || entry.Name != part || (i < len(parts)-1 && entry.Kind != "directory") {
			return Entry{}, "", ErrInvalid
		}
		parent, index = entry.ObjectID, record.ObjectIndex
	}
	return entry, index, nil
}

func (s *SQLStore) lyricPathEntryTx(ctx context.Context, tx treeQuery, path, kind string) (Entry, int64, error) {
	entry, index, err := s.pathEntryTx(ctx, tx, path)
	if err != nil {
		return Entry{}, 0, err
	}
	if entry.Kind != kind {
		return Entry{}, 0, ErrInvalid
	}
	_, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil {
		return Entry{}, 0, err
	}
	return entry, revision, nil
}

// ApplyNativeLyricBatch atomically changes the supplied tracks, their scope
// revisions and encrypted audit records. It is an unregistered primitive:
// the caller must independently prove the complete affected set for the old
// lyric-origin replacement operation, enforce Admin auth and preserve all
// capability/admission fences. It never calls the production HTTP handler.
// A lost response requires reading current state before retry, as with the old
// API; a stale expected revision never silently reapplies the change.
func (s *SQLStore) ApplyNativeLyricBatch(ctx context.Context, request NativeLyricOperation, audit store.AdminAudit) error {
	return s.applyNativeLyricBatch(ctx, request, audit, nil)
}

// ApplyNativeTrackLyricPath changes one track using paths resolved within the
// same fenced transaction as the update. Empty lyricPath selects fallback.
// The caller must authenticate the administrator and hold its ingress fence.
func (s *SQLStore) ApplyNativeTrackLyricPath(ctx context.Context, trackPath, lyricPath string, audit store.AdminAudit) error {
	if trackPath == "" || !strings.HasPrefix(trackPath, "music/") || (lyricPath != "" && !strings.HasPrefix(lyricPath, "lyrics/")) {
		return ErrInvalid
	}
	return s.applyNativeLyricBatch(ctx, NativeLyricOperation{}, audit, func(tx treeQuery) (NativeLyricOperation, error) {
		track, revision, err := s.lyricPathEntryTx(ctx, tx, trackPath, "audio")
		if err != nil {
			return NativeLyricOperation{}, err
		}
		request := NativeLyricOperation{OriginID: track.ObjectID}
		change := NativeLyricChange{TrackID: track.ObjectID, ExpectedFactsRevision: revision}
		if lyricPath != "" {
			lyric, _, err := s.lyricPathEntryTx(ctx, tx, lyricPath, "lyric")
			if err != nil {
				return NativeLyricOperation{}, err
			}
			change.LyricID = lyric.ObjectID
			request.TargetIDs = []string{lyric.ObjectID}
		}
		request.Changes = []NativeLyricChange{change}
		return request, nil
	})
}

// ApplyNativeLyricPathPatch changes only explicitly supplied tracks. It resolves
// paths and reads revisions under the same fence and transaction as the writes.
// A removal must still refer to this lyric when the transaction applies it.
func (s *SQLStore) ApplyNativeLyricPathPatch(ctx context.Context, lyricPath string, linked, unlinked []string, audit store.AdminAudit) error {
	count := len(linked) + len(unlinked)
	if !strings.HasPrefix(lyricPath, "lyrics/") || strings.Count(lyricPath, "/") > 3 || count == 0 || count > MaxNativeLyricPatchTracks {
		return ErrInvalid
	}
	paths := make([]string, 0, count)
	paths = append(paths, linked...)
	paths = append(paths, unlinked...)
	seen := make(map[string]bool, count)
	for _, path := range paths {
		if !strings.HasPrefix(path, "music/") || seen[path] {
			return ErrInvalid
		}
		seen[path] = true
	}
	return s.applyNativeLyricBatch(ctx, NativeLyricOperation{}, audit, func(tx treeQuery) (NativeLyricOperation, error) {
		lyric, _, err := s.lyricPathEntryTx(ctx, tx, lyricPath, "lyric")
		if err != nil {
			return NativeLyricOperation{}, err
		}
		request := NativeLyricOperation{
			OriginID: lyric.ObjectID, TargetIDs: make([]string, 0, len(linked)), Changes: make([]NativeLyricChange, 0, count),
		}
		for i, path := range paths {
			track, revision, err := s.lyricPathEntryTx(ctx, tx, path, "audio")
			if err != nil {
				return NativeLyricOperation{}, err
			}
			change := NativeLyricChange{TrackID: track.ObjectID, ExpectedFactsRevision: revision}
			if i < len(linked) {
				change.LyricID = lyric.ObjectID
				request.TargetIDs = append(request.TargetIDs, track.ObjectID)
			}
			request.Changes = append(request.Changes, change)
		}
		return request, nil
	})
}

func (s *SQLStore) applyNativeLyricBatch(ctx context.Context, request NativeLyricOperation, audit store.AdminAudit, resolve func(treeQuery) (NativeLyricOperation, error)) error {
	if resolve == nil && !hexID(request.OriginID) {
		return ErrInvalid
	}
	return s.withNativeLyricWrite(ctx, func(tx treeQuery, operation string) error {
		if resolve != nil {
			var err error
			request, err = resolve(tx)
			if err != nil {
				return err
			}
		}
		return s.applyNativeLyricBatchTx(ctx, tx, operation, request, audit)
	})
}

func (s *SQLStore) withNativeLyricWrite(ctx context.Context, apply func(treeQuery, string) error) error {
	if !s.valid() || ctx == nil {
		return ErrInvalid
	}
	operation, err := NewBlobID()
	if err != nil {
		return err
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = apply(tx, operation); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) applyNativeLyricBatchTx(ctx context.Context, tx treeQuery, operation string, request NativeLyricOperation, audit store.AdminAudit) error {
	targets := make(map[string]bool, len(request.TargetIDs))
	for _, id := range request.TargetIDs {
		if !hexID(id) || targets[id] {
			return ErrInvalid
		}
		targets[id] = true
	}
	changes := request.Changes
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		if !hexID(change.TrackID) || seen[change.TrackID] || change.ExpectedFactsRevision < 1 || change.ExpectedFactsRevision == math.MaxInt64 || (change.LyricID != "" && !hexID(change.LyricID)) {
			return ErrInvalid
		}
		seen[change.TrackID] = true
	}
	cache, err := s.newLyricTxCache(ctx, tx)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
	originRecord, err := cache.entry(request.OriginID)
	origin := originRecord.entry
	if err != nil || (origin.Kind != "audio" && origin.Kind != "lyric") {
		return ErrInvalid
	}
	originPath, err := cache.path(origin)
	if err != nil || originPath == "lyrics/default.lrc" || origin.Kind == "audio" && !strings.HasPrefix(originPath, "music/") || origin.Kind == "lyric" && !strings.HasPrefix(originPath, "lyrics/") {
		return ErrInvalid
	}
	if origin.Kind == "lyric" {
		if _, err = cache.lyric(origin.ObjectID); err != nil {
			return err
		}
	}
	if origin.Kind == "audio" {
		if len(request.TargetIDs) > 1 || len(changes) != 1 || changes[0].TrackID != origin.ObjectID {
			return ErrInvalid
		}
		if len(request.TargetIDs) == 0 && changes[0].LyricID != "" || len(request.TargetIDs) == 1 && changes[0].LyricID != request.TargetIDs[0] {
			return ErrInvalid
		}
	} else {
		for _, change := range changes {
			if targets[change.TrackID] && change.LyricID != origin.ObjectID || !targets[change.TrackID] && change.LyricID != "" {
				return ErrInvalid
			}
		}
		for id := range targets {
			if !seen[id] {
				return ErrInvalid
			}
		}
	}
	targetPaths := make([]string, 0, len(request.TargetIDs))
	for _, id := range request.TargetIDs {
		item, e := cache.entry(id)
		entry := item.entry
		if e != nil || origin.Kind == "audio" && entry.Kind != "lyric" || origin.Kind == "lyric" && entry.Kind != "audio" {
			return ErrInvalid
		}
		path, e := cache.path(entry)
		if e != nil {
			return e
		}
		targetPaths = append(targetPaths, path)
	}
	changesAudit, err := cache.applyChanges(operation, now, changes, func(change NativeLyricChange, facts Facts) error {
		if origin.Kind == "lyric" && !targets[change.TrackID] && (facts.Lyric == nil || facts.Lyric.LyricID != origin.ObjectID) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	relations := len(request.TargetIDs)
	if origin.Kind == "audio" {
		relations = 1
	}
	audit = nativeLyricAudit(audit, "lyric_relations", len(targetPaths)+1)
	return s.appendEncryptedLyricAudit(ctx, tx, operation, lyricAuditPayload{Origin: originPath, Targets: targetPaths, Changes: changesAudit, Relations: relations, At: now, Audit: audit})
}

func (s *SQLStore) newLyricTxCache(ctx context.Context, tx treeQuery) (*lyricTxCache, error) {
	var masterID, role string
	if err := tx.QueryRowContext(ctx, `SELECT node_id,role FROM node_identity WHERE singleton=1`).Scan(&masterID, &role); err != nil || len(masterID) != 32 || strings.ToLower(masterID) != masterID || (role != "Master" && role != "Standalone") {
		return nil, ErrInvalid
	}
	if _, err := hex.DecodeString(masterID); err != nil {
		return nil, ErrInvalid
	}
	return &lyricTxCache{s: s, tx: tx, ctx: ctx, masterID: masterID, entries: map[string]lyricCachedEntry{}, parents: map[string]string{}, lyrics: map[string]string{}}, nil
}

func nativeLyricAudit(audit store.AdminAudit, action string, count int) store.AdminAudit {
	audit.Action, audit.Result, audit.TargetCount, audit.SourceSummary, audit.Detail = action, "success", count, "", ""
	audit.SessionHash = truncateAudit(audit.SessionHash, 64)
	audit.ClientIP = truncateAudit(audit.ClientIP, 45)
	audit.UserAgent = truncateAudit(audit.UserAgent, 512)
	audit.RequestID = truncateAudit(audit.RequestID, 128)
	audit.TraceID = truncateAudit(audit.TraceID, 32)
	return audit
}

func (cache *lyricTxCache) applyChanges(operation, now string, changes []NativeLyricChange, admit func(NativeLyricChange, Facts) error) ([]LyricAuditChange, error) {
	s, ctx, tx := cache.s, cache.ctx, cache.tx
	changesAudit := make([]LyricAuditChange, 0, len(changes))
	changedGroups := make(map[string]bool)
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item, e := cache.entry(change.TrackID)
		track := item.entry
		if e != nil || track.Kind != "audio" {
			return nil, ErrInvalid
		}
		trackPath, e := cache.path(track)
		if e != nil || !strings.HasPrefix(trackPath, "music/") {
			return nil, ErrInvalid
		}
		facts, revision, e := s.factsFor(ctx, tx, track, item.index)
		if e != nil || revision != change.ExpectedFactsRevision || facts.Revocation != nil || facts.InternalPlaceholder {
			return nil, ErrConflict
		}
		if e = admit(change, facts); e != nil {
			return nil, e
		}
		if e = noPendingLyricRevocation(ctx, tx, item.index); e != nil {
			return nil, e
		}
		if facts.LyricResolution != nil && facts.LyricResolution.Origin == "native" {
			proof, err := s.nativeLyricEvidence(facts)
			if err != nil || !hmac.Equal([]byte(proof), []byte(facts.LyricResolution.Evidence)) {
				return nil, ErrInvalid
			}
		} else if facts.LyricResolution != nil && facts.LyricResolution.Origin == "local" {
			proof, err := s.localLyricEvidence(facts)
			if err != nil || !hmac.Equal([]byte(proof), []byte(facts.LyricResolution.Evidence)) {
				return nil, ErrInvalid
			}
		}
		trackPlacement, e := s.placementFor(ctx, tx, track, item.index)
		if errors.Is(e, ErrInvalid) {
			providerPlacement, err := s.checkIndexedS3(ctx, tx, track, item.index)
			if err != nil || !providerPlacement {
				return nil, ErrInvalid
			}
		} else if e != nil || trackPlacement.State != "active" {
			return nil, ErrInvalid
		}
		lyricPath := ""
		var link *LyricFact
		created := now
		if facts.Lyric != nil {
			created = facts.Lyric.CreatedAt
		} else if facts.InternalDefaultLyric != nil {
			created = facts.InternalDefaultLyric.CreatedAt
		} else if facts.LyricResolution != nil && facts.LyricResolution.Origin == "native" {
			created = facts.LyricResolution.RelationCreatedAt
		}
		if change.LyricID != "" {
			lyricPath, e = cache.lyric(change.LyricID)
			if e != nil {
				return nil, e
			}
			link = &LyricFact{LegacyMediaPath: trackPath, LyricID: change.LyricID, LegacyLyricPath: lyricPath, CreatedAt: created, UpdatedAt: now}
		}
		previous := ""
		if facts.LyricResolution != nil {
			previous = facts.LyricResolution.Evidence
		}
		state := "default"
		if link != nil {
			state = "explicit"
		}
		facts.Lyric, facts.InternalDefaultLyric = link, nil
		facts.LyricResolution = &LyricResolutionFact{State: state, Origin: "native", OperationID: operation, PreviousEvidence: previous, PreviousRevision: revision, RelationCreatedAt: created, RelationUpdatedAt: now}
		facts.LyricResolution.Evidence, e = s.nativeLyricEvidence(facts)
		if e != nil || !factsCompatible(track, facts) {
			return nil, ErrInvalid
		}
		sealed, e := s.tree.SealFacts(facts, revision+1)
		if e != nil {
			return nil, e
		}
		id, e := FactsEncryptionID(sealed)
		if e != nil {
			return nil, e
		}
		if _, e = reserveID(ctx, tx, id); e != nil {
			return nil, e
		}
		result, e := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, item.index, revision)
		if e != nil {
			return nil, ErrConflict
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return nil, ErrConflict
		}
		changedGroups[s.listingClassGroup(track.ParentID, listingClass(&facts))] = true
		changesAudit = append(changesAudit, LyricAuditChange{Track: trackPath, Lyric: lyricPath})
	}
	groups := make([]string, 0, len(changedGroups))
	for group := range changedGroups {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	for _, group := range groups {
		if err := s.listingAdjust(ctx, tx, group, 0); err != nil {
			return nil, err
		}
	}
	return changesAudit, nil
}

func truncateAudit(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func noPendingLyricRevocation(ctx context.Context, tx treeQuery, index string) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, index).Scan(&count); err != nil || count != 0 {
		return ErrConflict
	}
	return nil
}

// pathInTransaction reconstructs authenticated ancestors without writing a
// name/path to SQL. Hidden is allowed for the existing Admin operation.
func (s *SQLStore) pathInTransaction(ctx context.Context, tx treeQuery, leaf Entry) (string, error) {
	parts := []string{leaf.Name}
	seen := map[string]bool{leaf.ObjectID: true}
	current := leaf.ParentID
	for depth := 0; depth < 128 && current != s.rootID; depth++ {
		if seen[current] {
			return "", ErrInvalid
		}
		seen[current] = true
		_, parent, err := s.recordByID(ctx, tx, current)
		if err != nil || parent.Kind != "directory" {
			return "", ErrInvalid
		}
		parts = append(parts, parent.Name)
		current = parent.ParentID
	}
	if current != s.rootID {
		return "", ErrInvalid
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	path := strings.Join(parts, "/")
	if len(path) > 4096 || utf8.RuneCountInString(path) > 1024 {
		return "", ErrInvalid
	}
	return path, nil
}
