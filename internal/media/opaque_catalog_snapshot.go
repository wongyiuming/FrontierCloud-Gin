package media

import (
	"context"
	"errors"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This bounded in-memory experiment is not wired to a product route. Before
// it can replace the catalog, migration must prove complete tree membership,
// all old writers must share its fence, and the caller must preserve the old
// category-existence and authorization semantics.
var errOpaqueCatalogBudget = errors.New("encrypted catalog exceeds in-memory budget")
var opaqueCatalogSlot = make(chan struct{}, 1)

const opaqueCatalogPageSize = 128
const opaqueCatalogMemoryBudget int64 = 32 << 20

// opaqueCatalogAuthorize is a trusted Master-only callback. It must validate
// the legacy public display scope, current active global placement and content
// descriptor without issuing a byte capability. Owner transport policy and
// readiness are checked separately when a browser requests a resource grant.
// The tree's listing operation itself grants neither playback nor lyric access.
type opaqueCatalogAuthorize func(context.Context, sealedtree.ListingObject) (store.GlobalMedia, string, error)

// authorizeOpaqueCatalogListing is for display only: unlike a resource-read
// authorizer it deliberately permits a listing object from include_hidden.
// Migration and all legacy writers must eventually share the held tree fence;
// this adapter remains dormant until that cross-store invariant is proven.
func (s *Service) authorizeOpaqueCatalogListing(ctx context.Context, object sealedtree.ListingObject) (store.GlobalMedia, string, error) {
	var empty store.GlobalMedia
	if s == nil || s.nodes == nil || s.pool == nil || s.repository == nil || s.identity == nil || !network.HasActivePublicAdmission(ctx) {
		return empty, "", ErrUnavailable
	}
	assertion, local, ok := network.PublicIngressIdentityFromContext(ctx)
	identity, err := s.IdentityState(ctx)
	routing, supports := s.nodes.(store.PublicRoutingRepository)
	if !ok || err != nil || !supports || identity.Role != "Master" || identity.ID != s.identity.ID || local != (assertion.NodeID == identity.ID) {
		return empty, "", ErrUnavailable
	}
	current, err := routing.PublicIngress(ctx)
	if err != nil || current.NodeID != assertion.NodeID || current.Generation != assertion.Generation || current.PublicOrigin != assertion.PublicOrigin {
		return empty, "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return empty, "", err
	}
	defer release()
	row, err := s.pool.Resource(ctx, object.Entry.ObjectID)
	if err != nil || row.ID != object.Entry.ObjectID || row.Path != object.Path || row.Kind != object.Entry.Kind || row.State != "active" || row.Transport != "Local" && row.Transport != "Direct" && row.Transport != "Relay" || row.MemberID != object.Placement.OwnerID || row.ObjectID != object.Placement.NativeObjectID || row.Bytes != object.Placement.Bytes || row.ETag != object.Placement.ETag {
		return empty, "", ErrUnavailable
	}
	legacy, err := s.repository.ObjectByID(ctx, row.ID)
	if err != nil || legacy == nil || legacy.ID != row.ID || legacy.Path != row.Path || legacy.Kind != row.Kind || !reflect.DeepEqual(legacy.Encryption, object.Placement.Encryption) {
		return empty, "", ErrUnavailable
	}
	// Preference and play count are encrypted tree facts as well as legacy
	// catalog fields. Never silently order a partially migrated projection.
	if object.Facts.Playback == nil {
		if row.Preference != 0 || row.PlayScore != 0 {
			return empty, "", ErrUnavailable
		}
	} else if int64(row.Preference) != object.Facts.Playback.Preference || row.PlayScore != object.Facts.Playback.PlayScore {
		return empty, "", ErrUnavailable
	}
	handle, err := s.identity.KaraokeHandle(row.ID, true)
	if err != nil {
		return empty, "", err
	}
	return row, handle, nil
}

// collectOpaqueCatalog consumes every tree page before sorting using the old
// comparator. It never persists names, silently truncates, or returns partial
// output on timeout/budget/authorization errors. The exact shared tree lease
// must remain held through the caller's eventual response admission commit.
func collectOpaqueCatalog(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, directory, kind string, includeHidden bool, budget int64, authorize opaqueCatalogAuthorize) ([]Track, error) {
	if ctx == nil || tree == nil || lease == nil || authorize == nil || budget < 1 || budget > opaqueCatalogMemoryBudget || !categoryShape(directory, kind) || !network.HasActivePublicAdmission(ctx) {
		return nil, ErrUnavailable
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Minute {
		return nil, ErrUnavailable
	}
	if _, _, authenticated := network.PublicIngressIdentityFromContext(ctx); !authenticated {
		return nil, ErrUnavailable
	}
	prerequisite, ok := store.IngressPrerequisiteFromContext(ctx)
	if !ok || prerequisite != lease || lease.Check(ctx) != nil {
		return nil, ErrUnavailable
	}
	select {
	case opaqueCatalogSlot <- struct{}{}:
		defer func() { <-opaqueCatalogSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	parent, err := tree.ResolveDirectoryWithLease(ctx, lease, directory, includeHidden)
	if err != nil {
		return nil, ErrUnavailable
	}
	items := make([]Track, 0)
	var bytesUsed int64
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, next, err := tree.ListDirectoryWithLease(ctx, lease, parent, cursor, opaqueCatalogPageSize, includeHidden)
		if err != nil {
			return nil, ErrUnavailable
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if entry.Kind == "directory" {
				continue
			}
			if kind == "music" && entry.Kind != "audio" || kind == "video" && entry.Kind != "video" {
				return nil, ErrUnavailable
			}
			object, err := tree.ReadListingObjectWithLease(ctx, lease, entry.ObjectID, includeHidden)
			if err != nil || object.Entry != entry || path.Dir(object.Path) != directory || object.Placement.State != "active" {
				return nil, ErrUnavailable
			}
			row, handle, err := authorize(ctx, object)
			if err != nil || row.ID != entry.ObjectID || row.Path != object.Path || row.Kind != entry.Kind || row.State != "active" || row.MemberID != object.Placement.OwnerID || row.ObjectID != object.Placement.NativeObjectID || row.Bytes != object.Placement.Bytes || row.ETag != object.Placement.ETag || row.Transport != "Local" && row.Transport != "Direct" && row.Transport != "Relay" || handle == "" || len(handle) > 4096 {
				return nil, ErrUnavailable
			}
			// Reserve pessimistically for the live Track, its strings and sort
			// overhead; budget failure is explicit and never a partial catalog.
			cost := int64(2048 + 8*len(row.Path) + len(handle) + len(row.ID) + len(row.ObjectID))
			if cost > budget-bytesUsed {
				return nil, errOpaqueCatalogBudget
			}
			bytesUsed += cost
			params := url.Values{"file_path": {row.Path}, "resource_id": {row.ID}}
			hasLyrics := row.HasLyrics
			items = append(items, Track{MediaPath: row.Path, Title: strings.TrimSuffix(path.Base(row.Path), path.Ext(row.Path)), Artist: "前沿娱乐", Type: row.Kind, URL: "/api/v1/media/stream?" + params.Encode(), Cover: "/favicon.ico", MediaID: row.ID, ResourceID: row.ID, ObjectID: row.ObjectID, Transport: row.Transport, SizeBytes: row.Bytes, PlaybackStats: row.PlaybackStats, KaraokeID: handle, HasLyrics: &hasLyrics, Encryption: object.Placement.Encryption, NativeSource: true, SourceIdentityVersion: 1})
		}
		if next == "" {
			break
		}
		if next == cursor {
			return nil, ErrUnavailable
		}
		cursor = next
	}
	if ctx.Err() != nil || !network.HasActivePublicAdmission(ctx) || lease.Check(ctx) != nil {
		return nil, ErrUnavailable
	}
	sortTracks(items)
	if ctx.Err() != nil || !network.HasActivePublicAdmission(ctx) || lease.Check(ctx) != nil {
		return nil, ErrUnavailable
	}
	return items, nil
}
