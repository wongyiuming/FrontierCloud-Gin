package media

import (
	"context"
	"errors"
	"net/url"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CatalogOwnerSnapshot is obtained from an independently authenticated member
// configuration snapshot. Check must be read-only, verify the same owner and
// revision, and be valid while the final ingress fence is held. An offline
// owner can still be displayed. It does not authorize resource access.
type CatalogOwnerSnapshot struct {
	Transport string
	Acquire   CatalogResourceSnapshot
	// Required for S3: compare each sealed placement with the currently
	// authenticated member namespace, without exposing provider keys.
	CheckS3 func(*sealedtree.S3Placement) error
}
type CatalogOwnerResolver func(context.Context, string) (CatalogOwnerSnapshot, error)

type CatalogResourceLease interface {
	Check(context.Context) error
	Release()
}

// Acquire verifies the captured immutable revision and obtains the resource
// fence only after the final tree lease is held. Implementations must obey the
// same global lock order in every writer and recovery path.
type CatalogResourceSnapshot func(context.Context, store.IngressPrerequisite) (CatalogResourceLease, error)
type PreparedCatalogFence struct {
	Check   func(context.Context, store.IngressPrerequisite) error
	Release func()
}

func validCatalogResourceLease(v CatalogResourceLease) bool {
	if v == nil {
		return false
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !r.IsNil()
	}
	return true
}

type catalogScopeChecker interface {
	CheckCatalogScopes(context.Context, *sealedtree.SQLStore, []sealedtree.CatalogScopeCheck) error
}

// CatalogFactsVerifier authenticates the migration/native evidence needed for
// public display fields, including whether a lyric relation really exists.
// A missing or unverified lyric-resolution proof must be rejected; the tree
// having no relation pointer alone is not evidence of absence.
// It runs under the same real tree lease as the batch and must return a
// read-only final check for the exact evidence snapshot, or fail closed. Any
// independently mutable source must remain fenced through admission commit;
// a momentary version comparison alone does not provide that guarantee.
type CatalogFactsVerifier func(context.Context, *sealedtree.TreeLease, []sealedtree.CatalogItem) (CatalogResourceSnapshot, error)

func pEncryption(native *sealedtree.Placement, s3 *sealedtree.S3Placement) *mediacrypto.Metadata {
	if native != nil {
		return native.Encryption
	}
	if s3 != nil {
		return s3.Encryption
	}
	return nil
}

// PrepareOpaqueTreeCatalog is an unregistered, bounded pre-admission adapter.
// It reads only sealed tree facts, releases each shared tree lease after one
// page and returns a private result plus the final scope check. The caller
// must commit the exact ingress admission before releasing any result. Empty
// categories and categories containing only nested media remain unsupported. S3
// entries require a separately verified current member/namespace snapshot;
// its actual provider source, rotation and recovery are not yet installed.
func (s *Service) PrepareOpaqueTreeCatalog(ctx context.Context, tree *sealedtree.SQLStore, kind, directory string, includeHidden bool, resolve CatalogOwnerResolver, verifyFacts CatalogFactsVerifier) ([]Track, *PreparedCatalogFence, error) {
	return s.prepareOpaqueTreeCatalog(ctx, tree, kind, directory, includeHidden, resolve, verifyFacts, false)
}

// A known directory address can open a hidden directory. Visible parents still
// use their normal filtered lists, so knowing one address does not reveal siblings.
func resolveKnownCatalogDirectory(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, directory string, includeHidden bool) (string, bool, error) {
	parent, err := tree.ResolveDirectoryWithLease(ctx, lease, directory, includeHidden)
	if !includeHidden && errors.Is(err, sealedtree.ErrHidden) {
		parent, err = tree.ResolveDirectoryWithLease(ctx, lease, directory, true)
		return parent, true, err
	}
	return parent, includeHidden, err
}

// PrepareOpaqueArtworkDirectory retains the same scope proof when no direct
// tracks exist so a caller can safely evaluate the legacy nested fallback.
// Empty results do not prove category existence by themselves.
func (s *Service) PrepareOpaqueArtworkDirectory(ctx context.Context, tree *sealedtree.SQLStore, directory string, includeHidden bool, resolve CatalogOwnerResolver, verifyFacts CatalogFactsVerifier) ([]Track, *PreparedCatalogFence, error) {
	return s.prepareOpaqueTreeCatalog(ctx, tree, "music", directory, includeHidden, resolve, verifyFacts, true)
}

func (s *Service) prepareOpaqueTreeCatalog(ctx context.Context, tree *sealedtree.SQLStore, kind, directory string, includeHidden bool, resolve CatalogOwnerResolver, verifyFacts CatalogFactsVerifier, allowEmpty bool) ([]Track, *PreparedCatalogFence, error) {
	if s == nil || s.identity == nil || ctx == nil || tree == nil || resolve == nil || verifyFacts == nil || !categoryShape(directory, kind) {
		return nil, nil, ErrUnavailable
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	_, local := network.LocalCatalogPreflightFromContext(ctx)
	if !peer && !local {
		return nil, nil, ErrUnavailable
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Minute {
		return nil, nil, ErrUnavailable
	}
	select {
	case opaqueCatalogSlot <- struct{}{}:
		defer func() { <-opaqueCatalogSlot }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	var parent string
	var scope sealedtree.CatalogScopeProof
	var cursor string
	var items []Track
	var used int64
	owners := map[string]CatalogOwnerSnapshot{}
	var factSnapshots []CatalogResourceSnapshot
	guard := &catalogResourceGuard{}
	release := guard.release
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	for {
		lease, err := tree.AcquireReadFence(ctx)
		if err != nil {
			return nil, nil, ErrUnavailable
		}
		if cursor == "" {
			if allowEmpty {
				parent, err = tree.ResolveDirectoryWithLease(ctx, lease, directory, includeHidden)
			} else {
				parent, includeHidden, err = resolveKnownCatalogDirectory(ctx, tree, lease, directory, includeHidden)
			}
			if err == nil {
				scope, err = tree.CaptureCatalogScopeWithLease(ctx, lease, parent, includeHidden)
			}
		}
		var page []sealedtree.CatalogItem
		var next string
		if err == nil {
			page, next, err = tree.ListCatalogPageWithLease(ctx, lease, parent, cursor, opaqueCatalogPageSize, includeHidden)
		}
		if err == nil {
			var verify CatalogResourceSnapshot
			verify, err = verifyFacts(ctx, lease, page)
			if err == nil && verify == nil {
				err = ErrUnavailable
			}
			if err == nil {
				if used > opaqueCatalogMemoryBudget-1024 {
					err = errOpaqueCatalogBudget
				} else {
					used += 1024
					factSnapshots = append(factSnapshots, verify)
				}
			}
		}
		lease.Release()
		if err != nil {
			return nil, nil, ErrUnavailable
		}
		for _, item := range page {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			if item.Entry.Kind == "directory" {
				continue
			}
			p, s3 := item.Placement, item.S3Placement
			if (p == nil) == (s3 == nil) || p != nil && (p.State != "active" || p.ObjectID != item.Entry.ObjectID) || s3 != nil && s3.ObjectID != item.Entry.ObjectID || kind == "music" && item.Entry.Kind != "audio" || kind == "video" && item.Entry.Kind != "video" {
				return nil, nil, ErrUnavailable
			}
			ownerID, objectID, size, encrypted := "", "", int64(0), pEncryption(p, s3)
			if p != nil {
				ownerID, objectID, size = p.OwnerID, p.NativeObjectID, p.Bytes
			} else {
				ownerID, objectID, size = s3.MemberID, s3.Proof.ObjectID, s3.Proof.Bytes
			}
			owner, ok := owners[ownerID]
			if !ok {
				owner, err = resolve(ctx, ownerID)
				if err != nil || owner.Acquire == nil || owner.Transport != "Local" && owner.Transport != "Direct" && owner.Transport != "Relay" && owner.Transport != "S3" {
					return nil, nil, ErrUnavailable
				}
				owners[ownerID] = owner
			}
			if s3 != nil && (owner.Transport != "S3" || owner.CheckS3 == nil || owner.CheckS3(s3) != nil) || p != nil && owner.Transport == "S3" {
				return nil, nil, ErrUnavailable
			}
			name := path.Join(directory, item.Entry.Name)
			if path.Dir(name) != directory {
				return nil, nil, ErrUnavailable
			}
			handle, err := s.identity.KaraokeHandle(item.Entry.ObjectID, true)
			if err != nil {
				return nil, nil, ErrUnavailable
			}
			cost := int64(2048 + 8*len(name) + len(handle) + len(item.Entry.ObjectID) + len(objectID))
			if cost > opaqueCatalogMemoryBudget-used {
				return nil, nil, errOpaqueCatalogBudget
			}
			used += cost
			stats := store.PlaybackStats{}
			if item.Facts.Playback != nil {
				stats.Preference = int(item.Facts.Playback.Preference)
				if int64(stats.Preference) != item.Facts.Playback.Preference {
					return nil, nil, ErrUnavailable
				}
				stats.PlayScore = item.Facts.Playback.PlayScore
			}
			has := item.Facts.Lyric != nil || item.Facts.InternalDefaultLyric != nil
			if item.Facts.LyricResolution != nil {
				switch item.Facts.LyricResolution.State {
				case "default", "explicit":
					has = true
				case "none":
					// A fresh S3 upload has an authenticated no-association
					// decision, for which the lyric route supplies the builtin.
					has = s3 != nil && item.Entry.Kind == "audio" && (item.Facts.LyricResolution.Origin == "native" || item.Facts.LyricResolution.Origin == "local")
				default:
					return nil, nil, ErrUnavailable
				}
			}
			params := url.Values{"file_path": {name}, "resource_id": {item.Entry.ObjectID}}
			identityVersion := 0
			if p != nil {
				identityVersion = 1
			}
			items = append(items, Track{MediaPath: name, Title: strings.TrimSuffix(item.Entry.Name, path.Ext(item.Entry.Name)), Artist: "前沿娱乐", Type: item.Entry.Kind, URL: "/api/v1/media/stream?" + params.Encode(), Cover: "/favicon.ico", MediaID: item.Entry.ObjectID, ResourceID: item.Entry.ObjectID, ObjectID: objectID, Transport: owner.Transport, SizeBytes: size, PlaybackStats: stats, KaraokeID: handle, HasLyrics: &has, Encryption: encrypted, NativeSource: p != nil, SourceIdentityVersion: identityVersion})
		}
		if next == "" {
			break
		}
		if cursor == next {
			return nil, nil, ErrUnavailable
		}
		cursor = next
	}
	if len(items) == 0 && !allowEmpty {
		return nil, nil, ErrUnavailable
	}
	sortTracks(items)
	ownerIDs := make([]string, 0, len(owners))
	for id := range owners {
		ownerIDs = append(ownerIDs, id)
	}
	sort.Strings(ownerIDs)
	var acquireOnce sync.Once
	var acquireErr error
	check := func(c context.Context, prerequisite store.IngressPrerequisite) error {
		if guard.begin(prerequisite) != nil {
			return ErrUnavailable
		}
		checker, ok := prerequisite.(catalogScopeChecker)
		if !ok || checker.CheckCatalogScopes(c, tree, []sealedtree.CatalogScopeCheck{{ParentID: parent, IncludeHidden: includeHidden, Proof: scope}}) != nil {
			return ErrUnavailable
		}
		acquireOnce.Do(func() {
			snapshots := make([]CatalogResourceSnapshot, 0, len(ownerIDs)+len(factSnapshots))
			for _, id := range ownerIDs {
				snapshots = append(snapshots, owners[id].Acquire)
			}
			snapshots = append(snapshots, factSnapshots...)
			for _, snapshot := range snapshots {
				resource, e := snapshot(c, prerequisite)
				if e != nil || !validCatalogResourceLease(resource) {
					if validCatalogResourceLease(resource) {
						resource.Release()
					}
					acquireErr = ErrUnavailable
					return
				}
				if !guard.add(resource) {
					resource.Release()
					acquireErr = ErrUnavailable
					return
				}
			}
		})
		if acquireErr != nil {
			return acquireErr
		}
		for _, resource := range guard.resources() {
			if resource.Check(c) != nil {
				return ErrUnavailable
			}
		}
		return c.Err()
	}
	transferred = true
	return items, &PreparedCatalogFence{Check: check, Release: release}, nil
}
