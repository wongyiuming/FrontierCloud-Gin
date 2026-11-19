package media

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrOpaqueAdminDownloadOwner = errors.New("所选资源的存储节点暂不支持加密下载")

type OpaqueAdminDownloadTarget struct {
	Path       string `json:"path"`
	ResourceID string `json:"resource_id"`
	Kind       string `json:"kind"`
}

type OpaqueAdminDownloadEntry struct {
	Path       string               `json:"path"`
	ResourceID string               `json:"resource_id"`
	Filename   string               `json:"filename"`
	Snapshot   string               `json:"download_snapshot"`
	Encryption mediacrypto.Metadata `json:"encryption"`
	Transport  string               `json:"transport,omitempty"`
	ObjectID   string               `json:"object_id,omitempty"`
	placement  sealedtree.Placement
	s3         *sealedtree.S3Placement
	policy     store.SelectedUploadPolicy
}

func (s *Service) OpaqueAdminDownloadEntry(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, resourceID string) (OpaqueAdminDownloadEntry, error) {
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		return OpaqueAdminDownloadEntry{}, ErrUnavailable
	}
	return s.readOpaqueAdminDownloadEntry(ctx, tree, lease, identity.ID, resourceID, nil)
}

func (s *Service) readOpaqueAdminDownloadEntry(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, masterID, resourceID string, owners map[string]store.SelectedUploadPolicy) (OpaqueAdminDownloadEntry, error) {
	row, err := tree.ReadListingObjectWithLease(ctx, lease, resourceID, true)
	if err != nil {
		if remote, remoteErr := tree.ReadS3ListingObjectWithLease(ctx, lease, resourceID, true); remoteErr == nil && remote.Entry.ObjectID == resourceID {
			return opaqueAdminS3DownloadEntry(resourceID, remote.Path, remote.Entry.Kind, remote.Placement, remote.PlacementRevision)
		}
		return OpaqueAdminDownloadEntry{}, sealedtree.ErrConflict
	}
	return s.opaqueAdminDownloadEntry(ctx, masterID, resourceID, row.Path, row.Entry.Kind, row.Placement, owners)
}

func (s *Service) opaqueAdminDownloadEntry(ctx context.Context, masterID, resourceID, name, kind string, p sealedtree.Placement, owners map[string]store.SelectedUploadPolicy) (OpaqueAdminDownloadEntry, error) {
	var empty OpaqueAdminDownloadEntry
	if (kind != "audio" && kind != "video" && kind != "lyric") || !managedObject(name, false) || p.ObjectID != resourceID || p.State != "active" ||
		p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Bytes {
		return empty, sealedtree.ErrConflict
	}
	revision, err := opaqueSourceRevision(p)
	if err != nil {
		return empty, sealedtree.ErrConflict
	}
	item := OpaqueAdminDownloadEntry{Path: name, ResourceID: resourceID, Filename: DownloadFilename(name), Encryption: *p.Encryption, placement: p}
	if p.OwnerID != masterID {
		if kind == "lyric" {
			return empty, ErrOpaqueAdminDownloadOwner
		}
		policy, found := owners[p.OwnerID]
		if !found {
			policy, err = s.opaqueAdminDownloadOwner(ctx, masterID, p)
			if err != nil {
				return empty, err
			}
			if owners != nil {
				owners[p.OwnerID] = policy
			}
		}
		item.Transport, item.ObjectID, item.policy = policy.Transport, p.NativeObjectID, policy
		revision = opaqueAdminDownloadRevision(revision, p.NativeObjectID, policy)
	}
	item.Snapshot = downloadSnapshot(resourceID, name, p.Bytes, revision)
	return item, nil
}

// OpenOpaqueAdminDownload opens only the placement returned by a fresh,
// identity-pinned Admin admission. The browser authenticates each GCM chunk.
func (s *Service) OpenOpaqueAdminDownload(ctx context.Context, item OpaqueAdminDownloadEntry) (*OpaqueBlob, error) {
	p := item.placement
	if item.ResourceID != p.ObjectID || item.Snapshot == "" || item.Transport != "" {
		return nil, ErrUnavailable
	}
	return s.openOpaqueBlob(ctx, p.BlobID, p.SHA256, p.Bytes, true, nil, false)
}

// OpaqueAdminDownloadPlan visits only selected folders and their children. A
// capped traversal fails the whole plan instead of silently omitting files.
func (s *Service) OpaqueAdminDownloadPlan(ctx context.Context, tree *sealedtree.SQLStore, lease *sealedtree.TreeLease, targets []OpaqueAdminDownloadTarget) ([]OpaqueAdminDownloadEntry, bool, error) {
	const maxEntries = 5000
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		return nil, false, ErrUnavailable
	}
	items := []OpaqueAdminDownloadEntry{}
	seen := map[string]bool{}
	owners := map[string]store.SelectedUploadPolicy{}
	visited := 0
	forceZIP := len(targets) > 1
	add := func(item OpaqueAdminDownloadEntry) {
		if !seen[item.ResourceID] {
			items = append(items, item)
			seen[item.ResourceID] = true
		}
	}
	var walk func(string, string) error
	walk = func(name, id string) error {
		cursor := ""
		for {
			rows, next, err := tree.ListCatalogPageWithLease(ctx, lease, id, cursor, 128, true)
			if err != nil {
				return err
			}
			for _, row := range rows {
				visited++
				if visited > maxEntries {
					return ErrUploadSize
				}
				child := name + "/" + row.Entry.Name
				if row.Entry.Kind == "directory" {
					if !managedObject(child, true) {
						return ErrPath
					}
					if err = walk(child, row.Entry.ObjectID); err != nil {
						return err
					}
					continue
				}
				if row.S3Placement != nil {
					item, err := opaqueAdminS3DownloadEntry(row.Entry.ObjectID, child, row.Entry.Kind, *row.S3Placement, row.PlacementRevision)
					if err != nil {
						return err
					}
					add(item)
					continue
				}
				if row.Placement == nil {
					return sealedtree.ErrConflict
				}
				item, err := s.opaqueAdminDownloadEntry(ctx, identity.ID, row.Entry.ObjectID, child, row.Entry.Kind, *row.Placement, owners)
				if err != nil {
					return err
				}
				add(item)
			}
			if next == "" {
				return nil
			}
			if next == cursor {
				return sealedtree.ErrConflict
			}
			cursor = next
		}
	}
	for _, target := range targets {
		if target.Kind == "file" {
			item, err := s.readOpaqueAdminDownloadEntry(ctx, tree, lease, identity.ID, target.ResourceID, owners)
			if err != nil {
				return nil, false, err
			}
			if item.Path != target.Path {
				return nil, false, sealedtree.ErrConflict
			}
			add(item)
			continue
		}
		if target.Kind != "directory" || !strings.Contains(target.Path, "/") || !managedObject(target.Path, true) || path.Clean(target.Path) != target.Path {
			return nil, false, ErrPath
		}
		forceZIP = true
		id, err := tree.ResolveDirectoryWithLease(ctx, lease, target.Path, true)
		if err != nil || id != target.ResourceID {
			return nil, false, sealedtree.ErrConflict
		}
		if err = walk(target.Path, id); err != nil {
			return nil, false, err
		}
	}
	if len(items) == 0 {
		return nil, false, ErrCategory
	}
	if len(items) > maxEntries {
		return nil, false, ErrUploadSize
	}
	return items, forceZIP, lease.Check(ctx)
}
