package media

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// treeBoundCatalogEvidence has no external mutable source. Its authority is
// the authenticated tree scope, which the caller must hold and verify through
// admission commit. It is not a substitute for a source snapshot lease.
type treeBoundCatalogEvidence struct{}

func (treeBoundCatalogEvidence) Check(ctx context.Context) error { return ctx.Err() }
func (treeBoundCatalogEvidence) Release()                        {}

// NativeCatalogFactsVerifier admits only native-origin lyric decisions with
// valid tree-keyed evidence. Imported source-origin facts remain unavailable
// until their independent source snapshot/lease verification is installed.
// The caller must also verify the complete tree scope under final admission.
func NativeCatalogFactsVerifier(tree *sealedtree.SQLStore) CatalogFactsVerifier {
	if tree == nil {
		return nil
	}
	return func(ctx context.Context, lease *sealedtree.TreeLease, items []sealedtree.CatalogItem) (CatalogResourceSnapshot, error) {
		if err := tree.VerifyNativeCatalogLyricFactsWithLease(ctx, lease, items); err != nil {
			return nil, err
		}
		return func(c context.Context, _ store.IngressPrerequisite) (CatalogResourceLease, error) {
			if err := c.Err(); err != nil {
				return nil, err
			}
			return treeBoundCatalogEvidence{}, nil
		}, nil
	}
}

// CatalogLyricFactsVerifier checks both native and tree-attested imported
// decisions under the held tree lease. It is not installed by runtime and
// source attestations cannot be minted until the authenticated import
// transaction and current independent source pin are connected.
func CatalogLyricFactsVerifier(tree *sealedtree.SQLStore) CatalogFactsVerifier {
	if tree == nil {
		return nil
	}
	return func(ctx context.Context, lease *sealedtree.TreeLease, items []sealedtree.CatalogItem) (CatalogResourceSnapshot, error) {
		if err := tree.VerifyCatalogLyricFactsWithLease(ctx, lease, items); err != nil {
			return nil, err
		}
		return func(c context.Context, _ store.IngressPrerequisite) (CatalogResourceLease, error) {
			if err := c.Err(); err != nil {
				return nil, err
			}
			return treeBoundCatalogEvidence{}, nil
		}, nil
	}
}
