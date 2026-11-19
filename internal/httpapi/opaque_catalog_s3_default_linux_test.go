//go:build linux && !catalog_fixture

package httpapi

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func addCatalogS3Fixture(context.Context, *testing.T, *sealedtree.SQLStore, string) string { return "" }

func addOpaqueS3LyricTrack(context.Context, *testing.T, *sealedtree.SQLStore, string) (string, string) {
	return "", ""
}
