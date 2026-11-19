//go:build catalog_fixture

package sealedtree

import "context"

// CatalogFixtureCreateS3 is compiled only under the explicit catalog_fixture
// test build tag. It deliberately does not authenticate source evidence or
// provider/member authorization and must never be used for real imports.
func (s *SQLStore) CatalogFixtureCreateS3(ctx context.Context, entry Entry, facts Facts, placement S3Placement) error {
	return s.createImportedS3Fixture(ctx, entry, facts, placement)
}
