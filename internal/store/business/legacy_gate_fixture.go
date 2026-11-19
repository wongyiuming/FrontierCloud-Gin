//go:build legacy_gate_fixture

package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// FixtureHoldLegacyWrite is only built in isolated lock-order tests.
func (r *Repository) FixtureHoldLegacyWrite(ctx context.Context, hold func() error) error {
	return r.legacyWrite(ctx, func(queryer) error { return hold() })
}

// FixtureLegacyEncryption exercises the actual nested old-writer helpers.
func (r *Repository) FixtureLegacyEncryption(ctx context.Context, id string, meta *mediacrypto.Metadata, retire bool) error {
	return r.write(ctx, func(q queryer) error {
		if retire {
			return retireEncryption(ctx, q, id)
		}
		return r.putEncryption(ctx, q, id, meta)
	})
}
