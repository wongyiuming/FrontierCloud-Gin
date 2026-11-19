//go:build linux

package business

import (
	"context"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func buildRecoveryExpectationsFixture(t *testing.T, ctx context.Context, r *Repository, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault) RecoveryExpectations {
	t.Helper()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	owner, err := r.AcquireOwnerControlShared(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Release()
	lease, err := tree.AcquireReadFence(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	result, err := r.BuildRecoveryExpectations(bounded, owner, tree, lease, key, nodeVault)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
