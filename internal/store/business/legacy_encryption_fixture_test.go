//go:build legacy_gate_fixture

package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestLegacyEncryptionHelpersRejectDurableTree(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	repo := business.New(raw, db.Backend())
	first, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	id, next := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if err = repo.FixtureLegacyEncryption(ctx, id, &first, false); err != nil {
		t.Fatal("old-mode put", err)
	}
	_, err = raw.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.FixtureLegacyEncryption(ctx, next, &second, false); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tree allowed old put", err)
	}
	if err = repo.FixtureLegacyEncryption(ctx, id, nil, true); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tree allowed old retirement", err)
	}
	got, err := repo.Encryption(ctx, id)
	if err != nil || got == nil || *got != first {
		t.Fatal("existing descriptor changed", err)
	}
	got, err = repo.Encryption(ctx, next)
	if err != nil || got != nil {
		t.Fatal("new descriptor persisted", err)
	}
}
