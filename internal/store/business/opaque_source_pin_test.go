package business_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestOpaqueSourcePinIsImmutableAndIdentityBound(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	sealedKey, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	initial := store.NodeIdentity{ID: strings.Repeat("1", 32), Role: "Standalone", PrivateKey: sealedKey, CreatedAt: 123}
	if _, err = db.Nodes().InitializeIdentity(ctx, initial); err != nil {
		t.Fatal(err)
	}
	identity, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	first, _ := v.Seal("synthetic pinned authority")
	second, _ := v.Seal("synthetic pinned authority")
	var wg sync.WaitGroup
	type outcome struct {
		stored  string
		created bool
		err     error
	}
	results := make(chan outcome, 2)
	for _, candidate := range []string{first, second} {
		wg.Add(1)
		go func(candidate string) {
			defer wg.Done()
			stored, created, e := repo.StoreOpaqueSourcePin(ctx, identity, v, candidate)
			results <- outcome{stored, created, e}
		}(candidate)
	}
	wg.Wait()
	close(results)
	var stored string
	creations := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if stored != "" && stored != result.stored {
			t.Fatal("concurrent stores returned different values")
		}
		stored = result.stored
		if result.created {
			creations++
		}
	}
	if creations != 1 {
		t.Fatal("expected exactly one committed insert", creations)
	}
	loaded, found, err := repo.LoadOpaqueSourcePin(ctx, identity, v)
	if err != nil || !found || loaded != stored {
		t.Fatal("source pin recovery", err)
	}
	other, _ := v.Seal("different authority")
	if _, _, err = repo.StoreOpaqueSourcePin(ctx, identity, v, other); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("pin replacement accepted", err)
	}
	wrong := identity
	wrong.CreatedAt++
	if _, _, err = repo.LoadOpaqueSourcePin(ctx, wrong, v); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("replacement identity accepted", err)
	}
	foreign, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if _, _, err = repo.LoadOpaqueSourcePin(ctx, identity, foreign); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong vault accepted", err)
	}
}
