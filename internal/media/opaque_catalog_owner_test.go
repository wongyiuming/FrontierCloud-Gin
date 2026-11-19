package media

import (
	"context"
	"testing"
)

type borrowedOwnerFixture struct {
	value string
	live  bool
}

func (f *borrowedOwnerFixture) Check(context.Context) error {
	if !f.live {
		return ErrUnavailable
	}
	return nil
}
func (f *borrowedOwnerFixture) CatalogOwnerBinding(ctx context.Context) (string, error) {
	if err := f.Check(ctx); err != nil {
		return "", err
	}
	return f.value, nil
}

func TestBorrowCatalogOwnerDoesNotReleaseComposite(t *testing.T) {
	ctx := context.Background()
	owner := &borrowedOwnerFixture{value: "binding", live: true}
	snapshot := BorrowLocalCatalogOwnerSnapshot("binding")
	lease, err := snapshot(ctx, owner)
	if err != nil || lease.Check(ctx) != nil {
		t.Fatal("borrow", err)
	}
	lease.Release()
	if !owner.live || lease.Check(ctx) != nil {
		t.Fatal("borrow released composite")
	}
	owner.value = "changed"
	if lease.Check(ctx) == nil {
		t.Fatal("changed owner binding accepted")
	}
	owner.live = false
	if _, err := snapshot(ctx, owner); err == nil {
		t.Fatal("released owner borrowed")
	}
}
