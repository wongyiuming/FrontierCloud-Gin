package media

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogOwnerBindingCarrier interface {
	CatalogOwnerBinding(context.Context) (string, error)
}
type borrowedCatalogOwner struct {
	carrier  catalogOwnerBindingCarrier
	expected string
}

func (b borrowedCatalogOwner) Check(ctx context.Context) error {
	value, err := b.carrier.CatalogOwnerBinding(ctx)
	if err != nil || value != b.expected {
		return ErrUnavailable
	}
	return nil
}

// Release cannot release the underlying composite prerequisite.
func (borrowedCatalogOwner) Release() {}

// BorrowLocalCatalogOwnerSnapshot uses the ownerControl already held by a
// trusted owner→tree→ingress composite. It never reacquires that lock after
// ingress and is not valid for a remote owner. Matching the lock binding is
// necessary but not sufficient: callers must independently recheck the exact
// member configuration, credential revision and provider identity under it.
func BorrowLocalCatalogOwnerSnapshot(expected string) CatalogResourceSnapshot {
	return func(ctx context.Context, prerequisite store.IngressPrerequisite) (CatalogResourceLease, error) {
		carrier, ok := prerequisite.(catalogOwnerBindingCarrier)
		if !ok || expected == "" {
			return nil, ErrUnavailable
		}
		value := borrowedCatalogOwner{carrier: carrier, expected: expected}
		if err := value.Check(ctx); err != nil {
			return nil, err
		}
		return value, nil
	}
}
