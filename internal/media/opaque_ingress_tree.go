package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type ingressTreeReader interface {
	Check(context.Context) error
	ReadVisibleObject(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, error)
	ReadVisibleObjectByAlias(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, error)
	ReadLinkedVisibleLyric(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, sealedtree.VisibleObject, error)
	SelectLyricForDisplay(context.Context, *sealedtree.SQLStore, string) (sealedtree.LyricSelection, error)
	ReadListingObject(context.Context, *sealedtree.SQLStore, string, bool) (sealedtree.ListingObject, error)
	ReadListingObjectByAlias(context.Context, *sealedtree.SQLStore, string, bool) (sealedtree.ListingObject, error)
}

// legacyTreeReader remains for explicitly-held tree leases used in isolated
// fixtures and relay reopen paths. The production composite supplies a
// non-releasable reader whose tree authority is retained by admission.
type legacyTreeReader struct{ lease *sealedtree.TreeLease }

func (v legacyTreeReader) Check(ctx context.Context) error { return v.lease.Check(ctx) }
func (v legacyTreeReader) ReadVisibleObject(ctx context.Context, s *sealedtree.SQLStore, id string) (sealedtree.VisibleObject, error) {
	return s.ReadVisibleObjectWithLease(ctx, v.lease, id)
}
func (v legacyTreeReader) ReadVisibleObjectByAlias(ctx context.Context, s *sealedtree.SQLStore, id string) (sealedtree.VisibleObject, error) {
	return s.ReadVisibleObjectByAliasWithLease(ctx, v.lease, id)
}
func (v legacyTreeReader) ReadLinkedVisibleLyric(ctx context.Context, s *sealedtree.SQLStore, id string) (sealedtree.VisibleObject, sealedtree.VisibleObject, error) {
	return s.ReadLinkedVisibleLyricWithLease(ctx, v.lease, id)
}
func (v legacyTreeReader) SelectLyricForDisplay(ctx context.Context, s *sealedtree.SQLStore, id string) (sealedtree.LyricSelection, error) {
	return s.SelectLyricForDisplayWithLease(ctx, v.lease, id)
}
func (v legacyTreeReader) ReadListingObject(ctx context.Context, s *sealedtree.SQLStore, id string, includeHidden bool) (sealedtree.ListingObject, error) {
	return s.ReadListingObjectWithLease(ctx, v.lease, id, includeHidden)
}

func (v legacyTreeReader) ReadListingObjectByAlias(ctx context.Context, s *sealedtree.SQLStore, alias string, includeHidden bool) (sealedtree.ListingObject, error) {
	return s.ReadListingObjectByAliasWithLease(ctx, v.lease, alias, includeHidden)
}

func (v legacyTreeReader) ReadS3ListingObject(ctx context.Context, s *sealedtree.SQLStore, id string, includeHidden bool) (sealedtree.S3ListingObject, error) {
	return s.ReadS3ListingObjectWithLease(ctx, v.lease, id, includeHidden)
}

func ingressTreeAuthority(ctx context.Context) (ingressTreeReader, bool) {
	p, ok := store.IngressPrerequisiteFromContext(ctx)
	if !ok {
		return nil, false
	}
	if reader, ok := p.(ingressTreeReader); ok && reader != nil {
		value := reflect.ValueOf(reader)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, false
			}
		}
		return reader, true
	}
	if lease, ok := p.(*sealedtree.TreeLease); ok && lease != nil {
		return legacyTreeReader{lease}, true
	}
	return nil, false
}
