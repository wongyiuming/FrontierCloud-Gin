package media

import "context"

// AdminResourceContext is installed only after the Master has authenticated
// its own management session. HTTP headers or browser parameters cannot set
// this process-local marker.
type adminResourceKey struct{}

func AdminResourceContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, adminResourceKey{}, true)
}

func IsAdminResourceContext(ctx context.Context) bool {
	value, _ := ctx.Value(adminResourceKey{}).(bool)
	return value
}
