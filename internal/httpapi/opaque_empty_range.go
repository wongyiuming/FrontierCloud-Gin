package httpapi

import "net/http"

// Nginx's historical X-Accel handler ignores ranges on empty files. Keep
// that deployment's response semantics while Go-only deployments retain
// ServeContent's existing empty suffix-range behaviour.
func opaqueEmptyRangeRequest(r *http.Request, size int64, nginxMedia bool) *http.Request {
	if r == nil || size != 0 || !nginxMedia || r.Header.Get("Range") == "" {
		return r
	}
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Del("Range")
	return clone
}
