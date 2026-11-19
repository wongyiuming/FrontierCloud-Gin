package publicproxy

import (
	"bytes"
	"errors"
	"net/http"
	"time"
)

// Directory metadata may be substantially larger than key envelopes. This is
// an explicit bounded proxy limit, not a claim that catalogs are size-limited.
// Larger responses fail without exposing a partial response or authorization.
const maxBusinessResponse = 8 << 20

// Bound buffered responses across verifier instances, including SQLite, while
// reserving independent capacity for small key responses. Waiting happens
// before obtaining the ingress lease.
var keyAdmissionSlots = make(chan struct{}, 4)
var businessAdmissionSlots = make(chan struct{}, 4)

func admissionLimit(path string) (int, bool) {
	if method, _ := recordingControl(path); method != "" {
		return recordingControlLimit(path), true
	}
	if pageRoute(path) || assetRoute(path) {
		return maxBusinessResponse, true
	}
	switch path {
	case "/", "/api/v1/media/project-diagnostics", "/api/v1/media/refresh", "/api/v1/media/crypto/session", "/api/v1/media/crypto/key", "/api/v1/media/crypto/native/source", "/api/v1/media/admin-handoff/authorize":
		return maxKeyResponse, true
	case "/api/v1/media/catalog/categories", "/api/v1/media/catalog/media", "/api/v1/media/catalog/artwork", "/api/v1/media/metadata", "/api/v1/media/lyrics/content", "/api/v1/karaoke/context", "/api/v1/karaoke/lyrics":
		return maxBusinessResponse, true
	default:
		return 0, false
	}
}

type admissionResponse struct {
	header       http.Header
	committed    http.Header
	body         bytes.Buffer
	status       int
	limit        int
	failed       bool
	readDeadline func(time.Time) error
}

func newAdmissionResponse(limit int) *admissionResponse {
	return &admissionResponse{header: make(http.Header), limit: limit}
}

func (b *admissionResponse) Header() http.Header { return b.header }

func (b *admissionResponse) SetReadDeadline(deadline time.Time) error {
	if b.readDeadline == nil {
		return http.ErrNotSupported
	}
	return b.readDeadline(deadline)
}

func (b *admissionResponse) WriteHeader(status int) {
	if b.status != 0 {
		return
	}
	if status < 200 || status > 599 {
		b.failed = true
		return
	}
	b.status = status
	b.committed = b.header.Clone()
}

func (b *admissionResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.WriteHeader(http.StatusOK)
	}
	if b.failed || len(p) > b.limit-b.body.Len() {
		b.failed = true
		return 0, errors.New("public ingress response exceeds admission limit")
	}
	return b.body.Write(p)
}

// Only the buffered response is flushed; the real client remains untouched.
func (b *admissionResponse) Flush() {
	if b.status == 0 {
		b.WriteHeader(http.StatusOK)
	}
}

func (b *admissionResponse) send(w http.ResponseWriter) {
	if b.status == 0 {
		b.WriteHeader(http.StatusOK)
	}
	for name, values := range b.committed {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
