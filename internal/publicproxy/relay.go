package publicproxy

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const relayPrefix = "/api/v1/media/master-relay/"
const relayReadLimit = 30 * time.Minute

var relayBearer = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
var relayRange = regexp.MustCompile(`^bytes=([0-9]+-[0-9]*|-[0-9]+)$`)

func relayRoute(path string) bool {
	for _, prefix := range []string{relayPrefix, "/api/v1/media/follower-relay/", "/api/v1/media/opaque-follower-relay/"} {
		if strings.HasPrefix(path, prefix) && validHex(strings.TrimPrefix(path, prefix), 64) {
			return true
		}
	}
	return false
}

func (h *Handler) admitRelayBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	// A native HTTP/2 request can have a body reader even after END_STREAM.
	// Verify EOF before forwarding and bound slow readers separately from streams.
	select {
	case h.bodies <- struct{}{}:
		defer func() { <-h.bodies }()
	default:
		fail(w, http.StatusServiceUnavailable)
		return false
	}
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(bodyReadTimeout)); err != nil {
		fail(w, http.StatusServiceUnavailable)
		return false
	}
	defer controller.SetReadDeadline(time.Time{})
	var probe [1]byte
	if _, err := io.ReadFull(r.Body, probe[:]); err != io.EOF {
		fail(w, http.StatusBadRequest)
		return false
	}
	return true
}

// serveRelay forwards only one resource identified by the path and an opaque
// Master-issued header. The caller cannot choose an upstream, and all bytes
// remain opaque. Separate slots and transport reserve control/key capacity.
func (h *Handler) serveRelay(w http.ResponseWriter, r *http.Request) {
	values := r.Header.Values("X-Media-Relay")
	if len(values) != 1 || len(values[0]) > 4096 || !relayBearer.MatchString(values[0]) || len(r.Header.Values("Range")) > 1 || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		fail(w, http.StatusBadRequest)
		return
	}
	if value := r.Header.Get("Range"); value != "" && (len(value) > 128 || !relayRange.MatchString(value)) {
		fail(w, http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if !h.admitRelayBody(w, r) {
		return
	}
	select {
	case h.relays <- struct{}{}:
		defer func() { <-h.relays }()
	default:
		fail(w, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), relayReadLimit)
	defer cancel()
	target := *h.master
	target.Path = r.URL.Path
	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), nil)
	if err != nil {
		fail(w, http.StatusBadGateway)
		return
	}
	out.Host = h.public.Host
	for _, name := range []string{"Origin", "Sec-Fetch-Site", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "X-Media-Relay"} {
		for _, value := range r.Header.Values(name) {
			out.Header.Add(name, value)
		}
	}
	if err = h.seal(ctx, out, nil, r); err != nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	if h.masterEdge {
		out.URL.Path = EdgePrefix + out.URL.Path
	}
	response, err := h.relayTransport.RoundTrip(out)
	if err != nil {
		fail(w, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if !validConnection(response.Header) || response.StatusCode >= 300 && response.StatusCode < 400 || response.ProtoMajor == 1 && response.ContentLength < 0 && len(response.TransferEncoding) == 0 {
		fail(w, http.StatusBadGateway)
		return
	}
	controller := http.NewResponseController(w)
	if err = controller.SetWriteDeadline(time.Now().Add(relayReadLimit)); err != nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Retry-After"} {
		for _, value := range response.Header.Values(name) {
			w.Header().Add(name, value)
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(response.StatusCode)
	if _, err := io.CopyBuffer(flushWriter{w: w, controller: controller}, readerOnly{response.Body}, make([]byte, 32<<10)); err != nil {
		panic(http.ErrAbortHandler)
	}
}
