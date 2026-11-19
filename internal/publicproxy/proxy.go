// Package publicproxy implements bounded public business forwarding and the
// versioned node-authenticated peer protocol. It does not activate an ingress
// or register routes. Master must mount its verifier on a dedicated trusted
// listener and read current Master-owned ingress state on every request.
package publicproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/net/idna"
)

const (
	maxRequestBody             = 8192
	maxQuery                   = 4096
	maxHeaderValue             = 8192
	requestTimeout             = 30 * time.Second
	bodyReadTimeout            = 5 * time.Second
	keyUpstreamTimeout         = 5 * time.Second
	keyQueueTimeout            = 7 * time.Second
	assetQueueTimeout          = 2 * time.Second
	maxKeyResponse             = 64 << 10
	bodySlots                  = 16
	businessSlots              = 8
	assetWaitSlots             = 8
	keySlots                   = 4
	keyResponseSlots           = 8
	recordingsPath             = "/api/v1/karaoke/account/recordings"
	recordingTicketPath        = recordingsPath + "/ticket"
	recordingAudioPreparePath  = recordingsPath + "/crypto/audio-prepare"
	recordingSessionHeader     = "X-Fc-Recording-Session"
	brandLogoPrefix            = "/api/v1/media/brand/logo/"
	recordingTicketTimeout     = 2 * time.Minute
	recordingTicketReadTimeout = 45 * time.Second
)

// These bounded slots are shared across proxy/verifier instances, including
// instances retiring after an ingress change. Tickets and deletion share
// this separate, bounded capacity for longer recording controls.
var recordingTicketIngressSlot = make(chan struct{}, 1)
var recordingTicketMasterSlot = make(chan struct{}, 1)

// Config must come from controlled deployment configuration, never a browser
// request. RootCAs, when provided, is a controlled trust store; certificate
// hostname and chain verification are always enabled.
type Config struct {
	MasterOrigin string
	PublicOrigin string
	RootCAs      *x509.CertPool
	Peer         *PeerConfig
	// MasterEdge uses the dedicated Master gateway path instead of public
	// routes, so Nginx cannot intercept signed static requests with aliases.
	MasterEdge bool
	// RecordingControlsReady is set only by startup after the Direct
	// recording lifecycle and its recovery paths are installed.
	RecordingControlsReady bool
}

type route struct {
	method, path string
	key          bool
}

// Deliberately excludes Admin, internal APIs and resource-byte routes. The
// latter need the separate owner/Local/Direct/Relay authorization protocol.
// Adding a route requires a review of its methods, payload and response.
var routes = [...]route{
	{http.MethodGet, "/", false},
	{http.MethodGet, "/api/v1/media", false},
	{http.MethodGet, "/api/v1/media/", false},
	{http.MethodGet, "/api/v1/media/refresh", false},
	{http.MethodGet, "/api/v1/media/music", false},
	{http.MethodGet, "/api/v1/media/video", false},
	{http.MethodGet, "/api/v1/media/music/category", false},
	{http.MethodGet, "/api/v1/media/video/category", false},
	{http.MethodGet, "/api/v1/media/catalog/categories", false},
	{http.MethodGet, "/api/v1/media/catalog/media", false},
	{http.MethodGet, "/api/v1/media/catalog/artwork", false},
	{http.MethodGet, "/api/v1/media/metadata", false},
	{http.MethodGet, "/api/v1/media/lyrics/content", false},
	{http.MethodGet, "/api/v1/media/lyrics", false},
	{http.MethodGet, "/karaoke/", false},
	{http.MethodGet, "/api/v1/karaoke/context", false},
	{http.MethodGet, "/api/v1/karaoke/lyrics", false},
	{http.MethodGet, "/api/v1/karaoke/account/captcha", false},
	{http.MethodGet, "/api/v1/karaoke/account/status", false},
	{http.MethodGet, recordingsPath, false},
	{http.MethodPost, "/api/v1/karaoke/account/register", false},
	{http.MethodPost, "/api/v1/karaoke/account/login", false},
	{http.MethodPost, "/api/v1/karaoke/account/logout", false},
	{http.MethodPost, "/api/v1/karaoke/account/password", false},
	{http.MethodDelete, "/api/v1/karaoke/account", false},
	{http.MethodPost, "/api/v1/media/playback", false},
	{http.MethodPost, "/api/v1/media/network-observation", false},
	{http.MethodGet, "/api/v1/media/project-diagnostics", false},
	{http.MethodPost, "/api/v1/media/project-diagnostics", false},
	{http.MethodPost, "/api/v1/media/crypto/session", true},
	{http.MethodPost, "/api/v1/media/crypto/key", true},
	{http.MethodPost, "/api/v1/media/crypto/native/source", true},
	{http.MethodPost, "/api/v1/media/crypto/revoke", true},
	{http.MethodPost, "/api/v1/media/admin-handoff/authorize", false},
}

func sensitiveRoute(item route) bool {
	return item.key || item.path == "/api/v1/media/admin-handoff/authorize" || karaokeAccountRoute(item.path)
}

func requestBodyLimit(path string) int64 {
	if path == recordingTicketPath {
		// The sealed ticket handler uses the smaller 8 KiB JSON contract.
		// The legacy account ticket still accepts a lyric snapshot.
		return int64(store.MaxRecordingMetadata + 8192)
	}
	if path == "/api/v1/media/network-observation" || path == "/api/v1/media/project-diagnostics" {
		return 16 << 10
	}
	if method, _ := recordingControl(path); method == http.MethodDelete {
		return 0
	}
	return int64(maxRequestBody)
}

// recordingControl permits only the exact Direct recording control surface.
// In particular, recording audio bytes never use this business proxy.
func recordingControl(path string) (method string, needsSession bool) {
	if path == recordingTicketPath || path == recordingAudioPreparePath {
		return http.MethodPost, false
	}
	tail, ok := strings.CutPrefix(path, recordingsPath+"/")
	if !ok {
		return "", false
	}
	id, suffix, separated := strings.Cut(tail, "/")
	if !validHex(id, 32) {
		return "", false
	}
	if !separated {
		return http.MethodDelete, true
	}
	switch suffix {
	case "pending":
		return http.MethodDelete, true
	case "audio-recover", "audio-complete":
		return http.MethodPost, true
	case "audio-key", "lyrics-key":
		return http.MethodPost, false
	default:
		return "", false
	}
}

func recordingControlLimit(path string) int {
	if strings.HasSuffix(path, "/lyrics-key") {
		return store.MaxRecordingMetadata + maxKeyResponse
	}
	return maxKeyResponse
}

// Only exact relative navigation and versioned logo targets are allowed.
func validNavigationResponse(path string, resp *http.Response) bool {
	if path != "/" && path != "/api/v1/media/refresh" {
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return true
		}
		if resp.StatusCode != http.StatusTemporaryRedirect || !strings.HasPrefix(path, brandLogoPrefix) || !assetRoute(path) {
			return false
		}
		locations := resp.Header.Values("Location")
		if len(locations) != 1 {
			return false
		}
		version, ok := strings.CutPrefix(locations[0], path+"?v=")
		return ok && validHex(version, 16)
	}
	if resp.StatusCode >= 400 {
		return true
	}
	locations := resp.Header.Values("Location")
	if len(locations) != 1 {
		return false
	}
	if path == "/" {
		return resp.StatusCode == http.StatusTemporaryRedirect && locations[0] == "/api/v1/media"
	}
	const prefix = "/api/v1/media?ui="
	location := locations[0]
	if resp.StatusCode != http.StatusSeeOther || len(location) != len(prefix)+32 || !strings.HasPrefix(location, prefix) {
		return false
	}
	for _, c := range location[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	clear := resp.Header.Values("Clear-Site-Data")
	return len(clear) == 1 && clear[0] == `"cache"`
}

// Account operations are a separate public business surface, not Admin.
// Only the generated 128-bit lowercase captcha ID is a parameterized path.
func karaokeAccountRoute(path string) bool {
	switch path {
	case "/api/v1/karaoke/account", "/api/v1/karaoke/account/captcha", "/api/v1/karaoke/account/status", "/api/v1/karaoke/account/register", "/api/v1/karaoke/account/login", "/api/v1/karaoke/account/logout", "/api/v1/karaoke/account/password":
		return true
	}
	const prefix = "/api/v1/karaoke/account/captcha/"
	if !strings.HasPrefix(path, prefix) || len(path) != len(prefix)+32 {
		return false
	}
	for _, ch := range path[len(prefix):] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func karaokeCredentialsRoute(path string) bool {
	method, _ := recordingControl(path)
	return karaokeAccountRoute(path) || path == recordingsPath || method != ""
}

// These pages are rendered by the Master, including its per-response CSP
// nonce. Resource bytes and administration endpoints are deliberately absent.
func pageRoute(path string) bool {
	switch path {
	case "/api/v1/media", "/api/v1/media/", "/api/v1/media/music", "/api/v1/media/video", "/api/v1/media/music/category", "/api/v1/media/video/category", "/api/v1/media/lyrics", "/karaoke/":
		return true
	default:
		return false
	}
}

// Only public player assets are eligible; this must never become a wildcard
// for the static tree, which also contains administrative code and templates.
var publicAssets = map[string]struct{}{
	"/media-crypto-sw.js": {}, "/favicon.ico": {},
	"/static/css/player.css": {}, "/static/css/lyrics.css": {},
	"/static/css/lyrics-window.css": {}, "/static/css/directory-globe.css": {},
	"/static/css/karaoke.css": {},
	"/static/js/player.js":    {}, "/static/js/lyrics.js": {},
	"/static/js/karaoke.js": {}, "/static/js/karaoke-audio-quality.js": {}, "/static/js/karaoke-ui.js": {}, "/static/js/upload-sha256.js": {},
	brandLogoPrefix + "entertainment": {}, brandLogoPrefix + "music": {}, brandLogoPrefix + "media": {},
	"/static/js/lyrics-window.js": {}, "/static/js/media-browser.js": {},
	"/static/js/business-navigation.js": {}, "/static/js/directory-globe.js": {},
	"/static/js/music-metadata.js": {}, "/static/js/network-observation.js": {},
	"/static/js/player-directory-label.js": {}, "/static/js/audio-continuous-stream.js": {},
	"/static/js/playback-continuity-diagnostics.js": {},
	"/static/js/compiled/media-crypto-common.js":    {}, "/static/js/compiled/media-crypto.js": {},
}

func assetRoute(path string) bool { _, ok := publicAssets[path]; return ok }

// Cache only versioned public CSS/JS, never pages, keys, logos or the worker.
func versionedPublicAsset(r *http.Request, resp *http.Response) bool {
	if r.Method != http.MethodGet || !assetRoute(r.URL.Path) || !strings.HasPrefix(r.URL.Path, "/static/") ||
		!(strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js")) ||
		resp.StatusCode != http.StatusOK || len(resp.Header.Values("Set-Cookie")) != 0 {
		return false
	}
	mime := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if strings.HasSuffix(r.URL.Path, ".css") && mime != "text/css" ||
		strings.HasSuffix(r.URL.Path, ".js") && mime != "text/javascript" && mime != "application/javascript" {
		return false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["v"]) != 1 || len(query.Get("v")) != 16 {
		return false
	}
	for _, c := range query.Get("v") {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Handler fails closed without an explicitly configured peer signer and
// applied ingress generation. The Master verifier remains authoritative.
type Handler struct {
	master          *url.URL
	public          *url.URL
	transport       *http.Transport
	relayTransport  *http.Transport
	ticketTransport *http.Transport
	relays          chan struct{}
	bodies          chan struct{}
	business        chan struct{}
	assetWaiters    chan struct{}
	keys            chan struct{}
	keyResponses    chan struct{}
	seal            func(context.Context, *http.Request, []byte, *http.Request) error
	masterEdge      bool
	// Not wired by production: the full recording upload lifecycle must be
	// installed and verified before this can ever become true.
	recordingTicketReady bool
}

// New validates both origins. A nil Peer returns an inert handler.
func New(c Config) (*Handler, error) {
	master, err := origin(c.MasterOrigin)
	if err != nil {
		return nil, errors.New("invalid Master origin")
	}
	public, err := origin(c.PublicOrigin)
	if err != nil {
		return nil, errors.New("invalid public origin")
	}
	if c.Peer != nil && strings.EqualFold(master.Host, public.Host) {
		return nil, errors.New("Master and ingress origins must be distinct")
	}
	seal, err := peerSeal(c.Peer, master, public)
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if c.RootCAs != nil {
		roots = c.RootCAs.Clone()
	}
	tr := &http.Transport{
		Proxy:                  nil, // Never inherit a proxy or destination from the environment.
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           12,
		MaxIdleConnsPerHost:    12,
		MaxConnsPerHost:        12,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
	}
	if c.Peer != nil {
		tr.DialContext = c.Peer.Signer.DialPublicIngress
	}
	relayTransport := tr.Clone()
	relayTransport.MaxConnsPerHost = 4
	relayTransport.MaxIdleConns = 4
	relayTransport.MaxIdleConnsPerHost = 4
	ticketTransport := tr.Clone()
	ticketTransport.ResponseHeaderTimeout = recordingTicketTimeout
	ticketTransport.MaxConnsPerHost = 1
	ticketTransport.MaxIdleConns = 1
	ticketTransport.MaxIdleConnsPerHost = 1
	return &Handler{master: master, public: public, transport: tr, relayTransport: relayTransport, ticketTransport: ticketTransport,
		relays: make(chan struct{}, 4), bodies: make(chan struct{}, bodySlots), business: make(chan struct{}, businessSlots),
		assetWaiters: make(chan struct{}, assetWaitSlots), keys: make(chan struct{}, keySlots), keyResponses: make(chan struct{}, keyResponseSlots),
		seal: seal, masterEdge: c.MasterEdge, recordingTicketReady: c.RecordingControlsReady}, nil
}

func origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("invalid origin")
	}
	if strings.ContainsAny(u.Host, "\\\r\n\t ") {
		return nil, errors.New("invalid host")
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid port")
		}
		if n == 443 {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty port")
	}
	host := strings.ToLower(u.Hostname())
	if address, e := netip.ParseAddr(host); e == nil {
		if address.Zone() != "" {
			return nil, errors.New("invalid scoped host")
		}
		host = address.Unmap().String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || host == "" {
			return nil, errors.New("invalid host")
		}
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Path = ""
	return u, nil
}

// CloseIdleConnections releases pooled connections after a configuration swap.
func (h *Handler) CloseIdleConnections() {
	if h != nil && h.transport != nil {
		h.transport.CloseIdleConnections()
	}
	if h != nil && h.relayTransport != nil {
		h.relayTransport.CloseIdleConnections()
	}
	if h != nil && h.ticketTransport != nil {
		h.ticketTransport.CloseIdleConnections()
	}
}

func match(r *http.Request) (route, bool) {
	if r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || len(r.URL.RawQuery) > maxQuery {
		return route{}, false
	}
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		return route{}, false
	}
	if (r.URL.Path == "/" || r.URL.Path == "/api/v1/media/refresh") && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		return route{}, false
	}
	if method, _ := recordingControl(r.URL.Path); method != "" {
		if r.Method == method && r.URL.RawQuery == "" && !r.URL.ForceQuery {
			return route{method: method, path: r.URL.Path, key: true}, true
		}
		return route{}, false
	}
	for _, item := range routes {
		if r.Method == item.method && r.URL.Path == item.path {
			return item, true
		}
	}
	if r.Method == http.MethodGet && assetRoute(r.URL.Path) {
		return route{method: r.Method, path: r.URL.Path}, true
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/karaoke/account/captcha/") && karaokeAccountRoute(r.URL.Path) {
		return route{method: r.Method, path: r.URL.Path}, true
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && relayRoute(r.URL.Path) && r.URL.RawQuery == "" && !r.URL.ForceQuery {
		return route{method: r.Method, path: r.URL.Path}, true
	}
	return route{}, false
}

// Eligible identifies the narrowly reviewed public surface; callers must not
// route arbitrary storage, internal or administrative requests through it.
func Eligible(r *http.Request) bool { _, ok := match(r); return ok }

func fail(w http.ResponseWriter, code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, http.StatusText(code), code)
}

// A cold browser page can request more assets than the business concurrency
// limit allows. Briefly queue allowlisted assets without adding upstream work.
func (h *Handler) waitForAssetSlot(ctx context.Context) bool {
	select {
	case h.assetWaiters <- struct{}{}:
		defer func() { <-h.assetWaiters }()
	default:
		return false
	}
	waitCtx, cancel := context.WithTimeout(ctx, assetQueueTimeout)
	defer cancel()
	select {
	case <-waitCtx.Done():
		return false
	case h.business <- struct{}{}:
		if waitCtx.Err() != nil {
			<-h.business
			return false
		}
		return true
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	item, ok := match(r)
	if !ok {
		fail(w, http.StatusNotFound)
		return
	}
	if len(r.Header.Values("X-Fc-Public-Hop")) > 0 {
		fail(w, http.StatusForbidden)
		return
	}
	if h == nil || h.seal == nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	recordingMethod, needsRecordingSession := recordingControl(item.path)
	longRecordingControl := item.path == recordingTicketPath || recordingMethod == http.MethodDelete
	if recordingMethod != "" && !h.recordingTicketReady {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	if longRecordingControl {
		select {
		case recordingTicketIngressSlot <- struct{}{}:
			defer func() { <-recordingTicketIngressSlot }()
		default:
			fail(w, http.StatusServiceUnavailable)
			return
		}
	}
	if _, exists := network.AuthenticatedIngressFromContext(r.Context()); exists {
		fail(w, http.StatusForbidden)
		return
	}
	if !strings.EqualFold(r.Host, h.public.Host) || !validClientHeaders(r.Header, h.public, item) {
		fail(w, http.StatusForbidden)
		return
	}
	if needsRecordingSession && !validRecordingSession(r.Header) {
		fail(w, http.StatusForbidden)
		return
	}
	if relayRoute(item.path) {
		h.serveRelay(w, r)
		return
	}
	bodyLimit := requestBodyLimit(item.path)
	if r.ContentLength > bodyLimit || (r.Method == http.MethodGet && r.ContentLength > 0) || recordingMethod == http.MethodDelete && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		fail(w, http.StatusRequestEntityTooLarge)
		return
	}
	controller := http.NewResponseController(w)
	timeout, readTimeout := requestTimeout, bodyReadTimeout
	if longRecordingControl {
		timeout, readTimeout = recordingTicketTimeout, recordingTicketReadTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		// Slow uploads use their own bounded admission and cannot occupy key
		// processing slots. A read deadline bounds each admitted upload.
		bodySlotHeld := false
		if !longRecordingControl {
			select {
			case h.bodies <- struct{}{}:
				bodySlotHeld = true
			default:
				fail(w, http.StatusServiceUnavailable)
				return
			}
		}
		if err := controller.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			if bodySlotHeld {
				<-h.bodies
			}
			fail(w, http.StatusServiceUnavailable)
			return
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
		_ = controller.SetReadDeadline(time.Time{})
		if bodySlotHeld {
			<-h.bodies
		}
		if err != nil {
			fail(w, http.StatusBadRequest)
			return
		}
		if int64(len(body)) > bodyLimit || (r.Method == http.MethodGet && len(body) != 0) {
			fail(w, http.StatusRequestEntityTooLarge)
			return
		}
	}
	// Limit the number of buffered key responses, including writes to slow
	// clients. This admission is separate from key processing slots.
	if sensitiveRoute(item) && !longRecordingControl {
		select {
		case h.keyResponses <- struct{}{}:
			defer func() { <-h.keyResponses }()
		default:
			fail(w, http.StatusServiceUnavailable)
			return
		}
	}
	var slots chan struct{}
	held := false
	if longRecordingControl {
		// The process-wide ticket slot already bounds the full request and
		// response, leaving ordinary business/key capacity independent.
	} else if sensitiveRoute(item) {
		slots = h.keys
		waitCtx, stopWait := context.WithTimeout(ctx, keyQueueTimeout)
		defer stopWait()
		select {
		case slots <- struct{}{}:
			held = true
		case <-waitCtx.Done():
			fail(w, http.StatusServiceUnavailable)
			return
		}
	} else {
		slots = h.business
		select {
		case slots <- struct{}{}:
			held = true
		default:
			if !assetRoute(item.path) || !h.waitForAssetSlot(ctx) {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			held = true
		}
	}
	defer func() {
		if held {
			<-slots
		}
	}()
	if sensitiveRoute(item) && !karaokeAccountRoute(item.path) && !longRecordingControl {
		var stopUpstream context.CancelFunc
		ctx, stopUpstream = context.WithTimeout(ctx, keyUpstreamTimeout)
		defer stopUpstream()
	}
	target := *h.master
	target.Path, target.RawQuery = r.URL.Path, r.URL.RawQuery
	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		fail(w, http.StatusBadGateway)
		return
	}
	// The public Host is controlled configuration, not the incoming Host. The
	// future Master verifier must authenticate it as part of ingress context.
	out.Host = h.public.Host
	for _, name := range []string{"Accept", "Accept-Language", "Content-Type", "Origin", "Sec-Fetch-Site", "Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		if assetRoute(item.path) && (name == "If-None-Match" || name == "If-Modified-Since") {
			continue // A 304 is not a complete response through this proxy.
		}
		for _, value := range r.Header.Values(name) {
			out.Header.Add(name, value)
		}
	}
	if crossOriginFetchSite(r.Header.Get("Sec-Fetch-Site")) {
		out.Header.Set(fetchModeHeader, "navigate")
		out.Header.Set(fetchDestHeader, "document")
	}
	if karaokeCredentialsRoute(item.path) {
		if value := r.Header.Get("X-Karaoke-CSRF"); value != "" {
			out.Header.Set("X-Karaoke-CSRF", value)
		}
	}
	if needsRecordingSession {
		out.Header.Set(recordingSessionHeader, r.Header.Get(recordingSessionHeader))
	}
	if item.key {
		var count int
		for _, cookie := range r.Cookies() {
			if cookie.Name == "frontiercloud_browser_crypto" {
				count++
				if count > 1 || len(cookie.Value) > 256 {
					fail(w, http.StatusBadRequest)
					return
				}
				out.AddCookie(cookie)
			}
		}
	}
	if karaokeCredentialsRoute(item.path) {
		seen := map[string]bool{}
		for _, cookie := range r.Cookies() {
			if cookie.Name != "__Host-karaoke_session" && cookie.Name != "__Host-karaoke_csrf" {
				continue
			}
			if seen[cookie.Name] || len(cookie.Value) > 256 {
				fail(w, http.StatusBadRequest)
				return
			}
			seen[cookie.Name] = true
			out.AddCookie(cookie)
		}
	}
	// Sign the filtered browser context and body before contacting Master.
	if err := h.seal(ctx, out, body, r); err != nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	if h.masterEdge {
		out.URL.Path = EdgePrefix + out.URL.Path
	}
	transport := h.transport
	if longRecordingControl {
		transport = h.ticketTransport
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		fail(w, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// Only the validated relative redirects may be forwarded.
	if !validConnection(resp.Header) || !validNavigationResponse(item.path, resp) {
		fail(w, http.StatusBadGateway)
		return
	}
	// A page's nonce is meaningful only together with its original CSP. Never
	// serve a successful HTML response after dropping or duplicating it.
	if pageRoute(item.path) && resp.StatusCode == http.StatusOK && (len(resp.Header.Values("Content-Security-Policy")) != 1 || resp.Header.Get("Content-Security-Policy") == "") {
		fail(w, http.StatusBadGateway)
		return
	}
	if item.path == "/media-crypto-sw.js" && resp.StatusCode >= 200 && resp.StatusCode < 300 && (resp.StatusCode != http.StatusOK || len(resp.Header.Values("Content-Security-Policy")) != 1 || resp.Header.Get("Content-Security-Policy") == "" || len(resp.Header.Values("Service-Worker-Allowed")) != 1 || resp.Header.Get("Service-Worker-Allowed") != "/") {
		fail(w, http.StatusBadGateway)
		return
	}
	// A close-delimited HTTP/1 body has no framing that distinguishes a
	// complete response from a broken connection. Do not turn that ambiguity
	// into a successful downstream EOF. HTTP/2 has explicit stream framing.
	if resp.ProtoMajor == 1 && resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
		fail(w, http.StatusBadGateway)
		return
	}
	var keyBody []byte
	if sensitiveRoute(item) {
		// Key envelopes are small. Read them completely before releasing the
		// processing slot, so slow downstream clients cannot retain it.
		limit := recordingControlLimit(item.path)
		keyBody, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
		_ = resp.Body.Close()
		if held {
			<-slots
			held = false
		}
		if err != nil || len(keyBody) > limit {
			fail(w, http.StatusBadGateway)
			return
		}
	}
	if err := controller.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		fail(w, http.StatusServiceUnavailable)
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified", "Retry-After"} {
		for _, value := range resp.Header.Values(name) {
			w.Header().Add(name, value)
		}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		w.Header().Set("Location", resp.Header.Get("Location"))
		if item.path == "/api/v1/media/refresh" {
			w.Header().Set("Clear-Site-Data", `"cache"`)
		}
	}
	if pageRoute(item.path) {
		for _, name := range []string{"Content-Security-Policy", "Permissions-Policy", "X-Frame-Options"} {
			for _, value := range resp.Header.Values(name) {
				w.Header().Add(name, value)
			}
		}
	}
	if item.path == "/media-crypto-sw.js" {
		w.Header().Set("Content-Security-Policy", resp.Header.Get("Content-Security-Policy"))
		w.Header().Set("Service-Worker-Allowed", resp.Header.Get("Service-Worker-Allowed"))
	}
	if item.key {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "frontiercloud_browser_crypto" && cookie.Domain == "" && cookie.Path == "/" && cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode && len(cookie.Value) <= 256 {
				http.SetCookie(w, cookie)
			}
		}
	}
	if karaokeAccountRoute(item.path) {
		for _, cookie := range resp.Cookies() {
			if (cookie.Name == "__Host-karaoke_session" || cookie.Name == "__Host-karaoke_csrf") && cookie.Domain == "" && cookie.Path == "/" && cookie.Secure && cookie.SameSite == http.SameSiteLaxMode && cookie.HttpOnly == (cookie.Name == "__Host-karaoke_session") && len(cookie.Value) <= 256 {
				http.SetCookie(w, cookie)
			}
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	if versionedPublicAsset(r, resp) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Del("Pragma")
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	var responseBody io.Reader = resp.Body
	if sensitiveRoute(item) {
		responseBody = bytes.NewReader(keyBody)
	}
	if _, err := io.CopyBuffer(flushWriter{w: w, controller: controller}, readerOnly{responseBody}, make([]byte, 32<<10)); err != nil {
		// Headers are already committed. Abort the stream so truncation cannot
		// appear as a complete response when no Content-Length was supplied.
		panic(http.ErrAbortHandler)
	}
}

// Hide optional WriterTo methods to keep the fixed-size copy buffer and
// synchronous downstream writes in control of the stream.
type readerOnly struct{ io.Reader }

// Flush each bounded chunk so clients can consume a response before the
// upstream finishes. Writes remain synchronous and apply downstream pressure.
type flushWriter struct {
	w          http.ResponseWriter
	controller *http.ResponseController
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err != nil {
		return n, err
	}
	if err = w.controller.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

const (
	fetchModeHeader = "Sec-Fetch-Mode"
	fetchDestHeader = "Sec-Fetch-Dest"
)

func crossOriginFetchSite(site string) bool {
	return site == "same-site" || site == "cross-site"
}

func validClientHeaders(h http.Header, public *url.URL, item route) bool {
	// Bound all headers, including fields that will never be forwarded.
	size := 0
	for name, values := range h {
		if len(name) > 256 {
			return false
		}
		size += len(name)
		for _, value := range values {
			if len(value) > maxHeaderValue {
				return false
			}
			size += len(value)
			if size > 32<<10 {
				return false
			}
		}
	}
	for _, name := range []string{"Origin", "Sec-Fetch-Site", "Content-Type", "Range", "If-Range", "X-Karaoke-CSRF"} {
		if len(h.Values(name)) > 1 {
			return false
		}
	}
	for _, name := range []string{"Accept", "Accept-Language", "Content-Type", "Origin", "Sec-Fetch-Site", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "X-Karaoke-CSRF"} {
		for _, value := range h.Values(name) {
			if len(value) > maxHeaderValue || strings.ContainsAny(value, "\r\n\x00") {
				return false
			}
		}
	}
	if value := h.Get("Origin"); value != "" && value != public.String() {
		return false
	}
	if site := h.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		// Only public top-level page navigation may cross origins.
		mode, dest := h.Values(fetchModeHeader), h.Values(fetchDestHeader)
		if !crossOriginFetchSite(site) || item.method != http.MethodGet || (item.path != "/" && !pageRoute(item.path)) ||
			len(h.Values("Origin")) != 0 || len(mode) != 1 || mode[0] != "navigate" || len(dest) != 1 || dest[0] != "document" {
			return false
		}
	}
	return validConnection(h)
}

func validRecordingSession(h http.Header) bool {
	sessions := h.Values(recordingSessionHeader)
	return len(sessions) == 1 && validHex(sessions[0], 32)
}

func validConnection(h http.Header) bool {
	for _, line := range h.Values("Connection") {
		for _, token := range strings.Split(line, ",") {
			token = strings.TrimSpace(strings.ToLower(token))
			if token != "close" && token != "keep-alive" {
				return false
			}
		}
	}
	return true
}
