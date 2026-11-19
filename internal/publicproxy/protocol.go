package publicproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Node authentication uses a separate fixed domain, not a publicly routable
// endpoint. The signed payload contains only hashes of browser credentials.
const ProofDomain = "/internal/v1/public-ingress-proof"
const proofVersion = 1

type masterIngressRejection struct {
	stage string
	next  atomic.Int64
}

var (
	masterIngressDiagnosticStart = time.Now()
	masterIngressEdge            = masterIngressRejection{stage: "edge_boundary"}
	masterIngressProofHeaders    = masterIngressRejection{stage: "proof_headers"}
	masterIngressProofOrigin     = masterIngressRejection{stage: "proof_origin"}
	masterIngressProofFormat     = masterIngressRejection{stage: "proof_format"}
	masterIngressActiveLease     = masterIngressRejection{stage: "active_lease"}
	masterIngressStaleTuple      = masterIngressRejection{stage: "stale_tuple"}
	masterIngressNodeAuth        = masterIngressRejection{stage: "node_authentication"}
)

func (r *masterIngressRejection) log() {
	now, next := time.Since(masterIngressDiagnosticStart).Nanoseconds(), r.next.Load()
	if now >= next && r.next.CompareAndSwap(next, now+int64(10*time.Second)) {
		slog.Warn("Master public ingress rejected", "stage", r.stage)
	}
}

func (r *masterIngressRejection) reject(w http.ResponseWriter) {
	r.log()
	fail(w, http.StatusForbidden)
}

// LogMasterIngressEdgeRejection records a request rejected before verification.
func LogMasterIngressEdgeRejection() {
	masterIngressEdge.log()
}

// EdgePrefix isolates signed peer forwarding from Nginx's public asset aliases.
// It is stripped before the logical request is authenticated and dispatched.
const EdgePrefix = "/_fc_public_proxy"

var nodeAuthHeaders = [...]string{"X-Node-Relationship", "X-Node-Time", "X-Node-Nonce", "X-Node-Signature"}
var signedHeaders = [...]string{"Accept", "Accept-Language", "Content-Type", "Origin", "Sec-Fetch-Site", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "Cookie", "X-Media-Relay", "X-Karaoke-CSRF", recordingSessionHeader}

// PeerSigner must use the existing active, paired upstream node relationship,
// and sign only this protocol's domain; it must never expose its credential.
type PeerSigner interface {
	SignPublicIngress(context.Context, string, []byte) (http.Header, error)
	DialPublicIngress(context.Context, string, string) (net.Conn, error)
}

// PeerConfig is explicit applied configuration for the ingress process. It is
// not authority to activate the peer: Master verifies its own current state.
type PeerConfig struct {
	NodeID               string
	Generation           int64
	Signer               PeerSigner
	TrustedProxyNetworks []string
}

// SigningProof has no session or key material. BrowserHeaderHash binds the
// exact filtered cookie, Origin, fetch metadata and other forwarded headers.
type SigningProof struct {
	Version           int    `json:"version"`
	IngressID         string `json:"ingress_id"`
	Generation        int64  `json:"generation"`
	PublicOrigin      string `json:"public_origin"`
	MasterOrigin      string `json:"master_origin"`
	ClientIP          string `json:"client_ip"`
	Method            string `json:"method"`
	RequestURI        string `json:"request_uri"`
	BodyHash          string `json:"body_sha256"`
	BrowserHeaderHash string `json:"browser_headers_sha256"`
}

type headerValue struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func browserHash(h http.Header) string {
	values := make([]headerValue, 0, len(signedHeaders))
	for _, name := range signedHeaders {
		v := append([]string{}, h.Values(name)...)
		// The new recording header extends the proof only for requests that
		// carry it. All existing no-session proofs keep their wire format.
		if name == recordingSessionHeader && len(v) == 0 {
			continue
		}
		values = append(values, headerValue{Name: name, Values: v})
	}
	// Preserve the existing proof for requests outside the page exception.
	if crossOriginFetchSite(h.Get("Sec-Fetch-Site")) {
		for _, name := range [...]string{fetchModeHeader, fetchDestHeader} {
			values = append(values, headerValue{Name: name, Values: append([]string{}, h.Values(name)...)})
		}
	}
	raw, _ := json.Marshal(values)
	return digest(raw)
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidateSigningProof rejects malformed/non-canonical proof envelopes before
// a node service will use its paired credential to sign one.
func ValidateSigningProof(raw []byte) (SigningProof, error) {
	var p SigningProof
	bad := errors.New("invalid ingress proof")
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, &p) != nil {
		return SigningProof{}, bad
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) || p.Version != proofVersion || !validHex(p.IngressID, 32) || p.Generation <= 0 || !validHex(p.BodyHash, 64) || !validHex(p.BrowserHeaderHash, 64) {
		return SigningProof{}, bad
	}
	pub, e1 := origin(p.PublicOrigin)
	master, e2 := origin(p.MasterOrigin)
	if e1 != nil || e2 != nil || pub.String() != p.PublicOrigin || master.String() != p.MasterOrigin {
		return SigningProof{}, bad
	}
	ip, e := network.Normalize(p.ClientIP)
	addr, addrErr := netip.ParseAddr(ip)
	if e != nil || ip != p.ClientIP || addrErr != nil || addr.Unmap().IsUnspecified() {
		return SigningProof{}, bad
	}
	u, e := url.ParseRequestURI(p.RequestURI)
	if e != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.RequestURI() != p.RequestURI {
		return SigningProof{}, bad
	}
	if _, ok := match(&http.Request{Method: p.Method, URL: u}); !ok {
		return SigningProof{}, bad
	}
	return p, nil
}

func makeProof(nodeID string, generation int64, public, master *url.URL, clientIP string, req *http.Request, body []byte) ([]byte, error) {
	p := SigningProof{Version: proofVersion, IngressID: nodeID, Generation: generation, PublicOrigin: public.String(), MasterOrigin: master.String(), ClientIP: clientIP, Method: req.Method, RequestURI: req.URL.RequestURI(), BodyHash: digest(body), BrowserHeaderHash: browserHash(req.Header)}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if _, err = ValidateSigningProof(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func peerSeal(cfg *PeerConfig, master, public *url.URL) (func(context.Context, *http.Request, []byte, *http.Request) error, error) {
	if cfg == nil {
		return nil, nil
	}
	if !validHex(cfg.NodeID, 32) || cfg.Generation <= 0 || nilValue(cfg.Signer) {
		return nil, errors.New("invalid ingress identity")
	}
	resolver, err := network.New(cfg.TrustedProxyNetworks)
	if err != nil {
		return nil, errors.New("invalid trusted proxy configuration")
	}
	nodeID, generation, signer := cfg.NodeID, cfg.Generation, cfg.Signer
	return func(ctx context.Context, out *http.Request, body []byte, incoming *http.Request) error {
		identity := resolver.Resolve(incoming)
		// HTTP on a local loopback is not public HTTPS. TLS or a configured
		// trusted edge with one verified HTTPS assertion is required.
		if identity.TrustedHeaderMissing || (incoming.TLS == nil && !(identity.FromTrustedProxy && resolver.SecureAdmin(incoming))) {
			return errors.New("untrusted browser source")
		}
		ip, e := network.Normalize(identity.IP)
		if e != nil || ip == "0.0.0.0" || ip == "::" {
			return errors.New("invalid browser source")
		}
		proof, e := makeProof(nodeID, generation, public, master, ip, out, body)
		if e != nil {
			return e
		}
		headers, e := signer.SignPublicIngress(ctx, master.String(), proof)
		if e != nil || len(headers) != len(nodeAuthHeaders) {
			return errors.New("node signing unavailable")
		}
		for _, name := range nodeAuthHeaders {
			if len(headers.Values(name)) != 1 || headers.Get(name) == "" {
				return errors.New("invalid node proof")
			}
			out.Header.Set(name, headers.Get(name))
		}
		out.Header.Set("X-Fc-Public-Hop", "1")
		out.Header.Set("X-Fc-Public-Version", strconv.Itoa(proofVersion))
		out.Header.Set("X-Fc-Public-Ingress", nodeID)
		out.Header.Set("X-Fc-Public-Generation", strconv.FormatInt(generation, 10))
		out.Header.Set("X-Fc-Public-Origin", public.String())
		out.Header.Set("X-Fc-Public-Client-Ip", ip)
		return nil
	}, nil
}

// NodeAuthenticator is implemented by node.Service.Authenticate. Its normal
// relationship verification also reserves a durable nonce against replay.
type NodeAuthenticator interface {
	Authenticate(context.Context, http.Header, string, string, []byte, bool, bool) (store.Relationship, error)
}

// CurrentIngress holds a shared lease over Master-owned authoritative state;
// ingress selection commits acquire the corresponding exclusive lease.
// Commit must fail if the transaction holding the lease was disconnected.
type CurrentIngress interface {
	AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error)
}

type VerifierConfig struct {
	MasterOrigin  string
	Authenticator NodeAuthenticator
	Current       CurrentIngress
	// Optional, trusted startup-only read-only catalog implementation. Leave
	// unset until encrypted-tree writes, recovery, S3 and policy gates are met.
	CatalogPreparer CatalogPreparer
	// EdgeResolver is optional. When set, a configured trusted proxy may
	// attest HTTPS after terminating TLS; arbitrary forwarding headers cannot.
	EdgeResolver *network.Resolver
	// RecordingControlsReady is set only by startup after the Master
	// installs the Direct recording lifecycle and its recovery paths.
	RecordingControlsReady bool
}

type Verifier struct {
	master  *url.URL
	auth    NodeAuthenticator
	current CurrentIngress
	edge    *network.Resolver
	// Disabled until a trusted encrypted-tree catalog preparer is explicitly
	// wired with the complete mutation, S3 and recovery contracts.
	catalogPreparer CatalogPreparer
	// Production leaves this disabled until recording upload and recovery are
	// fully integrated, so a ticket cannot strand a reservation.
	recordingTicketReady bool
}

func NewVerifier(c VerifierConfig) (*Verifier, error) {
	master, err := origin(c.MasterOrigin)
	if err != nil || nilValue(c.Authenticator) || nilValue(c.Current) {
		return nil, errors.New("incomplete Master ingress verifier")
	}
	var preparer CatalogPreparer
	if !nilValue(c.CatalogPreparer) {
		if _, ok := c.Current.(catalogFinalIngress); !ok {
			return nil, errors.New("catalog admission fence unavailable")
		}
		preparer = c.CatalogPreparer
	}
	return &Verifier{master: master, auth: c.Authenticator, current: c.Current, edge: c.EdgeResolver, catalogPreparer: preparer, recordingTicketReady: c.RecordingControlsReady}, nil
}

// Wrap is intended for a dedicated Master proxy listener. The outer server
// must not expose the same business handlers without its normal authorization.
// Authorization-bearing responses are held until their lease is committed.
// The playback and revocation operations instead commit admission before their
// handler runs; they are then bounded in-flight work, not new authorization.
func (v *Verifier) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		item, ok := match(r)
		if !ok {
			fail(w, http.StatusNotFound)
			return
		}
		recordingMethod, needsRecordingSession := recordingControl(item.path)
		longRecordingControl := item.path == recordingTicketPath || recordingMethod == http.MethodDelete
		timeout := requestTimeout
		if relayRoute(item.path) {
			timeout = relayReadLimit
		}
		if longRecordingControl {
			timeout = recordingTicketTimeout
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		if v == nil || nilValue(v.auth) || nilValue(v.current) || nilValue(next) {
			fail(w, http.StatusServiceUnavailable)
			return
		}
		if recordingMethod != "" && !v.recordingTicketReady {
			fail(w, http.StatusServiceUnavailable)
			return
		}
		if longRecordingControl {
			select {
			case recordingTicketMasterSlot <- struct{}{}:
				defer func() { <-recordingTicketMasterSlot }()
			default:
				fail(w, http.StatusServiceUnavailable)
				return
			}
		}
		if r.TLS == nil && (v.edge == nil || !v.edge.Resolve(r).FromTrustedProxy || !v.edge.SecureAdmin(r)) {
			masterIngressEdge.reject(w)
			return
		}
		if _, exists := network.AuthenticatedIngressFromContext(r.Context()); exists {
			masterIngressProofHeaders.reject(w)
			return
		}
		for _, name := range []string{"X-Fc-Public-Hop", "X-Fc-Public-Version", "X-Fc-Public-Ingress", "X-Fc-Public-Generation", "X-Fc-Public-Origin", "X-Fc-Public-Client-Ip"} {
			if len(r.Header.Values(name)) != 1 {
				masterIngressProofHeaders.reject(w)
				return
			}
		}
		if r.Header.Get("X-Fc-Public-Hop") != "1" || r.Header.Get("X-Fc-Public-Version") != strconv.Itoa(proofVersion) {
			masterIngressProofHeaders.reject(w)
			return
		}
		id, originValue, ip := r.Header.Get("X-Fc-Public-Ingress"), r.Header.Get("X-Fc-Public-Origin"), r.Header.Get("X-Fc-Public-Client-Ip")
		genText := r.Header.Get("X-Fc-Public-Generation")
		gen, err := strconv.ParseInt(genText, 10, 64)
		public, originErr := origin(originValue)
		if err != nil || gen <= 0 || strconv.FormatInt(gen, 10) != genText || originErr != nil || public.String() != originValue || !strings.EqualFold(r.Host, public.Host) || !validClientHeaders(r.Header, public, item) {
			masterIngressProofOrigin.reject(w)
			return
		}
		if needsRecordingSession && !validRecordingSession(r.Header) || !needsRecordingSession && len(r.Header.Values(recordingSessionHeader)) != 0 {
			masterIngressProofHeaders.reject(w)
			return
		}
		bodyLimit := requestBodyLimit(item.path)
		if r.ContentLength > bodyLimit || ((r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength > 0) || recordingMethod == http.MethodDelete && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
			fail(w, http.StatusRequestEntityTooLarge)
			return
		}
		ctl := http.NewResponseController(w)
		if deadlineErr := ctl.SetReadDeadline(time.Now().Add(timeout)); deadlineErr != nil && recordingMethod != "" {
			fail(w, http.StatusServiceUnavailable)
			return
		}
		defer ctl.SetReadDeadline(time.Time{})
		var body []byte
		if r.Body != nil {
			body, err = io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
			if err != nil || int64(len(body)) > bodyLimit || ((r.Method == http.MethodGet || r.Method == http.MethodHead) && len(body) != 0) {
				fail(w, http.StatusBadRequest)
				return
			}
		}
		if !validCookies(r, item) {
			masterIngressProofFormat.reject(w)
			return
		}
		proof, err := makeProof(id, gen, public, v.master, ip, r, body)
		if err != nil {
			masterIngressProofFormat.reject(w)
			return
		}
		limit, buffered := admissionLimit(item.path)
		if buffered && !longRecordingControl {
			slots := businessAdmissionSlots
			if sensitiveRoute(item) {
				slots = keyAdmissionSlots
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				fail(w, http.StatusServiceUnavailable)
				return
			}
		} else if item.path != "/api/v1/media/playback" && item.path != "/api/v1/media/network-observation" && item.path != "/api/v1/media/project-diagnostics" && item.path != "/api/v1/media/crypto/revoke" && !relayRoute(item.path) && !karaokeCredentialsRoute(item.path) {
			fail(w, http.StatusServiceUnavailable)
			return
		}
		if catalogReadPath(item.path) && v.catalogPreparer != nil {
			v.servePreparedCatalog(w, r, item, proof, id, originValue, ip, gen, limit)
			return
		}
		current, release, err := v.current.AcquireCurrentIngress(r.Context())
		if err != nil {
			if !nilValue(release) {
				release.Release()
			}
			masterIngressActiveLease.reject(w)
			return
		}
		if nilValue(release) {
			masterIngressActiveLease.reject(w)
			return
		}
		defer release.Release()
		if ctx.Err() != nil {
			fail(w, http.StatusServiceUnavailable)
			return
		}
		if current.NodeID != id || current.Generation != gen || current.PublicOrigin != originValue {
			masterIngressStaleTuple.reject(w)
			return
		}
		// Re-check the relationship while holding the same shared lease used by
		// revocation and ingress changes. Otherwise a successful authentication
		// could be revoked before this request acquires its authorization fence.
		rel, err := v.auth.Authenticate(r.Context(), r.Header, http.MethodPost, ProofDomain, proof, false, false)
		if err != nil || rel.PeerID != id || rel.Direction != "downstream" || rel.State != "active" || rel.Protocol != protocol.Version {
			masterIngressNodeAuth.reject(w)
			return
		}
		verified, err := network.WithAuthenticatedIngress(r.Context(), network.AuthenticatedIngress{NodeID: id, Generation: gen, PublicOrigin: originValue, ClientIP: ip})
		if err != nil {
			masterIngressProofFormat.reject(w)
			return
		}
		clean := r.Clone(verified)
		clean.Header = make(http.Header)
		for _, name := range signedHeaders {
			for _, value := range r.Header.Values(name) {
				clean.Header.Add(name, value)
			}
		}
		clean.Body = io.NopCloser(bytes.NewReader(body))
		clean.ContentLength = int64(len(body))
		deadline, _ := ctx.Deadline()
		_ = ctl.SetWriteDeadline(deadline)
		defer ctl.SetWriteDeadline(time.Time{})
		switch {
		case relayRoute(item.path):
			// The separately signed, session-bound resource grant is checked by
			// the reader. Commit the current ingress fence before the bounded
			// stream starts, so already admitted reads can drain on selection.
			if len(clean.Header.Values("X-Media-Relay")) != 1 || ctx.Err() != nil || release.Commit() != nil || ctx.Err() != nil {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, clean)
		case recordingMethod != "":
			// The recording coordinator rechecks ingress and account under its
			// own transaction. Release the admission fence before it runs and
			// buffer the small control response before sending it.
			if ctx.Err() != nil || release.Commit() != nil || ctx.Err() != nil {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			buffer := newAdmissionResponse(limit)
			buffer.readDeadline = ctl.SetReadDeadline
			next.ServeHTTP(buffer, clean)
			if buffer.failed || ctx.Err() != nil {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			buffer.send(w)
		case item.path == "/api/v1/media/playback" || item.path == "/api/v1/media/network-observation" || item.method == http.MethodPost && item.path == "/api/v1/media/project-diagnostics" || item.path == "/api/v1/media/crypto/revoke" || karaokeCredentialsRoute(item.path):
			// These operations have independent committed effects (including
			// account sessions and captcha state). Their authorization point is
			// the ingress commit before the handler; admitted work can finish
			// after selection changes, and requests are never retried here.
			if ctx.Err() != nil || release.Commit() != nil || ctx.Err() != nil {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, clean)
		case item.path == "/" || item.path == "/api/v1/media/project-diagnostics" || item.path == "/api/v1/media/refresh" || item.path == "/api/v1/media/crypto/session" || item.path == "/api/v1/media/crypto/key" || item.path == "/api/v1/media/crypto/native/source" || item.path == "/api/v1/media/admin-handoff/authorize" ||
			item.path == "/api/v1/media/catalog/categories" || item.path == "/api/v1/media/catalog/media" || item.path == "/api/v1/media/catalog/artwork" || item.path == "/api/v1/media/metadata" || item.path == "/api/v1/media/lyrics/content" || item.path == "/api/v1/karaoke/context" || item.path == "/api/v1/karaoke/lyrics" || pageRoute(item.path) || assetRoute(item.path):
			bound, err := store.BindIngressPrerequisite(clean.Context(), release)
			if err != nil {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			clean = clean.WithContext(bound)
			// The callback is process-local and installed only after the peer and
			// current ingress have been authenticated. No session identifier or
			// browser key needs to cross this boundary as an HTTP header.
			admissionContext, admission := network.WithPublicAdmission(clean.Context())
			clean = clean.WithContext(admissionContext)
			defer admission.Abort()
			buffer := newAdmissionResponse(limit)
			next.ServeHTTP(buffer, clean)
			if buffer.failed || ctx.Err() != nil {
				admission.Abort()
				fail(w, http.StatusServiceUnavailable)
				return
			}
			// An error response may legitimately contain no new credential. If a
			// handler did register one, discard the entire anomalous response.
			success := buffer.status == 0 || buffer.status >= 200 && buffer.status < 300
			if !success && admission.Abort() {
				fail(w, http.StatusServiceUnavailable)
				return
			}
			if ctx.Err() != nil || release.Commit() != nil || ctx.Err() != nil || success && !admission.Commit() {
				admission.Abort()
				fail(w, http.StatusServiceUnavailable)
				return
			}
			buffer.send(w)
		default:
			// New routes need explicit review of response and side effects.
			fail(w, http.StatusServiceUnavailable)
		}
	})
}

func validCookies(r *http.Request, item route) bool {
	raw := r.Header.Values("Cookie")
	if len(raw) > 1 {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	cookies, err := http.ParseCookie(raw[0])
	if err != nil || len(cookies) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, cookie := range cookies {
		allowed := item.key && cookie.Name == "frontiercloud_browser_crypto" || karaokeCredentialsRoute(item.path) && (cookie.Name == "__Host-karaoke_session" || cookie.Name == "__Host-karaoke_csrf")
		if !allowed || seen[cookie.Name] || len(cookie.Value) > 256 {
			return false
		}
		seen[cookie.Name] = true
	}
	return true
}
