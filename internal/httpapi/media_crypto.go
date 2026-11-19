package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"math"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const mediaCryptoCookie = "frontiercloud_browser_crypto"

// Role changes are durable and may occur after Standalone startup created a
// manager. Its presence never grants a newly promoted storage node key service.
func (p *Public) cryptoAvailable(c *gin.Context) bool {
	noStore(c)
	if p.crypto == nil {
		detail(c, 409, "存储节点不提供媒体密钥，请访问主节点")
		return false
	}
	role, err := p.media.BusinessRole(c.Request.Context())
	if err != nil {
		internalError(c, err)
		return false
	}
	if role == "Follower" {
		detail(c, 409, "存储节点不提供媒体密钥，请访问主节点")
		return false
	}
	return true
}

func (p *Public) cryptoTransport(c *gin.Context) bool {
	if !p.cryptoAvailable(c) {
		return false
	}
	resolver, err := network.New(p.settings.TrustedProxyNetworks)
	if err != nil {
		internalError(c, err)
		return false
	}
	if !securePublicCryptoTransport(c.Request, resolver) {
		detail(c, 426, "临时密钥只允许通过 HTTPS 或本机回环访问")
		return false
	}
	return true
}

func securePublicCryptoTransport(request *http.Request, resolver *network.Resolver) bool {
	// This context is installed by the Master only after authenticating the
	// selected peer and its HTTPS browser transport. Headers alone cannot
	// establish it, and it does not authorize Admin requests.
	if _, verified := network.AuthenticatedIngressFromContext(request.Context()); verified {
		return true
	}
	return resolver.SecureAdmin(request)
}

func encryptedUploadLimit(maximum int64) int64 {
	if maximum > math.MaxInt64-mediacrypto.ChunkSize {
		return math.MaxInt64
	}
	overhead := 16 * ((maximum + mediacrypto.ChunkSize - 1) / mediacrypto.ChunkSize)
	if maximum > math.MaxInt64-overhead {
		return math.MaxInt64
	}
	return maximum + overhead
}

func (p *Public) encryptedLyrics(c *gin.Context, page bool) bool {
	name := c.Query("track")
	if name == "" {
		return false
	}
	object, err := p.media.EncryptedLyric(c.Request.Context(), name, c.Query("resource_id"))
	if err != nil {
		if errors.Is(err, media.ErrLyrics) {
			return false
		}
		cryptoError(c, err)
		return true
	}
	if object.Encryption == nil {
		return false
	}
	if page {
		p.page(c, "lyrics.html", map[string]string{"LYRICS_JSON": "[]", "LINE_COUNT": "0", "ENCRYPTED_LYRICS_JSON": jsonString(gin.H{"file_path": object.Path, "encryption": object.Encryption})})
	} else {
		noStore(c)
		if _, proxied := network.AuthenticatedIngressFromContext(c.Request.Context()); proxied {
			c.JSON(200, gin.H{"encrypted": true, "lyric_path": object.Path, "encryption": object.Encryption})
		} else {
			c.JSON(200, cryptoEncryptedLyrics(object.Path, object.Encryption))
		}
	}
	return true
}

func (p *Public) registerMediaCrypto(router *gin.Engine) error {
	// The key is part of durable business state and is separate from node signing
	// credentials. Backups must preserve it alongside the database metadata.
	ctx := context.Background()
	identity, err := p.media.IdentityState(ctx)
	if err != nil {
		return err
	}
	// Storage Followers transport opaque bytes and never need a premaster key.
	if identity.Role == "Follower" {
		return nil
	}
	hasEncryption, err := p.media.HasEncryption(ctx)
	if err != nil {
		return err
	}
	keyID, err := p.media.EncryptionKeyID(ctx)
	if err != nil {
		return err
	}
	if p.opaqueTree != nil && keyID == "" {
		return mediacrypto.ErrPremaster
	}
	m, err := mediacrypto.OpenForData(filepath.Join(p.settings.DataRoot, "media-keys"), hasEncryption || keyID != "")
	if err != nil {
		return err
	}
	if p.opaqueTree != nil {
		if m.KeyID() != keyID {
			return mediacrypto.ErrPremaster
		}
	} else if err = p.media.CheckEncryptionKey(ctx, m.KeyID()); err != nil {
		return err
	}
	p.crypto = m
	router.GET("/media-crypto-sw.js", func(c *gin.Context) {
		noStore(c)
		c.Header("Content-Security-Policy", mediaCryptoWorkerCSP)
		c.Header("Service-Worker-Allowed", "/")
		p.staticFile(c, "js/compiled/media-crypto-sw.js", false)
	})
	group := router.Group("/api/v1/media/crypto")
	group.POST("/session", p.cryptoIngressAdmission(false), p.cryptoSession)
	group.POST("/key", p.cryptoIngressAdmission(false), p.cryptoKey)
	group.POST("/source", p.cryptoIngressAdmission(false), p.s3Source)
	group.POST("/native/source", p.cryptoIngressAdmission(false), p.nativePlainSource)
	group.POST("/revoke", p.cryptoIngressAdmission(true), p.cryptoRevoke)
	group.GET("/bytes", p.cryptoLyricBytes)
	group.HEAD("/bytes", p.cryptoLyricBytes)
	return nil
}

func cryptoSameOrigin(c *gin.Context) bool {
	if site := c.GetHeader("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		detail(c, 403, "密钥授权只允许同源访问")
		return false
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != c.Request.Host || (u.Scheme != "http" && u.Scheme != "https") {
			detail(c, 403, "密钥授权只允许同源访问")
			return false
		}
	}
	return true
}

// cryptoIngress is resolved only from authenticated request context or from
// Master-owned configuration. In particular, Host and forwarding headers are
// never an authority for the identity or origin of an ingress.
type cryptoIngress struct {
	Scope      string
	NodeID     string
	Generation int64
	Origin     string
}

func (p *Public) cryptoIngress(c *gin.Context) (cryptoIngress, error) {
	if verified, ok := network.AuthenticatedIngressFromContext(c.Request.Context()); ok {
		return cryptoIngress{"ingress", verified.NodeID, verified.Generation, verified.PublicOrigin}, nil
	}
	if admitted, ok := c.Request.Context().Value(localCryptoIngressKey{}).(cryptoIngress); ok {
		return admitted, nil
	}
	identity, err := p.media.IdentityState(c.Request.Context())
	if err != nil {
		return cryptoIngress{}, err
	}
	if identity.Role == "Standalone" {
		return cryptoIngress{"standalone", identity.ID, 1, p.settings.PublicOrigin}, nil
	}
	if identity.Role != "Master" || p.control == nil {
		return cryptoIngress{}, mediacrypto.ErrSession
	}
	// Other existing browser-bound operations still use the current state. The
	// session, key and revoke routes supply the state held by their admission
	// lease above, rather than performing this separate read.
	ingress, err := p.control.CurrentPublicIngress(c.Request.Context())
	if err != nil || ingress.NodeID != identity.ID {
		return cryptoIngress{}, mediacrypto.ErrSession
	}
	return cryptoIngress{"ingress", ingress.NodeID, ingress.Generation, ingress.PublicOrigin}, nil
}

func cryptoOrigin(value string) (*url.URL, bool) {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(value, "\r\n\t \\") {
		return nil, false
	}
	return u, true
}

func sameCryptoOrigin(left, right string) bool {
	a, ok := cryptoOrigin(left)
	if !ok {
		return false
	}
	b, ok := cryptoOrigin(right)
	if !ok || a.Scheme != b.Scheme || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return port(a) == port(b)
}

func (p *Public) browserBinding(c *gin.Context, create bool) (string, error) {
	ingress, err := p.cryptoIngress(c)
	if err != nil {
		return "", err
	}
	return browserBindingForIngress(c, create, ingress)
}

func browserBindingForIngress(c *gin.Context, create bool, ingress cryptoIngress) (string, error) {
	origin, ok := cryptoOrigin(ingress.Origin)
	if !ok || len(ingress.NodeID) != 32 || ingress.Generation <= 0 {
		return "", mediacrypto.ErrSession
	}
	if requestOrigin := c.GetHeader("Origin"); requestOrigin != "" && !sameCryptoOrigin(requestOrigin, ingress.Origin) {
		return "", mediacrypto.ErrSession
	}
	value, _ := c.Cookie(mediaCryptoCookie)
	raw, err := hex.DecodeString(value)
	if err == nil && len(raw) == 32 {
		value = hex.EncodeToString(raw)
	} else {
		if !create {
			return "", mediacrypto.ErrSession
		}
		raw = make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		value = hex.EncodeToString(raw)
		http.SetCookie(c.Writer, &http.Cookie{Name: mediaCryptoCookie, Value: value, Path: "/", HttpOnly: true, Secure: origin.Scheme == "https", SameSite: http.SameSiteStrictMode})
	}
	// JSON's length-delimited fields prevent ambiguous concatenations. Keep the
	// cookie and other session material out of logs and diagnostic output.
	encoded, _ := json.Marshal(struct {
		Version int
		Ingress cryptoIngress
		Cookie  string
	}{2, ingress, value})
	digest := sha256.Sum256(encoded)
	return "browser:v2:" + hex.EncodeToString(digest[:]), nil
}

func cryptoDecode(c *gin.Context, body any) bool {
	if !cryptoSameOrigin(c) {
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8192)
	if err := c.ShouldBindJSON(body); err != nil {
		invalid(c, "body", "crypto")
		return false
	}
	return true
}

func cryptoError(c *gin.Context, err error) {
	if errors.Is(err, mediacrypto.ErrSessionLimit) {
		noStore(c)
		c.Header("Retry-After", "60")
		detail(c, http.StatusTooManyRequests, "临时密钥会话数量达到限额，请稍后重试")
		return
	}
	if errors.Is(err, mediacrypto.ErrSession) {
		detail(c, 401, "临时密钥授权已失效，请重新建立浏览器会话")
		return
	}
	if errors.Is(err, mediacrypto.ErrMetadata) {
		detail(c, 400, "加密元数据无效")
		return
	}
	mediaAdminError(c, err)
}

func (p *Public) cryptoSession(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	var body struct {
		PublicKey string `json:"public_key"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	binding, err := p.browserBinding(c, true)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if !p.allowPublicCryptoSession(c, binding) {
		return
	}
	grant, abort, err := p.crypto.NewSessionWithAbort(binding, body.PublicKey)
	if err != nil {
		cryptoError(c, err)
		return
	}
	// Until the request admission owns this callback, a panic must not leave a
	// session behind. Outside an admission (Standalone), retain the old session
	// lifetime on a normal response.
	transferred := false
	defer func() {
		if !transferred {
			abort()
		}
	}()
	present, registered := network.RegisterPublicAdmissionAbort(c.Request.Context(), abort)
	if present && !registered {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	noStore(c)
	c.JSON(200, grant)
	transferred = true
}

func (a *Admin) cryptoSession(c *gin.Context) {
	if !a.public.cryptoAvailable(c) {
		return
	}
	var body struct {
		PublicKey string `json:"public_key"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	grant, err := a.public.crypto.NewSession("admin:"+session(c).Hash, body.PublicKey)
	if err != nil {
		cryptoError(c, err)
		return
	}
	noStore(c)
	c.JSON(200, grant)
}

func (a *Admin) cryptoPrepare(c *gin.Context) {
	if !a.public.cryptoAvailable(c) {
		return
	}
	// A tree key may be issued only after the trusted startup/recovery gate
	// installs the matching durable file-ID reservation coordinator.
	if a.public.opaqueTree != nil && (a.selectedUpload == nil || !a.selectedUpload.Matches(a.public.opaqueTree, a.public.crypto, a.settings.AdminOrigin)) {
		detail(c, http.StatusServiceUnavailable, "资源暂不可用")
		return
	}
	if a.public.opaqueTree != nil && (!a.directManagementOrigin(c) || !sameOriginPost(c, a.settings.AdminOrigin)) {
		detail(c, http.StatusForbidden, "请求来源无效")
		return
	}
	var body struct {
		PlaintextSize int64  `json:"plaintext_size"`
		SessionID     string `json:"session_id"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	if body.PlaintextSize > a.settings.AdminMaxUploadBytes {
		detail(c, 413, "文件超过单文件上传限制")
		return
	}
	meta, err := mediacrypto.NewMetadata(body.PlaintextSize)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if meta.CiphertextSize > encryptedUploadLimit(a.settings.AdminMaxUploadBytes) {
		detail(c, 413, "加密后的文件超过单文件上传限制")
		return
	}
	binding := "admin:" + session(c).Hash
	if a.public.opaqueTree != nil {
		// Persist the freshly generated file ID before any browser receives a
		// key. A failed response permanently retires this ID rather than reusing it.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		if err = a.selectedUpload.ReservePreparation(ctx, session(c).Hash, meta); err != nil {
			detail(c, http.StatusServiceUnavailable, "资源暂不可用")
			return
		}
	}
	envelope, err := a.public.crypto.Wrap(binding, body.SessionID, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	var token string
	if a.public.opaqueTree != nil {
		token, err = a.public.crypto.SignTransientPreparation(binding, meta)
	} else {
		token, err = a.public.crypto.SignPreparation(binding, meta)
	}
	if err != nil {
		cryptoError(c, err)
		return
	}
	noStore(c)
	c.JSON(200, gin.H{"encryption": meta, "key_envelope": envelope, "preparation_token": token})
}

type cryptoKeyBody struct {
	SessionID        string `json:"session_id"`
	FilePath         string `json:"file_path"`
	ResourceID       string `json:"resource_id"`
	ObjectID         string `json:"object_id"`
	TrackResourceID  string `json:"track_resource_id"`
	DownloadSnapshot string `json:"download_snapshot"`
}

func (p *Public) cryptoKey(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	var body cryptoKeyBody
	if !cryptoDecode(c, &body) {
		return
	}
	if body.DownloadSnapshot != "" {
		invalid(c, "body", "download_snapshot")
		return
	}
	binding, err := p.browserBinding(c, false)
	if err != nil {
		cryptoError(c, err)
		return
	}
	p.cryptoKeyFor(c, binding, body, false)
}

func (a *Admin) cryptoKey(c *gin.Context) {
	if !a.public.cryptoAvailable(c) {
		return
	}
	var body cryptoKeyBody
	if !cryptoDecode(c, &body) {
		return
	}
	if a.public.opaqueTree != nil {
		a.selectedDownloadKey(c, body)
		return
	}
	if body.DownloadSnapshot != "" {
		invalid(c, "body", "download_snapshot")
		return
	}
	a.public.cryptoKeyFor(c, "admin:"+session(c).Hash, body, true)
}

func (p *Public) cryptoKeyFor(c *gin.Context, binding string, body cryptoKeyBody, admin bool) {
	if !p.cryptoAvailable(c) {
		return
	}
	if len(body.FilePath) > 4096 || len(body.ResourceID) > 128 || len(body.ObjectID) > 128 || body.FilePath == "" && body.ResourceID == "" {
		invalid(c, "body", "file_path")
		return
	}
	if p.opaqueTree != nil {
		if admin {
			detail(c, http.StatusServiceUnavailable, "资源路径不可用")
		} else if strings.HasPrefix(body.FilePath, "lyrics/") {
			p.opaqueEncryptedLyricKey(c, binding, body)
		} else {
			p.opaqueEncryptedMediaKey(c, binding, body)
		}
		return
	}
	object, err := p.media.CryptoObject(c.Request.Context(), body.FilePath, body.ResourceID, admin)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if object.Encryption == nil {
		detail(c, 409, "该文件为明文落盘")
		return
	}
	envelope, err := p.crypto.Wrap(binding, body.SessionID, *object.Encryption)
	if err != nil {
		cryptoError(c, err)
		return
	}
	read, err := p.media.ReadSource(c.Request.Context(), object.Path, body.ObjectID, admin)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	if read.ObjectID != "" {
		response, ok := s3SourceJSON(c, object.Path, read)
		if !ok {
			return
		}
		response["encryption"], response["key_envelope"] = object.Encryption, envelope
		response["source_expires_in"], response["source_expires_at"] = response["expires_in"], response["expires_at"]
		c.JSON(200, response)
		return
	}
	query := url.Values{"file_path": {object.Path}}
	if body.ResourceID != "" {
		query.Set("resource_id", body.ResourceID)
	}
	source := "/api/v1/media/stream?" + query.Encode()
	_, proxied := network.AuthenticatedIngressFromContext(c.Request.Context())
	unavailableSource := false
	var sourceCapability string
	var sourceHeaders map[string]string
	var sourceOrigin string
	var sourceTransport string
	var sourceExpiresAt int64
	if proxied && !admin {
		if object.Kind == "lyric" {
			// Lyric bytes belong to Master independently of the associated
			// track. Do not infer their route from the track's owner.
			sourceExpiresAt = min(envelope.ExpiresAt, time.Now().Unix()+protocol.TokenSeconds-1)
			policy, policyErr := p.media.MasterIngressPolicy(c.Request.Context())
			if policyErr != nil || policy.State != "applied" || policy.ConfiguredTransport != policy.AppliedTransport {
				unavailableSource = true
			} else {
				switch policy.AppliedTransport {
				case "Direct":
					if p.masterDirect == nil {
						unavailableSource = true
						break
					}
					source, sourceHeaders, err = p.masterDirect.Issue(c.Request.Context(), object, binding, body.SessionID)
					sourceOrigin, sourceTransport = p.masterDirect.origin, "Direct"
				case "Relay":
					if p.masterRelay == nil {
						unavailableSource = true
						break
					}
					var grantExpiry int64
					source, sourceHeaders, grantExpiry, err = p.masterRelay.Issue(c.Request.Context(), object, binding, body.SessionID)
					if err == nil {
						sourceExpiresAt = min(sourceExpiresAt, grantExpiry)
					}
					sourceTransport = "Relay"
				default:
					unavailableSource = true
				}
				if errors.Is(err, media.ErrUnavailable) || errors.Is(err, node.ErrCapability) {
					unavailableSource = true
				} else if err != nil {
					cryptoError(c, err)
					return
				}
			}
		} else {
			// Choose a conservative source deadline before signing so response
			// latency can never extend either the session or the 300-second grant.
			sourceExpiresAt = min(envelope.ExpiresAt, time.Now().Unix()+protocol.TokenSeconds-1)
			masterOwner, ownerErr := p.media.MasterOwnsIngressObject(c.Request.Context(), object)
			if errors.Is(ownerErr, media.ErrUnavailable) {
				unavailableSource = true
			} else if ownerErr != nil {
				cryptoError(c, ownerErr)
				return
			}
			if unavailableSource {
				// Keep the authorized envelope while explicitly refusing an
				// unavailable native data route.
			} else if masterOwner {
				policy, policyErr := p.media.MasterIngressPolicy(c.Request.Context())
				if policyErr != nil || policy.State != "applied" || policy.ConfiguredTransport != policy.AppliedTransport {
					unavailableSource = true
				} else {
					switch policy.AppliedTransport {
					case "Direct":
						if p.masterDirect == nil {
							unavailableSource = true
							break
						}
						source, sourceHeaders, err = p.masterDirect.Issue(c.Request.Context(), object, binding, body.SessionID)
						sourceOrigin, sourceTransport = p.masterDirect.origin, "Direct"
					case "Relay":
						if p.masterRelay == nil {
							unavailableSource = true
							break
						}
						var grantExpiry int64
						source, sourceHeaders, grantExpiry, err = p.masterRelay.Issue(c.Request.Context(), object, binding, body.SessionID)
						if err == nil {
							sourceExpiresAt = min(sourceExpiresAt, grantExpiry)
						}
						sourceTransport = "Relay"
					default:
						unavailableSource = true
					}
				}
			} else {
				local, policy, policyErr := p.media.FollowerIngressPolicy(c.Request.Context(), object)
				if policyErr != nil {
					unavailableSource = true
				} else if local {
					sessionContext, sessionErr := p.crypto.WithDirectSession(c.Request.Context(), binding, body.SessionID)
					if sessionErr != nil {
						cryptoError(c, sessionErr)
						return
					}
					source, sourceCapability, err = p.media.IngressLocalSource(sessionContext, object, sourceExpiresAt)
				} else if policy.State == "applied" && policy.ConfiguredTransport == "Relay" && policy.AppliedTransport == "Relay" && p.followerRelay != nil {
					var grantExpiry int64
					source, sourceHeaders, grantExpiry, err = p.followerRelay.Issue(c.Request.Context(), object, binding, body.SessionID)
					if err == nil {
						sourceExpiresAt = min(sourceExpiresAt, grantExpiry)
					}
					sourceTransport = "Relay"
				} else if policy.State == "applied" && policy.ConfiguredTransport == "Direct" && policy.AppliedTransport == "Direct" {
					sessionContext, sessionErr := p.crypto.WithDirectSession(c.Request.Context(), binding, body.SessionID)
					if sessionErr != nil {
						cryptoError(c, sessionErr)
						return
					}
					source, sourceOrigin, sourceCapability, err = p.media.FollowerDirectSource(sessionContext, object, sourceExpiresAt)
					sourceTransport = "Direct"
				} else {
					// Direct requires a separately verified resource origin; a Relay
					// failure or missing configuration never changes the policy.
					unavailableSource = true
				}
			}
			if errors.Is(err, media.ErrUnavailable) || errors.Is(err, node.ErrCapability) {
				unavailableSource = true
			} else if err != nil {
				cryptoError(c, err)
				return
			}
		}
	} else if object.Kind == "lyric" {
		source = "/api/v1/media/crypto/bytes?" + query.Encode()
	}
	if admin {
		source = "/api/v1/media/admin/crypto/bytes?" + url.Values{"file_path": {object.Path}}.Encode()
	}
	contentType := mime.TypeByExtension(path.Ext(object.Path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	noStore(c)
	response := gin.H{"encryption": object.Encryption, "key_envelope": envelope, "content_type": contentType, "filename": path.Base(object.Path)}
	if unavailableSource {
		// Deliver the authorized key envelope without inventing a data route.
		// The existing worker rejects a grant that has no source URL.
		response["source_error"] = "native_source_unavailable"
	} else {
		response["source_url"] = source
		if sourceCapability != "" || sourceHeaders != nil {
			remaining := sourceExpiresAt - time.Now().Unix()
			if remaining < 1 || remaining > protocol.TokenSeconds {
				cryptoError(c, mediacrypto.ErrSession)
				return
			}
			response["source_expires_at"], response["source_expires_in"] = sourceExpiresAt, remaining
		}
		if sourceCapability != "" {
			response["source_headers"] = gin.H{"X-Media-Capability": sourceCapability}
		}
		if sourceHeaders != nil {
			response["source_headers"] = sourceHeaders
		}
		if sourceTransport != "" {
			response["source_transport"] = sourceTransport
		}
		if sourceOrigin != "" {
			response["source_origin"] = sourceOrigin
		}
	}
	c.JSON(200, response)
}

func (p *Public) cryptoRevoke(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	var body map[string]any
	if !cryptoDecode(c, &body) {
		return
	}
	binding, err := p.browserBinding(c, false)
	if err != nil {
		if _, cookieErr := c.Cookie(mediaCryptoCookie); errors.Is(cookieErr, http.ErrNoCookie) {
			noStore(c)
			c.JSON(200, gin.H{"status": "revoked"})
			return
		}
		cryptoError(c, err)
		return
	}
	p.crypto.RevokeBinding(binding)
	// Cookies are shared across ports. Deleting it here would invalidate a
	// different origin's sessions; exact-binding revocation is sufficient.
	noStore(c)
	c.JSON(200, gin.H{"status": "revoked"})
}

func (p *Public) cryptoLyricBytes(c *gin.Context) {
	if p.opaqueTree != nil {
		detail(c, http.StatusServiceUnavailable, "歌词资源路径不可用")
		return
	}
	name := c.Query("file_path")
	f, info, err := p.media.OpenCryptoLyric(c.Request.Context(), name)
	if err != nil {
		cryptoError(c, err)
		return
	}
	defer f.Close()
	noStore(c)
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, c.Request, path.Base(name), info.ModTime(), f)
}

func (a *Admin) cryptoBytes(c *gin.Context) {
	if a.public.opaqueTree != nil {
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "资源暂不可用")
		return
	}
	object, err := a.public.media.CryptoObject(c.Request.Context(), c.Query("file_path"), "", true)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if object.Kind != "lyric" {
		a.public.deliver(c, object.Path, "")
		return
	}
	d, err := a.public.media.Download(c.Request.Context(), []string{object.Path})
	if err != nil {
		cryptoError(c, err)
		return
	}
	defer d.Close()
	f, info, err := d.Open(object.Path)
	if err != nil {
		cryptoError(c, err)
		return
	}
	defer f.Close()
	noStore(c)
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, c.Request, path.Base(object.Path), info.ModTime(), f)
}

func (a *Admin) downloadPlan(c *gin.Context) {
	if a.public.opaqueTree != nil {
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "资源暂不可用")
		return
	}
	var paths []string
	if json.Unmarshal([]byte(c.Query("paths")), &paths) != nil || len(paths) == 0 || len(paths) > a.settings.AdminMaxDownloadItems {
		detail(c, 400, "请选择合法下载对象")
		return
	}
	d, err := a.public.media.Download(c.Request.Context(), paths)
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	defer d.Close()
	items, err := d.BrowserPlan(5000)
	if err != nil {
		if errors.Is(err, media.ErrUploadSize) {
			detail(c, 413, "含加密文件的下载最多包含 5000 个文件，请分批下载")
			return
		}
		mediaAdminError(c, err)
		return
	}
	encrypted := false
	for _, item := range items {
		encrypted = encrypted || item.Encryption != nil
	}
	for i := range items {
		if encrypted {
			items[i].URL = "/api/v1/media/admin/download/bytes?" + url.Values{"file_path": {items[i].Path}, "media_id": {items[i].MediaID}, "snapshot": {items[i].Snapshot}}.Encode()
		} else {
			paths, _ := json.Marshal([]string{items[i].Path})
			items[i].URL = "/api/v1/media/admin/download?" + url.Values{"paths": {string(paths)}}.Encode()
		}
	}
	if err := a.auditEncryptedDownloadPlan(c, d, items); err != nil {
		internalError(c, err)
		return
	}
	noStore(c)
	c.JSON(200, gin.H{"items": items})
}

func (a *Admin) uploadEncryption(c *gin.Context, mode, encoded, preparation string) (*mediacrypto.Metadata, bool) {
	if mode != "encrypted" {
		detail(c, 400, "上传准备信息无效，请刷新页面后重试")
		return nil, false
	}
	if !a.public.cryptoAvailable(c) {
		return nil, false
	}
	var meta mediacrypto.Metadata
	if json.Unmarshal([]byte(encoded), &meta) != nil || meta.Validate() != nil {
		detail(c, 400, "加密元数据无效")
		return nil, false
	}
	if err := a.public.crypto.VerifyPreparation("admin:"+session(c).Hash, preparation, meta); err != nil {
		cryptoError(c, err)
		return nil, false
	}
	return &meta, true
}

func cryptoEncryptedLyrics(objectPath string, meta *mediacrypto.Metadata) gin.H {
	return gin.H{"encrypted": true, "lyric_path": objectPath, "encryption": meta, "source_url": "/api/v1/media/crypto/bytes?" + url.Values{"file_path": {objectPath}}.Encode()}
}
