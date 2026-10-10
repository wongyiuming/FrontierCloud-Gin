package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"math"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
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
	if !resolver.SecureAdmin(c.Request) {
		detail(c, 426, "临时密钥只允许通过 HTTPS 或本机回环访问")
		return false
	}
	return true
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
		p.page(c, "lyrics.html", map[string]string{"LYRICS_JSON": "[]", "LINE_COUNT": "0", "ENCRYPTED_LYRICS_JSON": jsonString(gin.H{"file_path": object.Path})})
	} else {
		noStore(c)
		c.JSON(200, cryptoEncryptedLyrics(object.Path, object.Encryption))
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
	m, err := mediacrypto.OpenForData(filepath.Join(p.settings.DataRoot, "media-keys"), hasEncryption || keyID != "")
	if err != nil {
		return err
	}
	if err = p.media.CheckEncryptionKey(ctx, m.KeyID()); err != nil {
		return err
	}
	p.crypto = m
	router.GET("/media-crypto-sw.js", func(c *gin.Context) {
		noStore(c)
		c.Header("Service-Worker-Allowed", "/")
		p.staticFile(c, "js/compiled/media-crypto-sw.js", false)
	})
	group := router.Group("/api/v1/media/crypto")
	group.POST("/session", p.cryptoSession)
	group.POST("/key", p.cryptoKey)
	group.POST("/revoke", p.cryptoRevoke)
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

func (p *Public) browserBinding(c *gin.Context, create bool) (string, error) {
	value, _ := c.Cookie(mediaCryptoCookie)
	raw, err := hex.DecodeString(value)
	if err == nil && len(raw) == 32 {
		return "browser:" + value, nil
	}
	if !create {
		return "", mediacrypto.ErrSession
	}
	raw = make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value = hex.EncodeToString(raw)
	http.SetCookie(c.Writer, &http.Cookie{Name: mediaCryptoCookie, Value: value, Path: "/", HttpOnly: true, Secure: p.settings.TLSEnabled, SameSite: http.SameSiteStrictMode})
	return "browser:" + value, nil
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
	grant, err := p.crypto.NewSession(binding, body.PublicKey)
	if err != nil {
		cryptoError(c, err)
		return
	}
	noStore(c)
	c.JSON(200, grant)
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
	binding := "admin:" + session(c).Hash
	envelope, err := a.public.crypto.Wrap(binding, body.SessionID, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	token, err := a.public.crypto.SignPreparation(binding, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	noStore(c)
	c.JSON(200, gin.H{"encryption": meta, "key_envelope": envelope, "preparation_token": token})
}

type cryptoKeyBody struct {
	SessionID  string `json:"session_id"`
	FilePath   string `json:"file_path"`
	ResourceID string `json:"resource_id"`
}

func (p *Public) cryptoKey(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	var body cryptoKeyBody
	if !cryptoDecode(c, &body) {
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
	a.public.cryptoKeyFor(c, "admin:"+session(c).Hash, body, true)
}

func (p *Public) cryptoKeyFor(c *gin.Context, binding string, body cryptoKeyBody, admin bool) {
	if !p.cryptoAvailable(c) {
		return
	}
	if len(body.FilePath) > 4096 || len(body.ResourceID) > 128 || body.FilePath == "" && body.ResourceID == "" {
		invalid(c, "body", "file_path")
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
	query := url.Values{"file_path": {object.Path}}
	if body.ResourceID != "" {
		query.Set("resource_id", body.ResourceID)
	}
	source := "/api/v1/media/stream?" + query.Encode()
	if object.Kind == "lyric" {
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
	c.JSON(200, gin.H{"encryption": object.Encryption, "key_envelope": envelope, "source_url": source, "content_type": contentType, "filename": path.Base(object.Path)})
}

func (p *Public) cryptoRevoke(c *gin.Context) {
	var body map[string]any
	if !cryptoDecode(c, &body) {
		return
	}
	if binding, err := p.browserBinding(c, false); err == nil && p.crypto != nil {
		p.crypto.RevokeBinding(binding)
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: mediaCryptoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: p.settings.TLSEnabled, SameSite: http.SameSiteStrictMode})
	noStore(c)
	c.JSON(200, gin.H{"status": "revoked"})
}

func (p *Public) cryptoLyricBytes(c *gin.Context) {
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
	items, err := d.Plan(5000)
	if err != nil {
		mediaAdminError(c, err)
		return
	}
	for i := range items {
		paths, _ := json.Marshal([]string{items[i].Path})
		items[i].URL = "/api/v1/media/admin/download?" + url.Values{"paths": {string(paths)}}.Encode()
	}
	noStore(c)
	c.JSON(200, gin.H{"items": items})
}

func (a *Admin) uploadEncryption(c *gin.Context, mode, encoded, preparation string) (*mediacrypto.Metadata, bool) {
	if mode == "plain" && encoded == "" && preparation == "" {
		return nil, true
	}
	if mode != "encrypted" {
		detail(c, 400, "每次上传必须明确选择加密落盘或明文落盘")
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
