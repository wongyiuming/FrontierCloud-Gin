package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type Admin struct {
	settings            config.Config
	auth                *admin.Service
	network             *network.Resolver
	handoffNetwork      *network.Resolver
	public              *Public
	identity            *node.Identity
	selectedUpload      *business.SelectedUploadRuntime
	selectedMediaDelete selectedMediaDeleteFunc
}

func RegisterAdmin(router *gin.Engine, settings config.Config, auth *admin.Service, public *Public, identity *node.Identity) (*Admin, error) {
	resolver, err := network.New(settings.TrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	handoffResolver, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	a := &Admin{settings: settings, auth: auth, network: resolver, handoffNetwork: handoffResolver, public: public, identity: identity}
	group := router.Group("/api/v1/media/admin", a.transport)
	group.GET("", a.authenticatePage, a.page)
	group.GET("/", a.authenticatePage, a.page)
	group.GET("/login", a.login)
	group.POST("/elevate", a.elevate)
	group.GET("/handoff/start", a.handoffStart)
	group.POST("/handoff/redeem", a.handoffRedeem)
	// Only an authenticated current ingress may call this specific operation.
	router.POST("/api/v1/media/admin-handoff/authorize", a.handoffAuthorize)
	protected := group.Group("", a.authenticate)
	protected.GET("/status", a.status)
	protected.POST("/logout", a.logout)
	protected.POST("/crypto/session", a.cryptoSession)
	protected.POST("/crypto/prepare", a.cryptoPrepare)
	protected.POST("/crypto/key", a.cryptoKey)
	protected.POST("/crypto/source", a.s3Source)
	protected.GET("/crypto/bytes", a.cryptoBytes)
	protected.HEAD("/crypto/bytes", a.cryptoBytes)
	protected.POST("/key/temporary", a.temporary)
	protected.POST("/key/rotate", a.rotate)
	protected.GET("/brand", a.brandStatus)
	protected.GET("/brand/", a.brandStatus)
	protected.GET("/brand/:kind/download", a.brandDownload)
	protected.DELETE("/brand/:kind", a.brandDelete)
	protected.POST("/upload/brand/:kind", a.brandUpload)
	protected.GET("/tree", a.tree)
	protected.GET("/tree/search", a.treeSearch)
	protected.POST("/hide", a.hide)
	protected.POST("/delete", a.delete)
	protected.GET("/download", a.download)
	protected.GET("/download/plan", a.downloadPlan)
	protected.POST("/download/plan", a.selectedDownloadPlan)
	protected.GET("/download/bytes", a.downloadPlanBytes)
	protected.HEAD("/download/bytes", a.downloadPlanBytes)
	protected.POST("/upload/item", func(c *gin.Context) { a.upload(c, false) })
	protected.POST("/upload/lyric", func(c *gin.Context) { a.upload(c, true) })
	protected.GET("/storage-pool", a.storagePool)
	protected.POST("/upload/selected/hidden-directory", a.selectedHiddenDirectory)
	protected.POST("/upload/selected/prepare", a.selectedPrepareUpload)
	protected.POST("/upload/selected/:upload/resume", a.selectedResumeUpload)
	protected.PUT("/upload/selected/:upload/bytes", a.selectedRelayBytes)
	protected.POST("/upload/selected/:upload/recover", a.selectedRelayRecover)
	protected.POST("/upload/selected/:upload/cleanup", a.selectedRelayCleanup)
	protected.GET("/upload/selected/:upload/status", a.selectedUploadStatus)
	protected.POST("/upload/selected/:upload/complete", a.selectedCompleteUpload)
	protected.POST("/upload/selected/:upload/cancel", a.selectedCancelUpload)
	protected.POST("/upload/selected/:upload/cancel/finish", a.selectedFinishCancel)
	protected.POST("/upload/session", a.reserveUpload)
	protected.PUT("/upload/session/:upload/bytes", a.uploadBytes)
	protected.POST("/upload/session/:upload/finalize", a.finalizeUpload)
	protected.DELETE("/upload/session/:upload", a.cancelUpload)
	protected.GET("/directory-priorities", a.directoryPriorities)
	protected.POST("/directory-priority", a.directoryPriority)
	protected.POST("/directory/rename", a.renameDirectory)
	protected.GET("/lyrics/catalog", a.lyricCatalog)
	protected.POST("/lyrics/relations", a.lyricRelations)
	protected.POST("/lyrics/auto-relate", a.lyricAuto)
	protected.POST("/media-priority", a.mediaPriority)
	protected.GET("/media-priority", a.mediaPriorities)
	protected.GET("/priority-order", a.priorityOrder)
	protected.POST("/priority-order", a.movePriority)
	a.registerS3(protected)
	return a, nil
}

func authError(c *gin.Context, err error) {
	var rejected *admin.Error
	if errors.As(err, &rejected) {
		c.JSON(rejected.Status, gin.H{"detail": rejected.Detail})
	} else {
		internalError(c, err)
	}
	c.Abort()
}
func (a *Admin) info(c *gin.Context) admin.RequestInfo {
	return admin.RequestInfo{IP: a.network.Resolve(c.Request).IP, UserAgent: c.Request.UserAgent(), RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")}
}
func (a *Admin) transport(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !a.network.SecureAdmin(c.Request) {
		detail(c, 426, "安全控制台只允许通过 HTTPS 访问；仅本机回环 HTTP 例外")
		c.Abort()
		return
	}
	c.Next()
}
func (a *Admin) cookies(c *gin.Context, session admin.Session) {
	sameSite := http.SameSiteStrictMode
	if a.settings.AdminCookieSameSite == "lax" {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: a.settings.AdminCookieName(), Value: session.Cookie, Path: "/", MaxAge: session.IdleTTL, HttpOnly: true, Secure: a.settings.TLSEnabled, SameSite: sameSite})
	if session.CSRF != "" {
		http.SetCookie(c.Writer, &http.Cookie{Name: a.settings.CSRFCookieName(), Value: session.CSRF, Path: "/", MaxAge: session.IdleTTL, Secure: a.settings.TLSEnabled, SameSite: sameSite})
	}
}
func session(c *gin.Context) admin.Session {
	value, _ := c.Get("admin_session")
	return value.(admin.Session)
}
func (a *Admin) authenticate(c *gin.Context) {
	a.authenticateRequest(c, false)
}
func (a *Admin) authenticatePage(c *gin.Context) {
	a.authenticateRequest(c, true)
}
func (a *Admin) authenticateRequest(c *gin.Context, page bool) {
	cookie, _ := c.Cookie(a.settings.AdminCookieName())
	csrf, _ := c.Cookie(a.settings.CSRFCookieName())
	value, err := a.auth.Authenticate(c.Request.Context(), cookie, csrf, c.GetHeader("X-CSRF-Token"), c.Request.Method, c.GetHeader("X-Admin-Activity"))
	if err != nil {
		var rejected *admin.Error
		if page && errors.As(err, &rejected) && rejected.Status == http.StatusUnauthorized && a.canShowLogin(c) && adminPageNavigation(c) {
			c.Redirect(http.StatusSeeOther, adminLoginPath)
			c.Abort()
			return
		}
		authError(c, err)
		return
	}
	c.Set("admin_session", value)
	c.Request = c.Request.WithContext(media.AdminResourceContext(c.Request.Context()))
	if value.Refresh {
		a.cookies(c, value)
	}
	c.Next()
}
func (a *Admin) elevate(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)
	if err := c.Request.ParseForm(); err != nil {
		invalid(c, "body", "token")
		return
	}
	token := c.Request.PostForm.Get("token")
	if token == "" {
		invalid(c, "body", "token")
		return
	}
	value, err := a.auth.Login(c.Request.Context(), token, a.info(c))
	if err != nil {
		authError(c, err)
		return
	}
	a.cookies(c, value)
	c.JSON(200, gin.H{"status": "ok", "redirect": "/api/v1/media/admin"})
}
func (a *Admin) status(c *gin.Context) {
	value := session(c)
	identity, err := a.public.media.IdentityState(c.Request.Context())
	if err != nil {
		internalError(c, err)
		return
	}
	master, err := a.public.media.MasterURL(c.Request.Context())
	if err != nil {
		internalError(c, err)
		return
	}
	result := gin.H{"status": "ok", "session": true, "node_role": identity.Role, "master_url": master, "limits": gin.H{"max_upload_file_size": a.settings.AdminMaxUploadBytes, "max_upload_task_files": a.settings.AdminMaxTaskFiles, "max_batch_files": a.settings.AdminMaxBatchFiles, "max_lyric_file_size": 2 * 1024 * 1024}, "csrf_cookie_name": a.settings.CSRFCookieName(), "credential_kind": value.Kind, "session_idle_minutes": value.IdleTTL / 60}
	if a.public.opaqueTree != nil {
		result["media_download_protocol"] = "sealed-v1"
		result["media_delete_protocol"] = "sealed-v1"
		result["media_delete_available"] = a.selectedMediaDelete != nil
	}
	c.JSON(200, result)
}
func (a *Admin) logout(c *gin.Context) {
	if err := a.auth.Logout(c.Request.Context(), session(c), a.info(c)); err != nil {
		authError(c, err)
		return
	}
	if a.public.crypto != nil {
		a.public.crypto.RevokeBinding("admin:" + session(c).Hash)
	}
	for _, name := range []string{a.settings.AdminCookieName(), a.settings.CSRFCookieName()} {
		http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: a.settings.TLSEnabled})
	}
	c.JSON(200, gin.H{"status": "logged_out"})
}
func (a *Admin) temporary(c *gin.Context) {
	var body map[string]json.RawMessage
	if !decodeAdmin(c, &body) {
		return
	}
	minutes := 15
	if raw, exists := body["minutes"]; exists {
		value := string(raw)
		if strings.HasPrefix(value, "\"") {
			if err := json.Unmarshal(raw, &value); err != nil {
				detail(c, 400, "临时 Admin Key 有效期无效")
				return
			}
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			detail(c, 400, "临时 Admin Key 有效期无效")
			return
		}
		minutes = parsed
	}
	key, err := a.auth.TemporaryKey(c.Request.Context(), session(c), minutes, a.info(c))
	if err != nil {
		authError(c, err)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.JSON(200, gin.H{"status": "ok", "admin_key": key, "minutes": minutes, "single_use": true})
}
func (a *Admin) rotate(c *gin.Context) {
	var body struct {
		Mode         string `json:"mode"`
		Key          string `json:"key"`
		Confirmation string `json:"confirmation"`
	}
	if !decodeAdmin(c, &body) {
		return
	}
	key, err := a.auth.Rotate(c.Request.Context(), session(c), body.Mode, body.Key, body.Confirmation, a.info(c))
	if err != nil {
		authError(c, err)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.JSON(200, gin.H{"status": "ok", "admin_key": key})
}
func decodeAdmin(c *gin.Context, target any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 512*1024)
	if err := c.ShouldBindJSON(target); err != nil {
		invalid(c, "body", "payload")
		return false
	}
	return true
}

func (a *Admin) asset(name string) (string, error) {
	if url, exists := a.public.assets[name]; exists {
		return url, nil
	}
	content, err := a.public.static.ReadFile(name)
	if err != nil {
		return "", err
	}
	return assetURL(name, content), nil
}
func (a *Admin) page(c *gin.Context) {
	content, err := a.public.template(c, "admin.html")
	if err != nil {
		internalError(c, err)
		return
	}
	for marker, asset := range map[string]string{"ADMIN_CSS_URL": "css/admin.css", "ADMIN_JS_URL": "js/admin.js", "NODES_JS_URL": "js/nodes.js", "MIGRATIONS_JS_URL": "js/node-migrations.js"} {
		url, err := a.asset(asset)
		if err != nil {
			internalError(c, err)
			return
		}
		content = strings.ReplaceAll(content, "{{"+marker+"}}", url)
	}
	var styles, scripts strings.Builder
	for _, asset := range []string{"css/admin-system-modules.css", "css/nodes-observability.css", "css/directory-admin.css", "css/upload-site-types.css"} {
		url, err := a.asset(asset)
		if err != nil {
			internalError(c, err)
			return
		}
		styles.WriteString(`<link rel="stylesheet" href="` + url + `">` + "\n")
	}
	for _, asset := range []string{"js/maintenance-admin.js", "js/brand-admin.js", "js/admin-focus.js", "js/directory-admin.js", "js/priority-drag.js", "js/lyrics-directory-counts.js", "js/upload-sha256.js", "js/admin-upload-integrity.js", "js/admin-visibility-integrity.js", "js/log-admin.js"} {
		url, err := a.asset(asset)
		if err != nil {
			internalError(c, err)
			return
		}
		scripts.WriteString(`<script nonce="` + c.GetString(htmlNonceKey) + `" src="` + url + `"></script>` + "\n")
	}
	content = strings.Replace(content, "</head>", styles.String()+"</head>", 1)
	content = strings.Replace(content, "</body>", scripts.String()+"</body>", 1)
	serveHTML(c, content, false)
}
