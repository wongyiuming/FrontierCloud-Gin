package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingAudioPreparation permanently reserves a file ID on the given tree
// and authenticates the account and ingress in the reservation transaction.
type RecordingAudioPreparation func(ctx context.Context, tree *sealedtree.SQLStore, ingress store.PublicIngress, userID, browserBinding, recordingID string, meta mediacrypto.Metadata) error

// RecordingAudioReservation commits a pending reservation for the exact
// member. The runtime must recheck account, ingress and crypto authority under
// its own write gates before committing.
type RecordingAudioReservation func(context.Context, *sealedtree.SQLStore, store.PublicIngress, store.KaraokeUser, string, store.RecordingAudioTicketRequest, store.KaraokeAudit) error

type RecordingAudioUpload func(context.Context, *sealedtree.SQLStore, store.PublicIngress, store.KaraokeUser, string, string, string, int64, selectedupload.ReadDeadline, io.ReadCloser, store.KaraokeAudit, func(context.Context) error) (bool, error)

// ConfigureRecordingAudioPreparation is startup-only. Install it only after
// the recording lifecycle, including recovery, is ready on the same tree.
func (a *KaraokeAccounts) ConfigureRecordingAudioPreparation(prepare RecordingAudioPreparation) error {
	if a == nil || a.public == nil || a.public.opaqueTree == nil || a.public.crypto == nil || a.resolver == nil || prepare == nil || a.recordingAudioPreparation != nil {
		return store.ErrRecordingState
	}
	a.recordingAudioPreparation = prepare
	return nil
}

// ConfigureRecordingAudioReservation is startup-only. Preparation and the
// full write and recovery lifecycle must be ready before exposing tickets.
func (a *KaraokeAccounts) ConfigureRecordingAudioReservation(reserve RecordingAudioReservation) error {
	if a == nil || a.recordingAudioPreparation == nil || reserve == nil || a.recordingAudioReservation != nil {
		return store.ErrRecordingState
	}
	a.recordingAudioReservation = reserve
	return nil
}

func (p *Public) recordingAudioIngress(c *gin.Context) (cryptoIngress, bool) {
	if !p.cryptoTransport(c) {
		return cryptoIngress{}, false
	}
	ingress, err := p.cryptoIngress(c)
	if err != nil || ingress.Scope != "ingress" {
		cryptoError(c, mediacrypto.ErrSession)
		return cryptoIngress{}, false
	}
	validOrigin := sameOriginPost(c, ingress.Origin)
	if c.Request.Method == http.MethodGet {
		origins := c.Request.Header.Values("Origin")
		sites := c.Request.Header.Values("Sec-Fetch-Site")
		validOrigin = sameCryptoOrigin("https://"+c.Request.Host, ingress.Origin) &&
			(len(origins) == 0 || len(origins) == 1 && sameCryptoOrigin(origins[0], ingress.Origin)) &&
			(len(sites) == 0 || len(sites) == 1 && sites[0] == "same-origin")
	}
	if !validOrigin {
		detail(c, http.StatusForbidden, "录音授权只允许同源访问")
		return cryptoIngress{}, false
	}
	return ingress, true
}

func (a *KaraokeAccounts) recordingAccountCheck(c *gin.Context, user *store.KaraokeUser, mutation bool) func(context.Context) error {
	sessionName, csrfName := a.cookieNames()
	token, _ := c.Cookie(sessionName)
	csrf, _ := c.Cookie(csrfName)
	supplied := c.GetHeader("X-Karaoke-CSRF")
	return func(check context.Context) error {
		current, err := a.service.CurrentUser(check, token, csrf, supplied, mutation, false)
		if err != nil || current == nil || current.ID != user.ID || current.PasswordHash != user.PasswordHash || current.CreatedAt != user.CreatedAt {
			return store.ErrRecordingState
		}
		return nil
	}
}

func (a *KaraokeAccounts) reserveRecordingAudio(c *gin.Context, user *store.KaraokeUser, audit store.KaraokeAudit) {
	p := a.public
	if (a.recordingAudioReservation == nil && a.recordingAudioDirect == nil) || p.opaqueTree == nil {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	ingress, ok := p.recordingAudioIngress(c)
	if !ok {
		return
	}
	var request store.RecordingAudioTicketRequest
	if !smallStrictJSON(c, &request) || len(request.ContentType) > 96 {
		invalid(c, "body", "recording_audio")
		return
	}
	request.ContentType = strings.ToLower(strings.TrimSpace(strings.SplitN(request.ContentType, ";", 2)[0]))
	request.Title = strings.TrimSpace(request.Title)
	if request.Title == "" {
		request.Title = "卡拉OK录音"
	}
	if !request.Valid() {
		invalid(c, "body", "recording_audio")
		return
	}
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, request.SessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	binding, err := store.RecordingAudioPreparationBinding(user.ID, browser, request.RecordingID)
	if err != nil || p.crypto.VerifyTransientPreparation(binding, request.PreparationToken, request.Encryption) != nil {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	if a.recordingAudioDirect != nil {
		ticket, err := a.recordingAudioDirect.AdmitRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, request, audit, a.recordingAccountCheck(c, user, true))
		if err != nil {
			recordingError(c, err)
			return
		}
		if ctx.Err() != nil {
			detail(c, http.StatusServiceUnavailable, "录音预留状态待确认")
			return
		}
		c.JSON(http.StatusOK, ticket)
		return
	}
	if err = a.recordingAudioReservation(ctx, p.opaqueTree, expected, *user, browser, request, audit); err != nil {
		recordingError(c, err)
		return
	}
	if ctx.Err() != nil {
		detail(c, http.StatusServiceUnavailable, "录音预留状态待确认")
		return
	}
	// A revoked account session must not receive a new ticket. The durable
	// pending intent survives a lost response and is reconciled separately.
	c.Request = c.Request.WithContext(ctx)
	current, ok := a.current(c, true, false)
	if !ok {
		return
	}
	if current == nil || current.ID != user.ID || current.PasswordHash != user.PasswordHash || current.CreatedAt != user.CreatedAt {
		detail(c, http.StatusUnauthorized, "卡拉OK登录已失效")
		return
	}
	c.JSON(http.StatusOK, gin.H{"recording_id": request.RecordingID, "storage_member_id": request.MemberID, "state": "pending"})
}

// The public ingress handles only recording control messages. Ciphertext is
// transferred between the browser and the selected storage node.
func (a *KaraokeAccounts) recordingAudioDirectAction(c *gin.Context, user *store.KaraokeUser, audit store.KaraokeAudit, complete bool) {
	p := a.public
	if a.recordingAudioDirect == nil || p.opaqueTree == nil {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	ingress, ok := p.recordingAudioIngress(c)
	if !ok {
		return
	}
	id := c.Param("recording")
	if !node.ValidIdentifier(id) || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		invalid(c, "body", "recording_audio")
		return
	}
	sessions := c.Request.Header.Values("X-Fc-Recording-Session")
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil || len(sessions) != 1 || !node.ValidIdentifier(sessions[0]) {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, sessions[0])
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	checkAccount := a.recordingAccountCheck(c, user, true)
	if complete {
		var signed struct {
			Receipt   protocol.OpaqueCapacityReceipt `json:"receipt"`
			Signature string                         `json:"signature"`
		}
		if !smallStrictJSON(c, &signed) || signed.Signature == "" || len(signed.Signature) > 4096 {
			invalid(c, "body", "recording_receipt")
			return
		}
		if _, err = a.recordingAudioDirect.CompleteRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, sessions[0], id, signed.Receipt, signed.Signature, audit, checkAccount); err != nil {
			recordingError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"recording_id": id, "status": "ready"})
		return
	}
	if c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0 {
		invalid(c, "body", "recording_audio")
		return
	}
	ticket, err := a.recordingAudioDirect.RecoverRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, sessions[0], id, checkAccount)
	if err != nil {
		recordingError(c, err)
		return
	}
	c.JSON(http.StatusOK, ticket)
}

// ConfigureRecordingAudioUpload is startup-only and requires the same tree
// and recovery readiness as the recording ticket route.
func (a *KaraokeAccounts) ConfigureRecordingAudioUpload(upload RecordingAudioUpload) error {
	if a == nil || a.recordingAudioReservation == nil || upload == nil || a.recordingAudioUpload != nil {
		return store.ErrRecordingState
	}
	a.recordingAudioUpload = upload
	return nil
}

func (a *KaraokeAccounts) uploadRecordingAudio(c *gin.Context, user *store.KaraokeUser, audit store.KaraokeAudit, action string) {
	p := a.public
	if a.recordingAudioUpload == nil || p.opaqueTree == nil {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	ingress, ok := p.recordingAudioIngress(c)
	if !ok {
		return
	}
	size := c.Request.ContentLength
	if len(c.Request.TransferEncoding) != 0 || (action == "recover" && size != 0) ||
		(action == "upload" && (size < 1 || size > store.MaxRecordingBytes || c.GetHeader("Content-Type") != "application/octet-stream")) ||
		!node.ValidIdentifier(c.Param("recording")) {
		invalid(c, "body", "recording_audio")
		return
	}
	sessionHeader := c.Request.Header.Values("X-Fc-Recording-Session")
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil || len(sessionHeader) != 1 || !node.ValidIdentifier(sessionHeader[0]) {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, sessionHeader[0])
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	checkAccount := a.recordingAccountCheck(c, user, true)
	controller := http.NewResponseController(c.Writer)
	body := http.MaxBytesReader(c.Writer, c.Request.Body, size)
	defer body.Close()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	if _, err = a.recordingAudioUpload(ctx, p.opaqueTree, expected, *user, browser, c.Param("recording"), action, size, controller, body, audit, checkAccount); err != nil {
		recordingError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recording_id": c.Param("recording"), "status": "ready"})
}

func (a *KaraokeAccounts) recordingAudioPrepare(c *gin.Context, user *store.KaraokeUser) {
	p := a.public
	if a.recordingAudioPreparation == nil || p.opaqueTree == nil {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	if !p.cryptoTransport(c) {
		return
	}
	if len(c.Request.Header.Values("Origin")) != 1 || c.GetHeader("Origin") == "" {
		detail(c, http.StatusForbidden, "录音密钥只允许同源访问")
		return
	}
	var body struct {
		SessionID     string `json:"session_id"`
		PlaintextSize int64  `json:"plaintext_size"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	if body.PlaintextSize <= 0 || body.PlaintextSize > store.MaxRecordingBytes {
		detail(c, http.StatusRequestEntityTooLarge, "加密录音超过单文件大小限制")
		return
	}
	ingress, err := p.cryptoIngress(c)
	if err != nil || ingress.Scope != "ingress" {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, body.SessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	meta, err := mediacrypto.NewMetadata(body.PlaintextSize)
	if err != nil {
		cryptoError(c, err)
		return
	}
	if meta.CiphertextSize > store.MaxRecordingBytes {
		detail(c, http.StatusRequestEntityTooLarge, "加密录音超过单文件大小限制")
		return
	}
	if user.Used < 0 || user.Quota <= user.Used || meta.CiphertextSize > user.Quota-user.Used {
		recordingError(c, store.ErrRecordingQuota)
		return
	}
	ip := a.resolver.Resolve(c.Request).IP
	if ip == "" || !a.recordingPreparationLimit.allow(ip, user.ID) {
		c.Header("Retry-After", strconv.Itoa(int(cryptoSessionCreationWindow/time.Second)))
		detail(c, http.StatusTooManyRequests, "录音加密准备过于频繁，请稍后重试")
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		internalError(c, err)
		return
	}
	recordingID := hex.EncodeToString(id[:])
	binding, err := recording.AudioPreparationBinding(user.ID, browser, recordingID)
	if err != nil {
		recordingError(c, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	if err = a.recordingAudioPreparation(ctx, p.opaqueTree, expected, user.ID, browser, recordingID, meta); err != nil || ctx.Err() != nil {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	envelope, err := p.crypto.Wrap(browser, body.SessionID, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	preparation, err := p.crypto.SignTransientPreparation(binding, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recording_id": recordingID, "encryption": meta, "key_envelope": envelope, "preparation_token": preparation})
}

// Bind the preparation to the authenticated account, current browser and
// actual encrypted source. A changed lyric relation requires a fresh snapshot.
func recordingLyricBinding(userID, browser, source, lyricFileID string) string {
	digest := sha256.Sum256([]byte(browser + "\x00" + source + "\x00" + lyricFileID))
	return "recording-lyric:" + userID + ":" + hex.EncodeToString(digest[:])
}

func (p *Public) recordingLyricSource(c *gin.Context, source string) (store.RecordingMetadata, string, bool) {
	metadata, fileID, err := p.media.RecordingLyricSource(c.Request.Context(), source)
	if err != nil {
		cryptoError(c, err)
		return store.RecordingMetadata{}, "", false
	}
	if fileID == "" {
		detail(c, 409, "当前媒体没有加密歌词")
		return store.RecordingMetadata{}, "", false
	}
	return metadata, fileID, true
}

func (p *Public) recordingCryptoPrepare(c *gin.Context, user *store.KaraokeUser) {
	// Until recording IDs participate in the sealed-tree reservation ledger,
	// do not issue a key envelope for an ID that could later be reused.
	if p.opaqueTree != nil {
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "Recording temporarily unavailable")
		return
	}
	if !p.cryptoTransport(c) {
		return
	}
	var body struct {
		Media         string `json:"media"`
		SessionID     string `json:"session_id"`
		PlaintextSize int64  `json:"plaintext_size"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	if body.PlaintextSize <= 0 || body.PlaintextSize > store.MaxEncryptedRecordingLyricPlaintext {
		detail(c, 413, "加密歌词快照超过大小限制")
		return
	}
	_, sourceID, ok := p.recordingLyricSource(c, body.Media)
	if !ok {
		return
	}
	browser, err := p.browserBinding(c, false)
	if err != nil {
		cryptoError(c, err)
		return
	}
	meta, err := mediacrypto.NewMetadata(body.PlaintextSize)
	if err != nil {
		cryptoError(c, err)
		return
	}
	envelope, err := p.crypto.Wrap(browser, body.SessionID, meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	preparation, err := p.crypto.SignPreparation(recordingLyricBinding(user.ID, browser, body.Media, sourceID), meta)
	if err != nil {
		cryptoError(c, err)
		return
	}
	c.JSON(200, gin.H{"encryption": meta, "key_envelope": envelope, "preparation_token": preparation})
}

func (p *Public) recordingCryptoKey(c *gin.Context, user *store.KaraokeUser) {
	if !p.cryptoTransport(c) {
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if !cryptoDecode(c, &body) {
		return
	}
	browser, err := p.browserBinding(c, false)
	if err != nil {
		cryptoError(c, err)
		return
	}
	snapshot, err := p.media.RecordingLyricSnapshot(c.Request.Context(), user.ID, c.Param("recording"))
	if err != nil {
		if err == mediacrypto.ErrMetadata {
			cryptoError(c, err)
		} else {
			recordingError(c, err)
		}
		return
	}
	envelope, err := p.crypto.Wrap(browser, body.SessionID, snapshot.Encryption)
	if err != nil {
		cryptoError(c, err)
		return
	}
	c.JSON(200, gin.H{"encrypted_lyrics": snapshot, "key_envelope": envelope})
}
