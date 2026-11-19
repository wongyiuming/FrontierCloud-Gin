package httpapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type RecordingAudioOpen func(context.Context, *sealedtree.SQLStore, store.PublicIngress, store.KaraokeUser, string, string, func(context.Context) error) (*business.RecordingAudioStream, error)

// ConfigureRecordingAudioRead is startup-only. The opener must bind the same
// tree and hold the authenticated ciphertext stream lease until Close.
func (a *KaraokeAccounts) ConfigureRecordingAudioRead(open RecordingAudioOpen) error {
	if a == nil || a.public == nil || a.public.opaqueTree == nil || a.public.crypto == nil || a.resolver == nil || open == nil || a.recordingAudioOpen != nil {
		return store.ErrRecordingState
	}
	a.recordingAudioOpen = open
	return nil
}

func (a *KaraokeAccounts) serveRecordingAudio(c *gin.Context, user *store.KaraokeUser, key bool) {
	p := a.public
	if p.opaqueTree == nil || (a.recordingAudioOpen == nil && (!key || a.recordingAudioDirect == nil)) {
		detail(c, http.StatusServiceUnavailable, "录音存储暂不可用")
		return
	}
	ingress, ok := p.recordingAudioIngress(c)
	if !ok {
		return
	}
	id := c.Param("recording")
	if !node.ValidIdentifier(id) || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		detail(c, http.StatusBadRequest, "录音请求无效")
		return
	}
	var sessionID string
	var start, end int64
	if key {
		var request struct {
			SessionID string `json:"session_id"`
		}
		if !smallStrictJSON(c, &request) {
			invalid(c, "body", "recording_audio_key")
			return
		}
		sessionID = request.SessionID
	} else {
		sessions := c.Request.Header.Values("X-Fc-Recording-Session")
		if len(sessions) != 1 || c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0 {
			cryptoError(c, mediacrypto.ErrSession)
			return
		}
		sessionID = sessions[0]
		if start, end, ok = parseOpaqueBrowserCipherRange(c.Request); !ok || start%(mediacrypto.ChunkSize+16) != 0 {
			detail(c, http.StatusRequestedRangeNotSatisfiable, "录音需要一个加密分块范围")
			return
		}
	}
	browser, err := browserBindingForIngress(c, false, ingress)
	if err != nil || !node.ValidIdentifier(sessionID) {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	ctx, err := p.crypto.WithDirectSession(c.Request.Context(), browser, sessionID)
	if err != nil {
		cryptoError(c, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	expected := store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.Origin, Generation: ingress.Generation}
	checkAccount := a.recordingAccountCheck(c, user, key)
	if key && a.recordingAudioDirect != nil {
		source, err := a.recordingAudioDirect.LookupRecordingAudioDirect(ctx, p.opaqueTree, expected, *user, browser, sessionID, id, checkAccount)
		if err == nil {
			remaining := source.ExpiresAt - time.Now().Unix()
			if remaining < 1 || remaining > 300 || ctx.Err() != nil {
				cryptoError(c, mediacrypto.ErrSession)
				return
			}
			envelope, err := p.crypto.Wrap(browser, sessionID, source.Encryption)
			if err != nil {
				cryptoError(c, err)
				return
			}
			c.JSON(http.StatusOK, gin.H{"recording_id": id, "encryption": source.Encryption, "key_envelope": envelope,
				"content_type": source.ContentType, "title": source.Title, "filename": recordingAudioFilename(id, source.ContentType), "source_revision": source.CipherSHA256,
				"source": gin.H{"transport": "Direct", "origin": source.ResourceOrigin, "url": source.ResourceOrigin + "/internal/v1/opaque-media/" + source.ReadAlias,
					"alias": source.ReadAlias, "owner_id": source.MemberID, "capability": source.Capability, "expires_in": remaining}})
			return
		}
	}
	if a.recordingAudioOpen == nil {
		detail(c, http.StatusForbidden, "录音读取暂不可用")
		return
	}
	stream, err := a.recordingAudioOpen(ctx, p.opaqueTree, expected, *user, browser, id, checkAccount)
	if stream != nil {
		defer stream.Close()
	}
	if err != nil || stream == nil {
		detail(c, http.StatusForbidden, "录音读取暂不可用")
		return
	}
	if stream.Encryption.Validate() != nil || stream.Size != stream.Encryption.CiphertextSize || stream.Size > store.MaxRecordingBytes ||
		!masterRelayID.MatchString(stream.SHA256) || !store.RecordingContentType(stream.ContentType) {
		detail(c, http.StatusForbidden, "录音读取暂不可用")
		return
	}
	if key {
		envelope, err := p.crypto.Wrap(browser, sessionID, stream.Encryption)
		if err != nil || ctx.Err() != nil {
			cryptoError(c, mediacrypto.ErrSession)
			return
		}
		filename := recordingAudioFilename(id, stream.ContentType)
		c.JSON(http.StatusOK, gin.H{"recording_id": id, "encryption": stream.Encryption, "key_envelope": envelope,
			"content_type": stream.ContentType, "title": stream.Title, "filename": filename, "source_revision": stream.SHA256})
		return
	}
	if start >= stream.Size || end != min(start+mediacrypto.ChunkSize+16, stream.Size)-1 {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(stream.Size, 10))
		detail(c, http.StatusRequestedRangeNotSatisfiable, "录音需要一个加密分块范围")
		return
	}
	if _, err := stream.Seek(start, io.SeekStart); err != nil {
		detail(c, http.StatusForbidden, "录音读取暂不可用")
		return
	}
	deadline, _ := ctx.Deadline()
	_, _, expires, active := mediacrypto.DirectSessionFromContext(ctx).Values()
	if !active {
		cryptoError(c, mediacrypto.ErrSession)
		return
	}
	if expiry := time.Unix(expires, 0); expiry.Before(deadline) {
		deadline = expiry
	}
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(deadline); err != nil {
		detail(c, http.StatusServiceUnavailable, "录音读取暂不可用")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	length := end - start + 1
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(length, 10))
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, stream.Size))
	c.Header("Accept-Ranges", "bytes")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("ETag", `"`+stream.SHA256+`"`)
	c.Status(http.StatusPartialContent)
	if _, err := io.CopyN(c.Writer, stream, length); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func recordingAudioFilename(id, contentType string) string {
	extension := map[string]string{"audio/webm": ".webm", "audio/ogg": ".ogg", "audio/mp4": ".m4a", "audio/mpeg": ".mp3", "audio/wav": ".wav"}[contentType]
	if extension == "" {
		extension = ".bin"
	}
	return "recording-" + id + extension
}
