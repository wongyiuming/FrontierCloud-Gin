package httpapi

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

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
