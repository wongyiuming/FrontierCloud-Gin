package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueRecordingPreparationFailsClosedWithoutFileIDReservation(t *testing.T) {
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, _ := clusterFixture(t, "https://master.test", transport, false)
	router.POST("/recording-prepare-gate", func(c *gin.Context) {
		public.recordingCryptoPrepare(c, &store.KaraokeUser{ID: "recording-user"})
	})
	var before int
	if err := db.Database().QueryRow(`SELECT COUNT(*) FROM media_encryption`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	response := request(router, http.MethodPost, "/recording-prepare-gate", `{"media":"fixture","session_id":"session-secret","plaintext_size":20}`)
	var body map[string]any
	if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body["encryption"] != nil || body["key_envelope"] != nil || body["preparation_token"] != nil ||
		strings.Contains(response.Body.String(), "session-secret") || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("sealed tree issued a recording preparation or leaked the session", response.Code, response.Body.String())
	}
	var after int
	if err := db.Database().QueryRow(`SELECT COUNT(*) FROM media_encryption`).Scan(&after); err != nil || before != after {
		t.Fatal("failed preparation changed the encryption ledger", before, after, err)
	}
}
