package httpapi

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestOpaqueAdminPreparationFailsClosedWithoutFileIDReservation(t *testing.T) {
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, _, public, _ := clusterFixture(t, "https://master.test", transport, false)
	a := &Admin{public: public, settings: public.settings}
	group := router.Group("/prepare-gate", func(c *gin.Context) {
		c.Set("admin_session", admin.Session{Hash: "prepare-gate-admin"})
		c.Next()
	})
	group.POST("/session", a.cryptoSession)
	group.POST("/prepare", a.cryptoPrepare)
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())})
	response := request(router, http.MethodPost, "/prepare-gate/session", string(input))
	var session mediacrypto.SessionGrant
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &session) != nil || session.SessionID == "" {
		t.Fatal("crypto session", response.Code, response.Body.String())
	}
	input, _ = json.Marshal(gin.H{"session_id": session.SessionID, "plaintext_size": 20})
	var before int
	if err = db.Database().QueryRow(`SELECT COUNT(*) FROM media_encryption`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	response = request(router, http.MethodPost, "/prepare-gate/prepare", string(input))
	var body map[string]any
	if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body["encryption"] != nil || body["key_envelope"] != nil || body["preparation_token"] != nil ||
		strings.Contains(response.Body.String(), session.SessionID) || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("sealed tree issued a preparation or leaked the session", response.Code, response.Body.String())
	}
	var after int
	if err = db.Database().QueryRow(`SELECT COUNT(*) FROM media_encryption`).Scan(&after); err != nil || before != after {
		t.Fatal("failed preparation changed the encryption ledger", before, after, err)
	}
	// A mismatched tree or an uninitialized tree must not expose a key, even
	// when some startup code accidentally supplies a preparation configuration.
	a.selectedUpload = &business.SelectedUploadRuntime{}
	response = request(router, http.MethodPost, "/prepare-gate/prepare", string(input))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "key_envelope") {
		t.Fatal("mismatched tree issued a key", response.Code)
	}
	public.opaqueTree = nil
	response = request(router, http.MethodPost, "/prepare-gate/prepare", string(input))
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["key_envelope"] == nil || body["preparation_token"] == nil {
		t.Fatal("legacy preparation changed", response.Code, response.Body.String())
	}
}
