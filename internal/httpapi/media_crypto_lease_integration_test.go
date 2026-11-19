package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

const cryptoLeaseOrigin = "https://master.example"

func cryptoLeaseFixture(t *testing.T, master bool) (*gin.Engine, *sqlitestore.Store, string, *Public, string) {
	t.Helper()
	router, db, dir, public := publicFixture(t, false)
	ctx := context.Background()
	plain := []byte("ingress lease key")
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(meta)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := meta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	path, err := public.media.PublishEncrypted(ctx, stage, "lease.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	if master {
		if err := public.media.WithPromotion(ctx, "Master", func(promotion store.NodePromotion) error {
			promotion.Endpoint, promotion.Allocation = cryptoLeaseOrigin, 10*store.GiB
			_, err := db.Nodes().PromoteIdentity(ctx, promotion, store.NodeAudit{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
		if err := public.control.ConfigurePublicOrigin(cryptoLeaseOrigin); err != nil {
			t.Fatal(err)
		}
		// A real peer verifier initializes and reads this state before the
		// authenticated handler runs under its held shared lease.
		if _, err := db.Nodes().(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return router, db, dir, public, path
}

func cryptoLeasePayload(t *testing.T) []byte {
	t.Helper()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cryptoLeaseRequest(ctx context.Context, origin, route string, body io.ReadCloser, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, origin+route, nil).WithContext(ctx)
	r.Body = body
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

type heldCryptoBody struct {
	started chan struct{}
	proceed chan struct{}
	once    sync.Once
	reader  *bytes.Reader
}

func (b *heldCryptoBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.proceed
	return b.reader.Read(p)
}
func (b *heldCryptoBody) Close() error { return nil }

func TestMasterCryptoSessionAndKeyHoldIngressSelectionLease(t *testing.T) {
	router, db, _, _, path := cryptoLeaseFixture(t, true)
	repo := db.Nodes().(store.PublicRoutingRepository)
	request := func(route string, payload []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		body := &heldCryptoBody{started: make(chan struct{}), proceed: make(chan struct{}), reader: bytes.NewReader(payload)}
		var release sync.Once
		unblock := func() { release.Do(func() { close(body.proceed) }) }
		defer unblock()
		response := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, cryptoLeaseRequest(context.Background(), cryptoLeaseOrigin, route, body, cookie))
			response <- w
		}()
		select {
		case <-body.started:
		case <-time.After(5 * time.Second):
			t.Fatal("crypto handler did not read request")
		}
		blocked, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, err := repo.CommitMasterPublicIngress(blocked, cryptoLeaseOrigin, 1, store.NodeAudit{})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("ingress selection was not fenced during "+route, err)
		}
		unblock()
		select {
		case w := <-response:
			if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("%s: status %d", route, w.Code)
			}
			return w
		case <-time.After(5 * time.Second):
			t.Fatal("crypto handler did not finish after input was released")
			return nil
		}
	}
	session := request("/api/v1/media/crypto/session", cryptoLeasePayload(t), nil)
	var grant mediacrypto.SessionGrant
	if err := json.Unmarshal(session.Body.Bytes(), &grant); err != nil || grant.SessionID == "" {
		t.Fatal("invalid session grant", err)
	}
	cookies := session.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != mediaCryptoCookie {
		t.Fatal("missing browser binding cookie")
	}
	payload, _ := json.Marshal(gin.H{"session_id": grant.SessionID, "file_path": path})
	key := request("/api/v1/media/crypto/key", payload, cookies[0])
	var response struct {
		Envelope mediacrypto.KeyEnvelope `json:"key_envelope"`
	}
	if err := json.Unmarshal(key.Body.Bytes(), &response); err != nil || response.Envelope.ExpiresAt != grant.ExpiresAt {
		t.Fatal("key response changed or lost the session deadline", err)
	}
	selected, err := repo.CommitMasterPublicIngress(context.Background(), cryptoLeaseOrigin, 1, store.NodeAudit{})
	if err != nil || selected.Generation != 2 {
		t.Fatal("selection could not proceed after the requests finished", err)
	}
}

func TestCryptoIngressContextAvoidsDuplicateLeaseAndStandaloneNeedsNone(t *testing.T) {
	for _, master := range []bool{true, false} {
		name := "standalone"
		if master {
			name = "authenticated-peer"
		}
		t.Run(name, func(t *testing.T) {
			router, _, dir, public, path := cryptoLeaseFixture(t, master)
			file, err := os.OpenFile(filepath.Join(dir, "data.db"+store.PublicIngressLeaseSuffix), os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			release, err := filelease.Acquire(context.Background(), file, true)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			origin := public.settings.PublicOrigin
			var admission *network.PublicAdmission
			if master {
				identity, err := public.media.IdentityState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				ctx, err = network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: identity.ID, Generation: 1, PublicOrigin: cryptoLeaseOrigin, ClientIP: "192.0.2.1"})
				if err != nil {
					t.Fatal(err)
				}
				ctx, admission = network.WithPublicAdmission(ctx)
				defer admission.Abort()
				origin = cryptoLeaseOrigin
			}
			call := func(route string, payload []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				w := httptest.NewRecorder()
				router.ServeHTTP(w, cryptoLeaseRequest(ctx, origin, route, io.NopCloser(bytes.NewReader(payload)), cookie))
				if w.Code != http.StatusOK {
					t.Fatalf("%s status %d", route, w.Code)
				}
				return w
			}
			session := call("/api/v1/media/crypto/session", cryptoLeasePayload(t), nil)
			var grant mediacrypto.SessionGrant
			if err := json.Unmarshal(session.Body.Bytes(), &grant); err != nil || grant.SessionID == "" {
				t.Fatal("invalid session grant", err)
			}
			if admission != nil && !admission.Commit() {
				t.Fatal("authenticated admission did not commit")
			}
			cookies := session.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing cookie")
			}
			payload, _ := json.Marshal(gin.H{"session_id": grant.SessionID, "file_path": path})
			key := call("/api/v1/media/crypto/key", payload, cookies[0])
			if !bytes.Contains(key.Body.Bytes(), []byte("wrapped_key")) {
				t.Fatal("key envelope missing")
			}
		})
	}
}

func TestCryptoSessionAdmissionAbortOnlyRevokesItsOwnGrant(t *testing.T) {
	router, _, _, public, path := cryptoLeaseFixture(t, true)
	identity, err := public.media.IdentityState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := network.WithAuthenticatedIngress(context.Background(), network.AuthenticatedIngress{
		NodeID: identity.ID, Generation: 1, PublicOrigin: cryptoLeaseOrigin, ClientIP: "192.0.2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := cryptoLeasePayload(t)
	create := func(cookie *http.Cookie) (mediacrypto.SessionGrant, *http.Cookie, *network.PublicAdmission, context.CancelFunc) {
		t.Helper()
		ctx, cancel := context.WithCancel(verified)
		ctx, admission := network.WithPublicAdmission(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, cryptoLeaseRequest(ctx, cryptoLeaseOrigin, "/api/v1/media/crypto/session", io.NopCloser(bytes.NewReader(payload)), cookie))
		if w.Code != http.StatusOK {
			cancel()
			t.Fatalf("session status %d", w.Code)
		}
		var grant mediacrypto.SessionGrant
		if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil || grant.SessionID == "" {
			cancel()
			t.Fatal("invalid session grant", err)
		}
		if cookie == nil {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				cancel()
				t.Fatal("missing browser binding cookie")
			}
			cookie = cookies[0]
		}
		return grant, cookie, admission, cancel
	}
	first, cookie, firstAdmission, firstCancel := create(nil)
	if !firstAdmission.Commit() {
		t.Fatal("successful admission was not committed")
	}
	firstCancel()
	failed, _, failedAdmission, failedCancel := create(cookie)
	if !failedAdmission.Abort() {
		t.Fatal("failed admission did not own a session rollback")
	}
	failedCancel()
	canceled, _, canceledAdmission, cancel := create(cookie)
	cancel()
	if !canceledAdmission.Abort() {
		t.Fatal("cancellation did not roll back its session")
	}

	for _, check := range []struct {
		grant mediacrypto.SessionGrant
		want  int
	}{
		{first, http.StatusOK}, {failed, http.StatusUnauthorized}, {canceled, http.StatusUnauthorized},
	} {
		body, _ := json.Marshal(gin.H{"session_id": check.grant.SessionID, "file_path": path})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, cryptoLeaseRequest(verified, cryptoLeaseOrigin, "/api/v1/media/crypto/key", io.NopCloser(bytes.NewReader(body)), cookie))
		if w.Code != check.want {
			t.Fatalf("key status %d, want %d", w.Code, check.want)
		}
		if check.want == http.StatusOK {
			var result struct {
				Envelope mediacrypto.KeyEnvelope `json:"key_envelope"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Envelope.ExpiresAt != first.ExpiresAt {
				t.Fatal("rollback changed the surviving grant's expiry", err)
			}
		}
	}
}
