package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedIngressRepository struct {
	store.NodeRepository
	store.PublicRoutingRepository
	selected store.PublicIngress
}

func (r selectedIngressRepository) PublicIngress(context.Context) (store.PublicIngress, error) {
	return r.selected, nil
}

// Exercises the real Master issuer, relationship vault and owner HTTP reader.
// The test injects the ingress assertion normally installed by the verifier;
// it does not claim selection or a deployed ingress is available.
func TestIngressCapabilityOwnerReadCORSAndDescriptor(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	storageRouter, _, storageDir, storagePublic, follower := clusterFixture(t, "https://follower.test", transport, true)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := db.Nodes().Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err := db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	observed, _, err := follower.ObservedPublicIngress(ctx)
	if err != nil {
		t.Fatal("authenticated heartbeat did not publish ingress observation", err)
	}
	preflight := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodOptions, "https://follower.test/internal/v1/media/"+strings.Repeat("a", 64), nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "GET")
		r.Header.Set("Access-Control-Request-Headers", "x-media-capability, range")
		w := httptest.NewRecorder()
		storageRouter.ServeHTTP(w, r)
		return w
	}
	if w := preflight(observed.PublicOrigin); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != observed.PublicOrigin {
		t.Fatal("observed ingress preflight failed", w.Code, w.Header())
	}
	if w := preflight("https://untrusted.test"); w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("untrusted preflight allowed", w.Code, w.Header())
	}
	unauthenticated := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/media/"+strings.Repeat("a", 64), nil)
	unauthenticated.Header.Set("Origin", observed.PublicOrigin)
	unauthenticatedResponse := httptest.NewRecorder()
	storageRouter.ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatal("preflight created resource authority", unauthenticatedResponse.Code)
	}
	probeRequest := httptest.NewRequest(http.MethodPost, "https://follower.test"+node.NativePlainProbePath, strings.NewReader(`{"challenge":"`+strings.Repeat("1", 32)+`","token":"forged"}`))
	probeResponse := httptest.NewRecorder()
	storageRouter.ServeHTTP(probeResponse, probeRequest)
	if probeResponse.Code != http.StatusUnauthorized || !strings.Contains(probeResponse.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("anonymous v4 readiness probe accepted", probeResponse.Code)
	}
	mediaProbeRequest := httptest.NewRequest(http.MethodGet, "https://follower.test"+node.NativePlainMediaProbePath, nil)
	mediaProbeRequest.Header.Set("X-Fc-Plain-Probe", strings.Repeat("1", 32))
	mediaProbeRequest.Header.Set("X-Media-Capability", "forged")
	mediaProbeResponse := httptest.NewRecorder()
	storageRouter.ServeHTTP(mediaProbeResponse, mediaProbeRequest)
	if mediaProbeResponse.Code != http.StatusUnauthorized {
		t.Fatal("anonymous actual media-path probe accepted", mediaProbeResponse.Code)
	}
	if err := db.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	tokenClient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenBinding := "browser:v2:" + strings.Repeat("c", 64)
	tokenSession, err := public.crypto.NewSession(tokenBinding, base64.StdEncoding.EncodeToString(tokenClient.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		filename, payload := "plain.mp3", []byte("ID3payload")
		var meta *mediacrypto.Metadata
		if encrypted {
			filename = "cipher.mp3"
			value, err := mediacrypto.NewMetadata(10)
			if err != nil {
				t.Fatal(err)
			}
			meta, payload = &value, bytes.Repeat([]byte{'x'}, int(value.CiphertextSize))
		}
		ticket, err := public.media.ReserveMasterEncryptedUpload(ctx, filename, "music/Ingress", "", "direct", int64(len(payload)), 255, store.AdminAudit{}, meta)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := db.Pool().Upload(ctx, ticket.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = master.UploadStorage(ctx, reservation, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		if _, err = public.media.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
		if _, err = master.MediaIngressCapability(ctx, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), time.Now().Unix()+300, meta); err == nil {
			t.Fatal("unauthenticated context issued a grant")
		}
		legacy, err := master.MediaCapability(ctx, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, "", "")
		if err != nil {
			t.Fatal(err)
		}
		legacyOptions := httptest.NewRequest(http.MethodOptions, "https://follower.test/internal/v1/media/"+ticket.MediaID+"?"+url.Values{"token": {legacy}}.Encode(), nil)
		legacyOptions.Header.Set("Origin", "https://master.test")
		legacyOptions.Header.Set("Access-Control-Request-Method", "GET")
		legacyOptions.Header.Set("Access-Control-Request-Headers", "if-range")
		legacyResponse := httptest.NewRecorder()
		storageRouter.ServeHTTP(legacyResponse, legacyOptions)
		if legacyResponse.Code != http.StatusOK || legacyResponse.Header().Get("Access-Control-Allow-Origin") != "https://master.test" {
			t.Fatal("legacy query capability preflight regressed", legacyResponse.Code, legacyResponse.Header())
		}
		for _, target := range []struct{ ingress, origin string }{{ticket.MemberID, "https://follower.test"}, {strings.Repeat("a", 32), "https://entry.test"}} {
			verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: target.ingress, Generation: 12, PublicOrigin: target.origin, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			verified, admission := network.WithPublicAdmission(verified)
			defer admission.Abort()
			if _, err := master.MediaIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), time.Now().Unix()+60, meta); err == nil {
				t.Fatal("missing session issued resource grant")
			}
			verified, err = public.crypto.WithDirectSession(verified, tokenBinding, tokenSession.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Unix() + 60
			var token string
			if encrypted {
				token, err = master.MediaIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), deadline, meta)
			} else {
				sum := sha256.Sum256(payload)
				token, err = master.MediaPlainIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), deadline, hex.EncodeToString(sum[:]))
			}
			if err != nil {
				t.Fatal(err)
			}
			_, claims, err := follower.VerifyOwnedMedia(ctx, token, ticket.MediaID)
			if err != nil {
				t.Fatal(err)
			}
			expires, err := claims["e"].(json.Number).Int64()
			if err != nil || expires > deadline {
				t.Fatal("resource grant outlived its session", expires, deadline, err)
			}
			if _, err := master.MediaIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), time.Now().Unix()-1, meta); err == nil {
				t.Fatal("expired session issued resource grant")
			}
			read := func(token, origin, object string) *httptest.ResponseRecorder {
				target := "https://follower.test/internal/v1/media/" + object
				if token == legacy {
					target += "?" + url.Values{"token": {token}}.Encode()
				}
				r := httptest.NewRequest(http.MethodGet, target, nil)
				if token != legacy {
					r.Header.Set("X-Media-Capability", token)
				}
				r.Header.Set("Origin", origin)
				r.Header.Set("Range", "bytes=1-3")
				w := httptest.NewRecorder()
				storageRouter.ServeHTTP(w, r)
				return w
			}
			w := read(token, target.origin, ticket.MediaID)
			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) || w.Header().Get("Access-Control-Allow-Origin") != target.origin || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("owner read encrypted=%v: %d %v %q", encrypted, w.Code, w.Header(), w.Body.Bytes())
			}
			queryRequest := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/media/"+ticket.MediaID+"?"+url.Values{"token": {token}}.Encode(), nil)
			queryResponse := httptest.NewRecorder()
			storageRouter.ServeHTTP(queryResponse, queryRequest)
			if queryResponse.Code != http.StatusUnauthorized {
				t.Fatal("v3 query capability accepted", queryResponse.Code)
			}
			if w := read(token, "https://other.test", ticket.MediaID); w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("wrong origin accepted", w.Code)
			}
			if target.origin != "https://master.test" {
				if w := read(legacy, target.origin, ticket.MediaID); w.Code != http.StatusForbidden {
					t.Fatal("legacy grant widened CORS", w.Code)
				}
			}
			if w := read(token, target.origin, strings.Repeat("f", 64)); w.Code != http.StatusUnauthorized {
				t.Fatal("wrong object accepted", w.Code)
			}
			if encrypted {
				if _, err := master.MediaIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), deadline, nil); err == nil {
					t.Fatal("descriptor downgrade issued")
				}
			} else {
				if _, err := master.MediaIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), deadline, nil); err == nil {
					t.Fatal("plaintext without content proof issued")
				}
				wrong, err := master.MediaPlainIngressCapability(verified, id, ticket.MemberID, ticket.MediaID, ticket.MediaID, int64(len(payload)), deadline, strings.Repeat("0", 64))
				if err != nil {
					t.Fatal(err)
				}
				if w := read(wrong, target.origin, ticket.MediaID); w.Code != http.StatusConflict {
					t.Fatal("plaintext with wrong content proof accepted", w.Code)
				}
				// The first read built the index. Bypass the cooperative lock in
				// this isolated fixture to simulate same-length external tampering.
				filename := filepath.Join(storageDir, "media", filepath.FromSlash(ticket.Path))
				owner := httptest.NewTLSServer(storageRouter)
				request, err := http.NewRequest(http.MethodGet, owner.URL+"/internal/v1/media/"+ticket.MediaID, nil)
				if err != nil {
					owner.Close()
					t.Fatal(err)
				}
				request.Header.Set("Origin", target.origin)
				request.Header.Set("X-Media-Capability", token)
				request.Header.Set("Range", "bytes=1-3")
				healthy, err := owner.Client().Do(request)
				if err != nil {
					owner.Close()
					t.Fatal("healthy TLS read", err)
				}
				healthyBytes, err := io.ReadAll(healthy.Body)
				healthy.Body.Close()
				if err != nil || healthy.StatusCode != http.StatusPartialContent || !bytes.Equal(healthyBytes, payload[1:4]) {
					owner.Close()
					t.Fatal("healthy TLS range", err)
				}
				if err := os.WriteFile(filename, []byte("ID3changed"), 0600); err != nil {
					owner.Close()
					t.Fatal(err)
				}
				response, readErr := owner.Client().Do(request)
				if readErr == nil {
					body, bodyErr := io.ReadAll(response.Body)
					response.Body.Close()
					if bodyErr == nil || len(body) != 0 {
						owner.Close()
						t.Fatal("tampered cached chunk produced a complete response", bodyErr)
					}
				}
				owner.Close()
				if err := os.WriteFile(filename, payload, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !encrypted {
			selected := store.PublicIngress{NodeID: ticket.MemberID, PublicOrigin: "https://follower.test", Generation: 12}
			routing := selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: selected}
			public.media.ConfigureCluster(routing, db.Pool(), master)
			verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: selected.NodeID, PublicOrigin: selected.PublicOrigin, Generation: selected.Generation, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			verified, admission := network.WithPublicAdmission(verified)
			verified, err = public.crypto.WithDirectSession(verified, tokenBinding, tokenSession.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			object, err := public.media.CryptoObject(verified, ticket.Path, ticket.MediaID, false)
			if err != nil {
				t.Fatal(err)
			}
			source, token, revision, size, err := public.media.IngressLocalPlainSource(verified, object, ticket.MediaID, time.Now().Unix()+60)
			if err != nil || source != selected.PublicOrigin+"/internal/v1/media/"+ticket.MediaID || len(revision) != 64 || size != int64(len(payload)) {
				t.Fatal("plaintext Local source", source, size, err)
			}
			r := httptest.NewRequest(http.MethodGet, source, nil)
			r.Header.Set("X-Media-Capability", token)
			r.Header.Set("Range", "bytes=1-3")
			w := httptest.NewRecorder()
			storageRouter.ServeHTTP(w, r)
			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) {
				t.Fatal("plaintext Local owner range", w.Code, w.Body.String())
			}
			call := func(route string, value any, cookie *http.Cookie) *httptest.ResponseRecorder {
				body, _ := json.Marshal(value)
				requestContext, requestAdmission := network.WithPublicAdmission(verified)
				defer requestAdmission.Abort()
				request := httptest.NewRequest(http.MethodPost, selected.PublicOrigin+route, bytes.NewReader(body)).WithContext(requestContext)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", selected.PublicOrigin)
				if cookie != nil {
					request.AddCookie(cookie)
				}
				result := httptest.NewRecorder()
				masterRouter.ServeHTTP(result, request)
				if result.Code == http.StatusOK && !requestAdmission.Commit() {
					t.Fatal("plaintext source admission")
				}
				return result
			}
			session := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(tokenClient.PublicKey().Bytes())}, nil)
			var browserSession mediacrypto.SessionGrant
			if session.Code != http.StatusOK || json.Unmarshal(session.Body.Bytes(), &browserSession) != nil || len(session.Result().Cookies()) != 1 {
				t.Fatal("plaintext Local session", session.Code)
			}
			plan := call("/api/v1/media/crypto/native/source", gin.H{"session_id": browserSession.SessionID, "file_path": ticket.Path, "resource_id": ticket.MediaID, "object_id": ticket.MediaID}, session.Result().Cookies()[0])
			var grant struct {
				SourceURL string            `json:"source_url"`
				Transport string            `json:"source_transport"`
				Headers   map[string]string `json:"source_headers"`
			}
			if plan.Code != http.StatusOK || json.Unmarshal(plan.Body.Bytes(), &grant) != nil || grant.Transport != "Local" || grant.SourceURL != source || grant.Headers["X-Media-Capability"] == "" {
				t.Fatal("plaintext Local HTTP plan", plan.Code, plan.Body.String())
			}
			request := httptest.NewRequest(http.MethodGet, grant.SourceURL, nil)
			request.Header.Set("X-Media-Capability", grant.Headers["X-Media-Capability"])
			request.Header.Set("Range", "bytes=1-3")
			result := httptest.NewRecorder()
			storageRouter.ServeHTTP(result, request)
			if result.Code != http.StatusPartialContent || !bytes.Equal(result.Body.Bytes(), payload[1:4]) {
				t.Fatal("plaintext Local HTTP range", result.Code)
			}
			nginxSettings := storagePublic.settings
			nginxSettings.NginxMedia = true
			nginxRouter := gin.New()
			resolver, err := network.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			RegisterNodeMedia(nginxRouter, nginxSettings, resolver, follower, storagePublic.media)
			nginxResult := httptest.NewRecorder()
			nginxRouter.ServeHTTP(nginxResult, request.Clone(ctx))
			if nginxResult.Code != http.StatusPartialContent || !bytes.Equal(nginxResult.Body.Bytes(), payload[1:4]) || nginxResult.Header().Get("X-Accel-Redirect") != "" {
				t.Fatal("plaintext read escaped lease through X-Accel", nginxResult.Code)
			}
			admission.Abort()
			public.media.ConfigureCluster(db.Nodes(), db.Pool(), master)
		}
		if encrypted {
			// The production store deliberately blocks peer activation. Substitute
			// only the selected-ingress read to exercise the eventual Local path.
			selected := store.PublicIngress{NodeID: ticket.MemberID, PublicOrigin: "https://follower.test", Generation: 12}
			routing := selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: selected}
			public.media.ConfigureCluster(routing, db.Pool(), master)
			masterPublic := httptest.NewRecorder()
			masterPublicTarget := "https://master.test/api/v1/media/stream?" + url.Values{"file_path": {ticket.Path}, "resource_id": {ticket.MediaID}}.Encode()
			masterRouter.ServeHTTP(masterPublic, httptest.NewRequest(http.MethodGet, masterPublicTarget, nil))
			if masterPublic.Code < 400 || masterPublic.Header().Get("Location") != "" || masterPublic.Header().Get("X-Accel-Redirect") != "" {
				t.Fatalf("Master after leaving ingress issued new public resource authority: %d %v", masterPublic.Code, masterPublic.Header())
			}
			// A capability issued before selection retains its existing bounded
			// lifetime and remains usable on the original owner.
			drainRequest := httptest.NewRequest(http.MethodGet, "https://follower.test/internal/v1/media/"+ticket.MediaID+"?"+url.Values{"token": {legacy}}.Encode(), nil)
			drainRequest.Header.Set("Origin", "https://master.test")
			drainRequest.Header.Set("Range", "bytes=1-3")
			drain := httptest.NewRecorder()
			storageRouter.ServeHTTP(drain, drainRequest)
			if drain.Code != http.StatusPartialContent || !bytes.Equal(drain.Body.Bytes(), payload[1:4]) {
				t.Fatalf("previous short-lived capability did not drain: %d", drain.Code)
			}
			verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: selected.NodeID, PublicOrigin: selected.PublicOrigin, Generation: selected.Generation, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			verified, admission := network.WithPublicAdmission(verified)
			defer admission.Abort()
			verified, err = public.crypto.WithDirectSession(verified, tokenBinding, tokenSession.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			object, err := public.media.CryptoObject(verified, ticket.Path, ticket.MediaID, false)
			if err != nil {
				t.Fatal(err)
			}
			source, capability, err := public.media.IngressLocalSource(verified, object, time.Now().Unix()+300)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(source)
			if err != nil || u.Scheme != "https" || u.Host != "follower.test" || u.Path != "/internal/v1/media/"+ticket.MediaID || u.RawQuery != "" || capability == "" {
				t.Fatal("wrong local path", source, err)
			}
			r := httptest.NewRequest(http.MethodGet, source, nil)
			r.Header.Set("Range", "bytes=1-3")
			r.Header.Set("Origin", selected.PublicOrigin)
			r.Header.Set("X-Media-Capability", capability)
			w := httptest.NewRecorder()
			storageRouter.ServeHTTP(w, r)
			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), payload[1:4]) || w.Header().Get("Content-Type") != "application/octet-stream" {
				t.Fatal("local ciphertext route failed", w.Code, w.Header())
			}
			for _, name := range []string{"X-Media-Resource-ID", "X-Media-Owner-ID", "X-Media-Object-ID", "X-Media-Parent-Request-ID", "X-Audit-Trace-ID"} {
				if w.Header().Get(name) != "" {
					t.Fatalf("browser capability exposed %s", name)
				}
			}
			stale, _ := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: selected.NodeID, PublicOrigin: selected.PublicOrigin, Generation: selected.Generation - 1, ClientIP: "192.0.2.1"})
			if _, _, err := public.media.IngressLocalSource(stale, object, time.Now().Unix()+300); err == nil {
				t.Fatal("stale ingress obtained a source")
			}
			if _, _, err := public.media.IngressLocalSource(ctx, object, time.Now().Unix()+300); err == nil {
				t.Fatal("direct request obtained peer source")
			}
			client, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			call := func(route string, value any, cookie *http.Cookie) *httptest.ResponseRecorder {
				body, _ := json.Marshal(value)
				requestContext, requestAdmission := network.WithPublicAdmission(verified)
				defer requestAdmission.Abort()
				r := httptest.NewRequest(http.MethodPost, selected.PublicOrigin+route, bytes.NewReader(body)).WithContext(requestContext)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", selected.PublicOrigin)
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				masterRouter.ServeHTTP(w, r)
				if w.Code == http.StatusOK && !requestAdmission.Commit() {
					t.Fatal("request admission failed")
				}
				return w
			}
			session := call("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
			var grant mediacrypto.SessionGrant
			if session.Code != http.StatusOK || json.Unmarshal(session.Body.Bytes(), &grant) != nil || len(session.Result().Cookies()) != 1 {
				t.Fatal("session", session.Code)
			}
			keyResponse := call("/api/v1/media/crypto/key", gin.H{"session_id": grant.SessionID, "file_path": ticket.Path, "resource_id": ticket.MediaID}, session.Result().Cookies()[0])
			var issued struct {
				SourceURL       string            `json:"source_url"`
				SourceHeaders   map[string]string `json:"source_headers"`
				SourceExpiresAt int64             `json:"source_expires_at"`
				SourceExpiresIn int64             `json:"source_expires_in"`
			}
			if keyResponse.Code != http.StatusOK || json.Unmarshal(keyResponse.Body.Bytes(), &issued) != nil || issued.SourceURL != source || issued.SourceHeaders["X-Media-Capability"] == "" || strings.Contains(issued.SourceURL, "?") || strings.Contains(keyResponse.Body.String(), `?token=`) {
				t.Fatalf("local authorization did not use a header: %d %s", keyResponse.Code, keyResponse.Body.String())
			}
			_, issuedClaims, err := follower.VerifyOwnedMedia(ctx, issued.SourceHeaders["X-Media-Capability"], ticket.MediaID)
			if err != nil {
				t.Fatal(err)
			}
			issuedExpiry, err := issuedClaims["e"].(json.Number).Int64()
			if err != nil || issuedExpiry > grant.ExpiresAt || issued.SourceExpiresAt > issuedExpiry || issued.SourceExpiresIn < 1 || issued.SourceExpiresIn > 300 {
				t.Fatal("local read outlived browser session", issuedExpiry, grant.ExpiresAt, err)
			}
		}
	}
	_ = storagePublic
}
