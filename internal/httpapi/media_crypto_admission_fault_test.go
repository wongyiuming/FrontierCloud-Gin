package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type cryptoFaultLease struct {
	err      error
	onCommit func()
	commits  int
	released bool
}

func (l *cryptoFaultLease) Commit() error {
	l.commits++
	if l.onCommit != nil {
		l.onCommit()
	}
	return l.err
}
func (l *cryptoFaultLease) Release() { l.released = true }

func TestCryptoLocalLeaseFailureAbortsOnlyCreatedSession(t *testing.T) {
	for _, mode := range []string{"success", "commit failure", "cancel before commit", "cancel during commit", "panic", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			_, _, _, public := publicFixture(t, false)
			client, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())
			ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://master.example"}
			cookie := &http.Cookie{Name: mediaCryptoCookie, Value: strings.Repeat("b", 64)}
			bindingContext, _ := gin.CreateTestContext(httptest.NewRecorder())
			bindingContext.Request = httptest.NewRequest("POST", "https://master.example/", nil)
			bindingContext.Request.AddCookie(cookie)
			bindingContext.Request = bindingContext.Request.WithContext(context.WithValue(bindingContext.Request.Context(), localCryptoIngressKey{}, cryptoIngress{"ingress", ingress.NodeID, ingress.Generation, ingress.PublicOrigin}))
			binding, err := public.browserBinding(bindingContext, false)
			if err != nil {
				t.Fatal(err)
			}
			existing, err := public.crypto.NewSession(binding, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			lease := &cryptoFaultLease{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "commit failure" {
				lease.err = errors.New("test disconnect")
			} else if mode == "cancel during commit" {
				lease.onCommit = cancel
			}
			var created mediacrypto.SessionGrant
			router := gin.New()
			router.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) { c.AbortWithStatus(500) }))
			router.POST("/session", func(c *gin.Context) {
				serveCryptoWithIngressLease(c, ingress, lease, false)
			}, func(c *gin.Context) {
				c.Next()
				buffer := c.Writer.(*cryptoAdmissionWriter)
				if json.Unmarshal(buffer.body.Bytes(), &created) != nil || created.SessionID == "" {
					t.Fatal("handler did not create a session")
				}
				switch mode {
				case "cancel before commit":
					cancel()
				case "panic":
					panic("test handler panic")
				case "oversize":
					_, _ = buffer.Write(bytes.Repeat([]byte("x"), maxLocalCryptoResponse+1))
				}
			}, public.cryptoSession)
			payload, _ := json.Marshal(map[string]string{"public_key": publicKey})
			r := httptest.NewRequest("POST", "https://master.example/session", bytes.NewReader(payload)).WithContext(ctx)
			r.TLS = &tls.ConnectionState{}
			r.RemoteAddr = "198.51.100.1:1234"
			r.Header.Set("Origin", ingress.PublicOrigin)
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			meta, _ := mediacrypto.NewMetadata(32)
			if _, err := public.crypto.Wrap(binding, existing.SessionID, meta); err != nil {
				t.Fatal("failure changed a pre-existing session", err)
			}
			_, createdErr := public.crypto.Wrap(binding, created.SessionID, meta)
			if mode == "success" {
				if w.Code != 200 || createdErr != nil || lease.commits != 1 {
					t.Fatal("successful admission not retained", w.Code, createdErr, lease.commits)
				}
			} else {
				if w.Code < 500 || !errors.Is(createdErr, mediacrypto.ErrSession) || strings.Contains(w.Body.String(), created.SessionID) || len(w.Header().Values("Set-Cookie")) != 0 {
					t.Fatal("failed admission leaked or retained a session", w.Code, createdErr)
				}
			}
			if !lease.released {
				t.Fatal("lease was not released")
			}
		})
	}
}
