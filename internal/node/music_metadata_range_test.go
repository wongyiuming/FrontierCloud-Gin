package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMusicMetadataRangeValidatesNativeIdentityAndExactTail(t *testing.T) {
	object, resource, owner := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32)
	payload := append([]byte("TAG"), bytes.Repeat([]byte("x"), 125)...)
	for _, kind := range []string{"valid", "whole-file-200", "wrong-range", "wrong-total", "wrong-owner", "wrong-resource", "wrong-object", "encoding", "duplicate-range", "duplicate-owner", "short-body", "long-body", "chunked-short", "chunked-long", "truncated-body", "unauthorized", "forbidden"} {
		t.Run(kind, func(t *testing.T) {
			server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/v1/media/"+object || r.Header.Get("Range") != "bytes=384-511" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("X-Media-Capability") != "bounded-capability" {
					t.Error("request escaped bounded metadata contract")
				}
				w.Header().Set("X-Media-Object-ID", object)
				w.Header().Set("X-Media-Resource-ID", resource)
				w.Header().Set("X-Media-Owner-ID", owner)
				w.Header().Set("Content-Range", "bytes 384-511/512")
				status := 206
				body := payload
				switch kind {
				case "whole-file-200":
					status = 200
				case "unauthorized":
					status = 401
				case "forbidden":
					status = 403
				case "wrong-range":
					w.Header().Set("Content-Range", "bytes 383-510/512")
				case "wrong-total":
					w.Header().Set("Content-Range", "bytes 384-511/513")
				case "wrong-owner":
					w.Header().Set("X-Media-Owner-ID", strings.Repeat("d", 32))
				case "wrong-resource":
					w.Header().Set("X-Media-Resource-ID", object)
				case "wrong-object":
					w.Header().Set("X-Media-Object-ID", resource)
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "duplicate-range":
					w.Header().Add("Content-Range", "bytes 384-511/512")
				case "duplicate-owner":
					w.Header().Add("X-Media-Owner-ID", owner)
				case "short-body", "chunked-short", "truncated-body":
					body = payload[:127]
				case "long-body", "chunked-long":
					body = append(append([]byte{}, payload...), 0)
				}
				if !strings.HasPrefix(kind, "chunked-") {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				}
				if kind == "truncated-body" {
					w.Header().Set("Content-Length", "128")
				}
				w.WriteHeader(status)
				if strings.HasPrefix(kind, "chunked-") {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write(body)
			}))
			transport := testTransport(t, server, roots)
			got, err := transport.MediaReadRange(context.Background(), "https://node.test", object, resource, owner, "bounded-capability", 512, 384, 511)
			if kind == "valid" {
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("unproven response accepted", kind)
			} else if errors.Is(err, ErrMediaRangeUnavailable) || got != nil {
				t.Fatal("permanent range refusal became retryable or returned bytes", kind, err)
			}
		})
	}
}

func TestMusicMetadataRangeTransportFailuresAreSanitizedAndRetryable(t *testing.T) {
	object, resource, owner := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32)
	token := "private-metadata-capability-do-not-log"
	for _, kind := range []string{"deadline-before-headers", "deadline-after-headers", "cancel-after-headers", "connection-refused", "untrusted-ca", "wrong-host"} {
		t.Run(kind, func(t *testing.T) {
			started := make(chan struct{}, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				started <- struct{}{}
				if kind != "deadline-before-headers" {
					w.Header().Set("X-Media-Object-ID", object)
					w.Header().Set("X-Media-Resource-ID", resource)
					w.Header().Set("X-Media-Owner-ID", owner)
					w.Header().Set("Content-Range", "bytes 384-511/512")
					w.Header().Set("Content-Length", "128")
					w.WriteHeader(http.StatusPartialContent)
					w.(http.Flusher).Flush()
				}
				if kind == "cancel-after-headers" {
					cancel()
				}
				<-r.Context().Done()
			}))
			if strings.HasPrefix(kind, "deadline-") {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
			}
			if kind == "untrusted-ca" {
				roots = x509.NewCertPool()
			}
			transport := testTransport(t, server, roots)
			if kind == "connection-refused" {
				server.Close()
			}
			origin := "https://node.test"
			if kind == "wrong-host" {
				origin = "https://wrong-name.test"
			}
			got, err := transport.MediaReadRange(ctx, origin, object, resource, owner, token, 512, 384, 511)
			if got != nil || !errors.Is(err, ErrMediaRangeUnavailable) {
				t.Fatal("transport failure lost its safe retry classification", kind, err)
			}
			for _, secret := range []string{token, origin, object, resource, owner, server.URL} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("transport diagnostic disclosed peer or capability data", kind)
				}
			}
			if strings.HasPrefix(kind, "deadline-") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline cause was lost", err)
			}
			if kind == "cancel-after-headers" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause was lost", err)
			}
			select {
			case <-started:
				if kind == "untrusted-ca" || kind == "wrong-host" || kind == "connection-refused" {
					t.Fatal("unverified HTTPS request reached the handler", kind)
				}
			default:
				if strings.HasPrefix(kind, "deadline-") || kind == "cancel-after-headers" {
					t.Fatal("failure did not exercise the actual HTTPS request", kind)
				}
			}
		})
	}
}
