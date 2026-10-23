package node

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestMusicMetadataRangeValidatesNativeIdentityAndExactTail(t *testing.T) {
	object, resource, owner := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32)
	payload := append([]byte("TAG"), bytes.Repeat([]byte("x"), 125)...)
	for _, kind := range []string{"valid", "whole-file-200", "wrong-range", "wrong-total", "wrong-owner", "wrong-resource", "wrong-object", "encoding", "duplicate-range", "duplicate-owner", "short-body", "long-body", "chunked-short", "chunked-long"} {
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
				case "short-body", "chunked-short":
					body = payload[:127]
				case "long-body", "chunked-long":
					body = append(append([]byte{}, payload...), 0)
				}
				if !strings.HasPrefix(kind, "chunked-") {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
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
			}
		})
	}
}
