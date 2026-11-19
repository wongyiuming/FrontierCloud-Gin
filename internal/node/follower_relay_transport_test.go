package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFollowerRelayTransportValidatesRangeAndFraming(t *testing.T) {
	object := strings.Repeat("a", 64)
	for _, variant := range []string{"valid", "wrong-range", "whole-file", "wrong-length", "encoding", "redirect"} {
		t.Run(variant, func(t *testing.T) {
			server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/v1/media/"+object || r.URL.RawQuery != "" || r.Header.Get("Range") != "bytes=1-3" || r.Header.Get("X-Media-Capability") != "private-owner-bearer" || r.Header.Get("Origin") != "" {
					t.Error("incorrect owner request")
				}
				w.Header().Set("Content-Range", "bytes 1-3/6")
				w.Header().Set("Content-Length", "3")
				status := http.StatusPartialContent
				switch variant {
				case "wrong-range":
					w.Header().Set("Content-Range", "bytes 0-2/6")
				case "wrong-length":
					w.Header().Set("Content-Length", "2")
				case "whole-file":
					status = http.StatusOK
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "redirect":
					status = http.StatusFound
					w.Header().Set("Location", "https://elsewhere.test/")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "bcd")
			}))
			transport := testTransport(t, server, roots)
			got, err := transport.MediaRelayRead(context.Background(), "https://node.test", object, "private-owner-bearer", "GET", "bytes=1-3", 6)
			if variant != "valid" {
				if err == nil || strings.Contains(err.Error(), "private-owner-bearer") {
					t.Fatal("unsafe response or secret-bearing error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer got.Body.Close()
			body, err := io.ReadAll(got.Body)
			if err != nil || string(body) != "bcd" || got.Status != 206 || got.Length != 3 || got.ContentRange != "bytes 1-3/6" {
				t.Fatal(got, string(body), err)
			}
		})
	}
}

func TestOpaqueFollowerRelayEmptyFileMatchesOwner(t *testing.T) {
	alias := strings.Repeat("a", 64)
	for _, nginx := range []bool{false, true} {
		server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/internal/v1/opaque-media/"+alias || r.URL.RawQuery != "" || r.Header.Get("X-Media-Capability") != "empty-bearer" {
				t.Error("incorrect owner request")
			}
			if nginx {
				r.Header.Del("Range")
			}
			http.ServeContent(w, r, "blob", time.Time{}, bytes.NewReader(nil))
		}))
		transport := testTransport(t, server, roots)
		for _, method := range []string{"GET", "HEAD"} {
			for _, tc := range []struct {
				value        string
				status       int
				contentRange string
			}{
				{"", 200, ""}, {"bytes=0-0", 200, ""}, {"bytes=-1", 206, "bytes 0--1/0"},
			} {
				if nginx {
					tc.status, tc.contentRange = 200, ""
				}
				got, err := transport.MediaOpaqueRelayRead(context.Background(), "https://node.test", alias, "empty-bearer", method, tc.value, 0)
				if err != nil {
					t.Fatal(method, tc.value, err)
				}
				body, err := io.ReadAll(got.Body)
				got.Body.Close()
				if err != nil || len(body) != 0 || got.Length != 0 || got.Status != tc.status || got.ContentRange != tc.contentRange {
					t.Fatal(method, tc.value, got, err)
				}
			}
		}
		if _, err := transport.MediaOpaqueRelayRead(context.Background(), "https://node.test", alias, "empty-bearer", "GET", "bytes=0-1,2-3", 0); err != ErrFollowerRelayRange {
			t.Fatal("multipart range accepted", err)
		}
	}
}

func TestOpaqueFollowerRelayTransportUsesOnlyAliasAndPinnedTLS(t *testing.T) {
	alias := strings.Repeat("a", 64)
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/opaque-media/"+alias || r.URL.RawQuery != "" || r.Header.Get("X-Media-Capability") != "private-owner-bearer" || r.Header.Get("Range") != "bytes=1-3" || r.Header.Get("Origin") != "" {
			t.Error("opaque owner request was not constrained")
		}
		w.Header().Set("Content-Range", "bytes 1-3/6")
		w.Header().Set("Content-Length", "3")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "bcd")
	}))
	transport := testTransport(t, server, roots)
	response, err := transport.MediaOpaqueRelayRead(context.Background(), "https://node.test", alias, "private-owner-bearer", "GET", "bytes=1-3", 6)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil || string(content) != "bcd" || response.ContentRange != "bytes 1-3/6" {
		t.Fatal("opaque range framing", err)
	}
	if _, err := testTransport(t, server, x509.NewCertPool()).MediaOpaqueRelayRead(context.Background(), "https://node.test", alias, "private-owner-bearer", "GET", "bytes=1-3", 6); err == nil || strings.Contains(err.Error(), "private-owner-bearer") {
		t.Fatal("untrusted TLS accepted or bearer leaked", err)
	}
}

func TestFollowerRelaySingleRangeParsing(t *testing.T) {
	for _, tc := range []struct {
		raw        string
		start, end int64
		valid      bool
	}{
		{"bytes=1-3", 1, 3, true}, {"bytes=4-", 4, 5, true}, {"bytes=-2", 4, 5, true}, {"bytes=-100", 0, 5, true}, {"bytes=4-100", 4, 5, true},
		{"bytes=6-", 0, 0, false}, {"bytes=4-3", 0, 0, false}, {"bytes=-0", 0, 0, false}, {"bytes=0-1,3-4", 0, 0, false}, {"bytes=+1-3", 0, 0, false}, {"bytes=999999999999999999999-", 0, 0, false},
	} {
		start, end, err := followerRelayRange(tc.raw, 6)
		if (err == nil) != tc.valid || tc.valid && (start != tc.start || end != tc.end) {
			t.Fatal(tc, start, end, err)
		}
	}
}
