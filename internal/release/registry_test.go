package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

type registryTransport func(*http.Request) (*http.Response, error)

func (f registryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func registryReply(status int, body string, badDigest bool) *http.Response {
	hash := sha256.Sum256([]byte(body))
	digest := "sha256:" + hex.EncodeToString(hash[:])
	if badDigest {
		digest = "sha256:" + strings.Repeat("0", 64)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Docker-Content-Digest": {digest}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestPublicRegistryResolutionPinsDigestAndFailsClosed(t *testing.T) {
	valid := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","platform":{"os":"linux","architecture":"` + runtime.GOARCH + `"}}]}`
	for _, test := range []struct {
		name      string
		status    int
		body      string
		badDigest bool
		missing   bool
		success   bool
	}{
		{"valid", 200, valid, false, false, true},
		{"missing", 404, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false, true, false},
		{"generic-404", 404, `{"errors":[{"code":"NAME_UNKNOWN"}]}`, false, false, false},
		{"duplicate-404", 404, `{"errors":[],"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false, false, false},
		{"ambiguous-404", 404, `{"errors":[{"code":"MANIFEST_UNKNOWN"},{"code":"DENIED"}]}`, false, false, false},
		{"forbidden", 403, `{}`, false, false, false},
		{"server-error", 500, `{}`, false, false, false},
		{"digest", 200, valid, true, false, false},
		{"duplicates", 200, `{"schemaVersion":2,"schemaVersion":2}`, false, false, false},
		{"wrong-platform", 200, strings.ReplaceAll(valid, `"architecture":"`+runtime.GOARCH+`"`, `"architecture":"unknown"`), false, true, false},
		{"invalid-kind", 200, `{"schemaVersion":2,"mediaType":"evil"}`, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistryClient()
			registry.Client.Transport = registryTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.URL.Host != "ghcr.io" || r.URL.Path != "/v2/wongyiuming/frontiercloud-gin-web/manifests/"+strings.Repeat("a", 40) {
					t.Fatal("unexpected registry URL", r.URL)
				}
				return registryReply(test.status, test.body, test.badDigest), nil
			})
			ref, err := registry.Resolve(context.Background(), strings.Repeat("a", 40), "web")
			if (err == nil) != test.success || errors.Is(err, ErrImageUnavailable) != test.missing {
				t.Fatal(ref, err)
			}
			if test.success && ref != "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:"+strings.Repeat("b", 64) {
				t.Fatal("not pinned", ref)
			}
		})
	}
}

func TestPublicRegistryReadTokenNeverUsesArbitraryRealm(t *testing.T) {
	registry := NewRegistryClient()
	calls := 0
	registry.Client.Transport = registryTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "ghcr.io" || r.URL.Scheme != "https" {
			t.Fatal("untrusted realm", r.URL)
		}
		if r.URL.Path == "/token" {
			if r.URL.Query().Get("scope") != "repository:wongyiuming/frontiercloud-gin-updater:pull" {
				t.Fatal(r.URL)
			}
			return registryReply(200, `{"token":"public-read-only"}`, false), nil
		}
		if r.Header.Get("Authorization") == "" {
			return registryReply(401, `{}`, false), nil
		}
		if r.Header.Get("Authorization") != "Bearer public-read-only" {
			t.Fatal("wrong scope token")
		}
		return registryReply(200, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`, false), nil
	})
	if _, err := registry.Resolve(context.Background(), strings.Repeat("a", 40), "updater"); err != nil || calls != 3 {
		t.Fatal(err, calls)
	}
}
