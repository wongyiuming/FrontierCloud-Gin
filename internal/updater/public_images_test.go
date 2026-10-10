package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

type publicImageTransport func(*http.Request) (*http.Response, error)

func (f publicImageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCanonicalReleasePrefersPublicImageAndNeverBuildsOnPullOrProofFailure(t *testing.T) {
	for _, scenario := range []string{"success", "registry-forbidden", "pull-error", "bad-label", "wrong-platform", "previous-schema", "missing-release-proof", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			source, _, target := gitFixture(t)
			if _, err := source.git(context.Background(), time.Second, "remote", "set-url", "origin", release.ImageSource+".git"); err != nil {
				t.Fatal(err)
			}
			pulled, tagged, built := false, false, false
			image := Image{ID: "sha256:" + strings.Repeat("b", 64), Architecture: runtime.GOARCH, OS: "linux"}
			image.Config.Labels = map[string]string{
				"frontiercloud.revision": target, "frontiercloud.component": "web", "frontiercloud.runtime": "go",
				"frontiercloud.schema-generation": "3", "frontiercloud.release-manifest-version": "1",
				"org.opencontainers.image.source": release.ImageSource, "org.opencontainers.image.revision": target,
			}
			if scenario == "bad-label" {
				image.Config.Labels["org.opencontainers.image.source"] = "https://attacker.test"
			}
			if scenario == "wrong-platform" {
				image.Architecture = "unknown"
			}
			if scenario == "previous-schema" {
				image.Config.Labels["frontiercloud.schema-generation"] = "2"
			}
			if scenario == "missing-release-proof" {
				delete(image.Config.Labels, "frontiercloud.release-manifest-version")
			}
			e := engineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/images/create"):
					pulled = true
					if !strings.HasPrefix(r.URL.Query().Get("fromImage"), "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:") {
						t.Error("unpinned image pull")
					}
					if scenario == "pull-error" {
						io.WriteString(w, "{\"error\":\"unauthorized fixture\"}\n")
					} else {
						io.WriteString(w, "{\"status\":\"Downloaded\"}\n")
					}
				case strings.HasSuffix(r.URL.Path, "/tag"):
					tagged = true
					w.WriteHeader(201)
				case strings.HasSuffix(r.URL.Path, "/build"):
					built = true
					io.Copy(io.Discard, r.Body)
					io.WriteString(w, "{\"error\":\"fixture stops after verified fallback\"}\n")
				case strings.HasSuffix(r.URL.Path, "/json"):
					if !tagged && strings.Contains(r.URL.Path, "frontiercloud-web:") {
						w.WriteHeader(404)
						return
					}
					json.NewEncoder(w).Encode(image)
				default:
					t.Error("unexpected Docker operation", r.URL.Path)
					w.WriteHeader(500)
				}
			})
			e.Project = "public-image-test"
			e.Registry = release.NewRegistryClient()
			e.Registry.Client.Transport = publicImageTransport(func(r *http.Request) (*http.Response, error) {
				status, body := 200, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
				if scenario == "registry-forbidden" {
					status, body = 403, `{}`
				}
				if scenario == "missing" {
					status, body = 404, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`
				}
				sum := sha256.Sum256([]byte(body))
				return &http.Response{StatusCode: status, Header: http.Header{"Docker-Content-Digest": {"sha256:" + hex.EncodeToString(sum[:])}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			ref, err := e.Build(context.Background(), source, target, "web", "Dockerfile.gin")
			if (err == nil) != (scenario == "success") || built != (scenario == "missing") {
				t.Fatal("unsafe artifact/fallback decision", ref, err, pulled, tagged, built)
			}
			if scenario == "success" && (!pulled || !tagged || ref != releaseImageTag(e.Project, target, "web")) {
				t.Fatal("public image not installed", ref)
			}
			if scenario != "success" && tagged {
				t.Fatal("unproven image tagged")
			}
		})
	}
}

func TestValidatedPublicCacheIsReusableButWrongPlatformIsNot(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid-cache", true: "wrong-platform"}[wrong], func(t *testing.T) {
			source, _, target := gitFixture(t)
			if _, err := source.git(context.Background(), time.Second, "remote", "set-url", "origin", release.ImageSource); err != nil {
				t.Fatal(err)
			}
			image := Image{ID: "sha256:" + strings.Repeat("b", 64), OS: "linux", Architecture: runtime.GOARCH}
			image.Config.Labels = map[string]string{"frontiercloud.revision": target, "frontiercloud.component": "updater", "frontiercloud.runtime": "go", "frontiercloud.schema-generation": "3", "frontiercloud.release-manifest-version": "1", "org.opencontainers.image.source": release.ImageSource, "org.opencontainers.image.revision": target}
			if wrong {
				image.OS = "windows"
			}
			e := engineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/json") {
					t.Fatal("cached artifact caused mutation", r.URL.Path)
				}
				json.NewEncoder(w).Encode(image)
			})
			e.Project = "public-cache-test"
			e.Registry = release.NewRegistryClient()
			e.Registry.Client.Transport = publicImageTransport(func(r *http.Request) (*http.Response, error) {
				t.Fatal("validated cache contacted registry")
				return nil, nil
			})
			ref, err := e.Build(context.Background(), source, target, "updater", "updater/Dockerfile.gin")
			if (err != nil) != wrong || (!wrong && ref != releaseImageTag(e.Project, target, "updater")) {
				t.Fatal(ref, err)
			}
		})
	}
}

func TestPublicCleanupOnlyRemovesOwnedProjectAliasNotSharedDigest(t *testing.T) {
	const project = "public-cleanup-test"
	stale := strings.Repeat("3", 40)
	own := releaseImageTag(project, stale, "web")
	foreign := releaseImageTag("other-project", stale, "web")
	legacy := "frontiercloud-web:" + stale
	global := "ghcr.io/wongyiuming/frontiercloud-gin-web:" + stale
	removed := []string{}
	e := engineFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.52/images/json" {
			json.NewEncoder(w).Encode([]Image{{RepoTags: []string{own, foreign, legacy, global, releaseImageTag(project, testCurrent, "web")}}})
			return
		}
		ref := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1.52/images/"), "/json")
		if r.Method == "DELETE" {
			if ref != own || r.URL.Query().Get("force") != "false" || r.URL.Query().Get("noprune") != "true" {
				t.Fatal("public cleanup crossed tag ownership", ref)
			}
			removed = append(removed, ref)
			w.WriteHeader(204)
			return
		}
		image := Image{ID: "sha256:" + strings.Repeat("b", 64)}
		image.Config.Labels = map[string]string{"frontiercloud.revision": stale, "frontiercloud.component": "web", "frontiercloud.runtime": "go", "frontiercloud.schema-generation": "3", "org.opencontainers.image.source": release.ImageSource, "org.opencontainers.image.revision": stale}
		json.NewEncoder(w).Encode(image)
	})
	e.Project = project
	if err := e.Cleanup(context.Background(), testCurrent, testTarget); err != nil || len(removed) != 1 || removed[0] != own {
		t.Fatal(err, removed)
	}
}
