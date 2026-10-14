package release

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func imageProofFixture(t *testing.T, mutate func(map[string]any)) (*RegistryClient, string, string) {
	t.Helper()
	revision := strings.Repeat("a", 40)
	configuration := map[string]any{"os": "linux", "architecture": "amd64", "config": map[string]any{"Labels": map[string]string{
		"frontiercloud.revision": revision, "frontiercloud.runtime": "go", "frontiercloud.component": "web", "frontiercloud.schema-generation": strconv.Itoa(migrations.Generation), "frontiercloud.release-manifest-version": "1", "frontiercloud.automatic-tls": "1", "org.opencontainers.image.source": ImageSource, "org.opencontainers.image.revision": revision,
	}}}
	if mutate != nil {
		mutate(configuration)
	}
	raw, _ := json.Marshal(configuration)
	configDigest := digestBytes(raw)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(raw)}})
	registry := NewRegistryClient()
	registry.Client.Transport = registryTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "ghcr.io" || req.URL.Scheme != "https" {
			t.Fatal("untrusted request", req.URL.Host)
		}
		if strings.Contains(req.URL.Path, "/blobs/") {
			return registryReply(200, string(raw), false), nil
		}
		return registryReply(200, string(manifest), false), nil
	})
	return registry, revision, digestBytes(manifest)
}

func TestImageProofBindsConfigProvenanceAndImmutableRuntime(t *testing.T) {
	r, revision, digest := imageProofFixture(t, nil)
	for _, target := range []string{"latest", revision} {
		p, e := r.Prove(context.Background(), target, "web", "amd64")
		if e != nil || p.Revision != revision || p.Image != "ghcr.io/wongyiuming/frontiercloud-gin-web@"+digest || p.Generation != migrations.Generation {
			t.Fatal(p, e)
		}
	}
	_, e := r.Prove(context.Background(), strings.Repeat("b", 40), "web", "amd64")
	if !errors.Is(e, ErrImageIntegrity) {
		t.Fatal("different source accepted", e)
	}
}

func TestOperatorRefreshAllowsNewGenerationWithoutWeakeningBusinessProof(t *testing.T) {
	for _, value := range []string{strconv.Itoa(migrations.Generation + 1), strconv.Itoa(migrations.Generation - 1), "0", "-1", "08", "invalid"} {
		r, revision, _ := imageProofFixture(t, func(c map[string]any) {
			c["config"].(map[string]any)["Labels"].(map[string]string)["frontiercloud.schema-generation"] = value
		})
		p, e := r.ProveOperator(context.Background(), revision, "amd64")
		if value == strconv.Itoa(migrations.Generation+1) {
			if e != nil || p.Generation != migrations.Generation+1 {
				t.Fatal(p, e)
			}
		} else if !errors.Is(e, ErrImageIntegrity) {
			t.Fatal(value, e)
		}
		if _, e = r.Prove(context.Background(), revision, "web", "amd64"); !errors.Is(e, ErrImageIntegrity) {
			t.Fatal("old business operator accepted foreign generation", e)
		}
		if _, e = r.ProveOperator(context.Background(), "latest", "amd64"); !errors.Is(e, ErrImageIntegrity) {
			t.Fatal("moving operator alias accepted", e)
		}
	}
}
func TestImageProofRejectsBadLabelsAndPlatform(t *testing.T) {
	for _, key := range []string{"frontiercloud.component", "frontiercloud.runtime", "frontiercloud.schema-generation", "frontiercloud.automatic-tls", "org.opencontainers.image.source", "org.opencontainers.image.revision", "frontiercloud.release-manifest-version"} {
		t.Run(key, func(t *testing.T) {
			r, revision, _ := imageProofFixture(t, func(c map[string]any) { c["config"].(map[string]any)["Labels"].(map[string]string)[key] = "invalid" })
			if _, e := r.Prove(context.Background(), revision, "web", "amd64"); !errors.Is(e, ErrImageIntegrity) {
				t.Fatal(e)
			}
		})
	}
	r, revision, _ := imageProofFixture(t, func(c map[string]any) { c["architecture"] = "arm64" })
	if _, e := r.Prove(context.Background(), revision, "web", "amd64"); !errors.Is(e, ErrImagePlatform) {
		t.Fatal(e)
	}
}
func TestImageProofClassifiesAbsencePermissionIntegrityAndNetwork(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   error
	}{{404, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, ErrImageUnavailable}, {404, `{"errors":[{"code":"NAME_UNKNOWN"}]}`, ErrImageIntegrity}, {403, `{}`, ErrImagePermission}, {503, `{}`, ErrImageNetwork}, {200, `{"schemaVersion":2,"schemaVersion":2}`, ErrImageIntegrity}} {
		r := NewRegistryClient()
		r.Client.Transport = registryTransport(func(*http.Request) (*http.Response, error) { return registryReply(test.status, test.body, false), nil })
		if _, e := r.Prove(context.Background(), strings.Repeat("a", 40), "web", "amd64"); !errors.Is(e, test.want) {
			t.Fatal(test.status, e)
		}
	}
}
func TestImageProofHashChecksActualConfigBytes(t *testing.T) {
	r, revision, _ := imageProofFixture(t, nil)
	transport := r.Client.Transport
	r.Client.Transport = registryTransport(func(req *http.Request) (*http.Response, error) {
		res, e := transport.RoundTrip(req)
		if strings.Contains(req.URL.Path, "/blobs/") {
			return registryReply(200, `{}`, false), nil
		}
		return res, e
	})
	if _, e := r.Prove(context.Background(), revision, "web", "amd64"); !errors.Is(e, ErrImageIntegrity) {
		t.Fatal(e)
	}
}
