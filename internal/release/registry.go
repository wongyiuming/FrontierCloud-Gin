package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const ImageSource = "https://github.com/wongyiuming/FrontierCloud-Gin"
const registryRoot = "https://ghcr.io"

var ErrImageUnavailable = errors.New("exact public image or platform is unavailable")
var imageDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Registry/namespace is fixed. No endpoint or deployment credential is accepted.
type RegistryClient struct{ Client *http.Client }

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{Client: &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone(), Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("registry redirects forbidden") },
	}}
}

func (r *RegistryClient) Close() {
	if r != nil && r.Client != nil {
		r.Client.CloseIdleConnections()
	}
}

func ImageRepository(component string) (string, error) {
	if component != "web" && component != "updater" && component != "nginx" {
		return "", errors.New("invalid native image component")
	}
	return "ghcr.io/wongyiuming/frontiercloud-gin-" + component, nil
}

func (r *RegistryClient) get(ctx context.Context, path, token string) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", registryRoot+path, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := r.Client.Do(req)
	if err != nil {
		return nil, nil, 0, errors.New("public registry request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return nil, nil, 0, errors.New("invalid public registry response")
	}
	return body, response.Header, response.StatusCode, nil
}

func (r *RegistryClient) Resolve(ctx context.Context, target, component string) (string, error) {
	repository, err := ImageRepository(component)
	if err != nil || !ValidSHA(target) || r == nil || r.Client == nil {
		return "", errors.New("invalid native image request")
	}
	name := strings.TrimPrefix(repository, "ghcr.io/")
	path := "/v2/" + name + "/manifests/" + target
	body, headers, status, err := r.get(ctx, path, "")
	if err != nil {
		return "", err
	}
	if status == http.StatusUnauthorized {
		// Never follow a challenge's arbitrary realm. Construct public read scope.
		query := url.Values{"service": {"ghcr.io"}, "scope": {"repository:" + name + ":pull"}}
		raw, _, code, err := r.get(ctx, "/token?"+query.Encode(), "")
		var token struct {
			Value string `json:"token"`
		}
		if err != nil || code != 200 || json.Unmarshal(raw, &token) != nil || len(token.Value) < 1 || len(token.Value) > 8192 || strings.ContainsAny(token.Value, "\r\n") {
			return "", errors.New("public registry anonymous access rejected")
		}
		body, headers, status, err = r.get(ctx, path, token.Value)
		if err != nil {
			return "", err
		}
	}
	if status == http.StatusNotFound {
		var missing struct {
			Errors []struct {
				Code string `json:"code"`
			} `json:"errors"`
		}
		_, strictErr := protocol.ParseStrictJSON(body, 4<<20)
		if strictErr == nil && json.Unmarshal(body, &missing) == nil && len(missing.Errors) == 1 {
			for _, failure := range missing.Errors {
				if failure.Code == "MANIFEST_UNKNOWN" {
					return "", ErrImageUnavailable
				}
			}
		}
		return "", errors.New("unconfirmed public registry absence")
	}
	if status != 200 {
		return "", errors.New("public registry access failed")
	}
	digest := headers.Get("Docker-Content-Digest")
	checksum := sha256.Sum256(body)
	if !imageDigest.MatchString(digest) || digest != "sha256:"+hex.EncodeToString(checksum[:]) {
		return "", errors.New("public image manifest digest mismatch")
	}
	if _, err := protocol.ParseStrictJSON(body, 4<<20); err != nil {
		return "", errors.New("invalid public image manifest")
	}
	var manifest struct {
		Schema    int    `json:"schemaVersion"`
		Kind      string `json:"mediaType"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Kind     string `json:"mediaType"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if json.Unmarshal(body, &manifest) != nil || manifest.Schema != 2 {
		return "", errors.New("invalid public image manifest schema")
	}
	switch manifest.Kind {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		selected := ""
		for _, descriptor := range manifest.Manifests {
			if descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != runtime.GOARCH {
				continue
			}
			if !imageDigest.MatchString(descriptor.Digest) || (descriptor.Kind != "application/vnd.oci.image.manifest.v1+json" && descriptor.Kind != "application/vnd.docker.distribution.manifest.v2+json") || selected != "" {
				return "", errors.New("ambiguous or invalid public image platform")
			}
			selected = descriptor.Digest
		}
		if selected == "" {
			return "", ErrImageUnavailable
		}
		digest = selected
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return "", errors.New("unsupported public image manifest")
	}
	return repository + "@" + digest, nil
}
