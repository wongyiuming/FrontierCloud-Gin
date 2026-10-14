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
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	"strconv"
)

// ImageProof binds manifest, config and runtime bytes before Docker pulls them.
type ImageProof struct {
	Image        string `json:"image"`
	Revision     string `json:"revision"`
	ConfigDigest string `json:"config_digest"`
	Platform     string `json:"platform"`
	Generation   int    `json:"schema_generation"`
}

var (
	ErrImagePermission = errors.New("public image access denied; check package visibility")
	ErrImageNetwork    = errors.New("public registry network request failed; retry connectivity")
	ErrImageIntegrity  = errors.New("image digest or provenance mismatch; do not deploy")
	ErrImagePlatform   = errors.New("published image does not support the requested architecture")
)

func (r *RegistryClient) imageRead(ctx context.Context, prefix, suffix string, token *string) ([]byte, http.Header, error) {
	path := prefix + suffix
	body, headers, code, err := r.get(ctx, path, *token)
	if err != nil {
		return nil, nil, ErrImageNetwork
	}
	if code == 401 && *token == "" {
		query := url.Values{"service": {"ghcr.io"}, "scope": {"repository:" + strings.TrimPrefix(prefix, "/v2/") + ":pull"}}
		raw, _, status, e := r.get(ctx, "/token?"+query.Encode(), "")
		var value struct {
			Token string `json:"token"`
		}
		if e != nil {
			return nil, nil, ErrImageNetwork
		}
		if status != 200 || json.Unmarshal(raw, &value) != nil || len(value.Token) < 1 || len(value.Token) > 8192 || strings.ContainsAny(value.Token, "\r\n") {
			return nil, nil, ErrImagePermission
		}
		*token = value.Token
		body, headers, code, err = r.get(ctx, path, *token)
		if err != nil {
			return nil, nil, ErrImageNetwork
		}
	}
	if code == 307 && strings.HasPrefix(suffix, "/blobs/sha256:") {
		// GHCR config redirects use one fixed public artifact host. Never forward
		// the registry token or follow a second redirect; callers hash the bytes.
		u, e := url.Parse(headers.Get("Location"))
		if e != nil || u.Scheme != "https" || u.Hostname() != "pkg-containers.githubusercontent.com" || u.Port() != "" && u.Port() != "443" || u.User != nil || u.Fragment != "" {
			return nil, nil, ErrImageIntegrity
		}
		req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if e != nil {
			return nil, nil, ErrImageIntegrity
		}
		res, e := r.Client.Do(req)
		if e != nil {
			return nil, nil, ErrImageNetwork
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, nil, ErrImagePermission
		}
		body, e = io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
		if e != nil || len(body) > 4<<20 {
			return nil, nil, ErrImageIntegrity
		}
		return body, res.Header, nil
	}
	if code == 401 || code == 403 {
		return nil, nil, ErrImagePermission
	}
	if code == 404 {
		var value struct {
			Errors []struct {
				Code string `json:"code"`
			} `json:"errors"`
		}
		_, e := protocol.ParseStrictJSON(body, 4<<20)
		if e == nil && json.Unmarshal(body, &value) == nil && len(value.Errors) == 1 && value.Errors[0].Code == "MANIFEST_UNKNOWN" && strings.HasPrefix(suffix, "/manifests/") {
			return nil, nil, ErrImageUnavailable
		}
		return nil, nil, ErrImageIntegrity
	}
	if code != 200 {
		return nil, nil, ErrImageNetwork
	}
	return body, headers, nil
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Prove accepts latest only for discovery. Its returned revision is then used
// for every component of an installation; no independent moving aliases.
func (r *RegistryClient) Prove(ctx context.Context, target, component, architecture string) (ImageProof, error) {
	return r.prove(ctx, target, component, architecture, false)
}

// ProveOperator permits a newer tool generation without permitting the old
// operator to apply that generation's database upgrade. No moving alias is used.
func (r *RegistryClient) ProveOperator(ctx context.Context, target, architecture string) (ImageProof, error) {
	if !ValidSHA(target) {
		return ImageProof{}, ErrImageIntegrity
	}
	return r.prove(ctx, target, "web", architecture, true)
}

func (r *RegistryClient) prove(ctx context.Context, target, component, architecture string, operatorOnly bool) (ImageProof, error) {
	var proof ImageProof
	repository, err := ImageRepository(component)
	if err != nil || target != "latest" && !ValidSHA(target) || architecture != "amd64" && architecture != "arm64" || r == nil || r.Client == nil {
		return proof, ErrImageIntegrity
	}
	prefix := "/v2/" + strings.TrimPrefix(repository, "ghcr.io/")
	token := ""
	type descriptor struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Platform  struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	}
	type manifest struct {
		Version   int          `json:"schemaVersion"`
		Kind      string       `json:"mediaType"`
		Manifests []descriptor `json:"manifests"`
		Config    descriptor   `json:"config"`
	}
	read := func(ref string) (manifest, string, error) {
		var value manifest
		raw, headers, e := r.imageRead(ctx, prefix, "/manifests/"+ref, &token)
		if e != nil {
			return value, "", e
		}
		digest := digestBytes(raw)
		if headers.Get("Docker-Content-Digest") != digest || strings.HasPrefix(ref, "sha256:") && ref != digest {
			return value, "", ErrImageIntegrity
		}
		if _, e = protocol.ParseStrictJSON(raw, 4<<20); e != nil {
			return value, "", ErrImageIntegrity
		}
		if json.Unmarshal(raw, &value) != nil || value.Version != 2 {
			return value, "", ErrImageIntegrity
		}
		return value, digest, nil
	}
	m, digest, err := read(target)
	if err != nil {
		return proof, err
	}
	if m.Kind == "application/vnd.oci.image.index.v1+json" || m.Kind == "application/vnd.docker.distribution.manifest.list.v2+json" {
		selected := ""
		for _, entry := range m.Manifests {
			if entry.Platform.OS == "linux" && entry.Platform.Architecture == architecture {
				if selected != "" || !imageDigest.MatchString(entry.Digest) {
					return proof, ErrImageIntegrity
				}
				selected = entry.Digest
			}
		}
		if selected == "" {
			return proof, ErrImagePlatform
		}
		m, digest, err = read(selected)
		if err != nil {
			return proof, err
		}
	}
	if m.Kind != "application/vnd.oci.image.manifest.v1+json" && m.Kind != "application/vnd.docker.distribution.manifest.v2+json" || !imageDigest.MatchString(m.Config.Digest) || m.Config.Size < 1 || m.Config.Size > 4<<20 || m.Config.MediaType != "application/vnd.oci.image.config.v1+json" && m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return proof, ErrImageIntegrity
	}
	raw, _, err := r.imageRead(ctx, prefix, "/blobs/"+m.Config.Digest, &token)
	if err != nil {
		return proof, err
	}
	if int64(len(raw)) != m.Config.Size || digestBytes(raw) != m.Config.Digest {
		return proof, ErrImageIntegrity
	}
	if _, err = protocol.ParseStrictJSON(raw, 4<<20); err != nil {
		return proof, ErrImageIntegrity
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return proof, ErrImageIntegrity
	}
	labels := config.Config.Labels
	revision := labels["frontiercloud.revision"]
	generation, generationErr := strconv.Atoi(labels["frontiercloud.schema-generation"])
	if config.OS != "linux" || config.Architecture != architecture {
		return proof, ErrImagePlatform
	}
	if generationErr != nil || generation < migrations.Generation || generation > 1<<31-1 || labels["frontiercloud.schema-generation"] != strconv.Itoa(generation) || !operatorOnly && generation != migrations.Generation || !ValidSHA(revision) || target != "latest" && revision != target || labels["org.opencontainers.image.revision"] != revision || labels["org.opencontainers.image.source"] != ImageSource || labels["frontiercloud.component"] != component || labels["frontiercloud.runtime"] != "go" || labels["frontiercloud.automatic-tls"] != "1" || component != "nginx" && labels["frontiercloud.release-manifest-version"] != "1" {
		return proof, ErrImageIntegrity
	}
	return ImageProof{repository + "@" + digest, revision, m.Config.Digest, "linux/" + architecture, generation}, nil
}
