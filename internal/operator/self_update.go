package operator

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

//go:embed foc_installer.yaml
var focInstaller []byte

type EnvironmentRunner interface {
	RunEnv(context.Context, map[string]string, string, ...string) ([]byte, error)
}
type OperatorImages interface {
	ProveOperator(context.Context, string, string) (release.ImageProof, error)
}
type OperatorUpdate struct {
	Revision        string `json:"operator_revision"`
	Image           string `json:"operator_image"`
	Deployment      string `json:"registered_deployment"`
	BusinessChanged bool   `json:"business_changed"`
}

// SelfUpdate uses the bounded Compose installer, never a host service or build.
func (d *Deployment) SelfUpdate(ctx context.Context, target, arch string, evidence Evidence, images OperatorImages) (result OperatorUpdate, operationErr error) {
	if !release.ValidSHA(target) {
		return result, errors.New("self-update requires one explicit published main revision")
	}
	done, err := d.AcquireOperation()
	if err != nil {
		return result, err
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	if err := d.localUpgradeEngine(ctx, arch); err != nil {
		return result, err
	}
	proof, err := evidence.Artifact(ctx, target)
	if err != nil {
		return result, fmt.Errorf("operator self-update release_verification failed: %w", release.SafeVerificationFailure(err))
	}
	if proof["publishable"] != true || proof["sha"] != target || !release.ValidSHA(fmtString(proof["ci_sha"])) {
		return result, errors.New("operator target lacks reviewed main and exact-source CI proof")
	}
	image, err := images.ProveOperator(ctx, target, arch)
	repository, _ := release.ImageRepository("web")
	if err != nil {
		for _, category := range []error{release.ErrImagePermission, release.ErrImageNetwork, release.ErrImageIntegrity, release.ErrImagePlatform, release.ErrImageUnavailable} {
			if errors.Is(err, category) {
				return result, fmt.Errorf("operator self-update image_verification failed: %w", category)
			}
		}
		return result, errors.New("operator self-update image_verification unavailable")
	}
	if image.Revision != target || image.Platform != "linux/"+arch || !strings.HasPrefix(image.Image, repository+"@sha256:") {
		return result, release.ErrImageIntegrity
	}
	runner, ok := d.Runner.(EnvironmentRunner)
	if !ok {
		return result, errors.New("scoped Compose installer environment unavailable")
	}
	// Separate registry/download failures from host installation. Compose must
	// consume only the already-verified, already-pulled immutable image.
	if _, err = d.Runner.Run(ctx, "docker", "pull", image.Image); err != nil {
		return result, fmt.Errorf("operator self-update image_pull failed; business deployment unchanged: %w", safeDockerFailure(err))
	}
	temp, err := os.MkdirTemp("", "foc-installer-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(temp)
	path := filepath.Join(temp, "compose.foc.yaml")
	if err = os.WriteFile(path, focInstaller, 0600); err != nil {
		return result, err
	}
	_, err = runner.RunEnv(ctx, map[string]string{"FOC_OPERATOR_IMAGE": image.Image, "FOC_OPERATOR_REVISION": target, "FOC_DEPLOYMENT_DIRECTORY": d.Directory, "FOC_OPERATOR_PULL_POLICY": "never"}, "docker", "compose", "-f", path, "run", "--rm", "--no-deps", "-T", "--interactive=false", "install")
	if err != nil {
		return result, fmt.Errorf("operator self-update compose_install failed; business deployment unchanged: %w", safeDockerFailure(err))
	}
	return OperatorUpdate{Revision: target, Image: image.Image, Deployment: d.Directory, BusinessChanged: false}, nil
}
