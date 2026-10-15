package operator

import (
	"context"
	"errors"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type installerRunner struct {
	*upgradeRunner
	environment    map[string]string
	installCalls   int
	pullFailure    error
	installFailure error
}

func (r *installerRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "pull" && r.pullFailure != nil {
		return nil, r.pullFailure
	}
	return r.upgradeRunner.Run(ctx, name, args...)
}

type operatorImages struct{ *fakeImages }

type selfUpdateFailedEvidence struct{}

func (selfUpdateFailedEvidence) Artifact(context.Context, string) (map[string]any, error) {
	return nil, fmt.Errorf("private must-not-escape: %w", context.DeadlineExceeded)
}

func TestSelfUpdateVerificationFailureDoesNotBecomeIntegrityOrReviewRejection(t *testing.T) {
	d, _, base, _ := upgradeFixture(t)
	runner := &installerRunner{upgradeRunner: base}
	d.Runner = runner
	_, err := d.SelfUpdate(context.Background(), strings.Repeat("b", 40), "amd64", selfUpdateFailedEvidence{}, operatorImages{&fakeImages{}})
	if err == nil || !strings.Contains(err.Error(), "release_verification") || !strings.Contains(err.Error(), "deadline exceeded") || strings.Contains(err.Error(), "must-not-escape") || runner.installCalls != 0 {
		t.Fatal(err)
	}
}

func (i operatorImages) ProveOperator(ctx context.Context, target, arch string) (release.ImageProof, error) {
	return i.Prove(ctx, target, "web", arch)
}

func (r *installerRunner) RunEnv(_ context.Context, env map[string]string, name string, args ...string) ([]byte, error) {
	r.environment = env
	r.installCalls++
	if name != "docker" || len(args) != 9 || args[0] != "compose" || strings.Join(args[3:], " ") != "run --rm --no-deps -T --interactive=false install" || env["FOC_OPERATOR_PULL_POLICY"] != "never" {
		panic("unexpected installer command")
	}
	contents, err := os.ReadFile(args[2])
	if err != nil || string(contents) != string(focInstaller) {
		panic("installer template mismatch")
	}
	return []byte("secret=must-not-escape"), r.installFailure
}

func TestSelfUpdatePreservesSafeFailureAndPhaseWithoutBusinessMutation(t *testing.T) {
	for _, stage := range []string{"image_pull", "compose_install"} {
		for _, category := range []error{ErrDockerNetwork, ErrDockerStorage, ErrInstallerLock, ErrInstallerOwnership, ErrDockerCanceled, ErrDockerTimeout, ErrDockerOutputLimit, ErrDockerCommand} {
			d, _, base, _ := upgradeFixture(t)
			failure := fmt.Errorf("private diagnostic must-not-escape: %w", &CommandFailure{Category: category, ExitCode: 19})
			runner := &installerRunner{upgradeRunner: base}
			if stage == "image_pull" {
				runner.pullFailure = failure
			} else {
				runner.installFailure = failure
			}
			d.Runner = runner
			before, _ := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
			_, err := d.SelfUpdate(context.Background(), strings.Repeat("b", 40), "amd64", fakeEvidence{true}, operatorImages{&fakeImages{}})
			if !errors.Is(err, category) || !strings.Contains(err.Error(), stage) || !strings.Contains(err.Error(), "exit_code=19") || strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("self-update lost execution facts or leaked raw output", stage, err)
			}
			if stage == "image_pull" && runner.installCalls != 0 {
				t.Fatal("failed pull reached host installation")
			}
			after, _ := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
			if string(before) != string(after) {
				t.Fatal("self-update changed business receipt")
			}
			for _, call := range base.calls {
				if strings.Contains(call, " up ") || strings.Contains(call, " stop ") || strings.Contains(call, " build ") {
					t.Fatal("self-update mutated business", call)
				}
			}
		}
	}
}
func TestSelfUpdateRequiresReviewedPublicImageAndChangesNoBusinessState(t *testing.T) {
	for _, kind := range []string{"valid", "unreviewed", "image-error", "active"} {
		t.Run(kind, func(t *testing.T) {
			d, _, base, _ := upgradeFixture(t)
			runner := &installerRunner{upgradeRunner: base}
			d.Runner = runner
			target := strings.Repeat("b", 40)
			images := operatorImages{&fakeImages{}}
			if kind == "image-error" {
				images.failure = "web"
			}
			if kind == "active" {
				if err := os.Mkdir(filepath.Join(d.Directory, OperationLock), 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
			if err != nil {
				t.Fatal(err)
			}
			result, err := d.SelfUpdate(context.Background(), target, "amd64", fakeEvidence{kind != "unreviewed"}, images)
			if kind == "valid" {
				if err != nil || result.BusinessChanged || result.Revision != target || runner.installCalls != 1 || runner.environment["FOC_OPERATOR_REVISION"] != target || runner.environment["FOC_DEPLOYMENT_DIRECTORY"] != d.Directory {
					t.Fatal(result, err, runner.environment)
				}
			} else if err == nil || runner.installCalls != 0 {
				t.Fatal("invalid operator install attempted", kind, err)
			}
			after, e := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
			if e != nil || string(before) != string(after) {
				t.Fatal("business receipt changed", e)
			}
		})
	}
}
func TestEmbeddedFocInstallerMatchesCanonicalCompose(t *testing.T) {
	canonical, err := os.ReadFile(filepath.Join("..", "..", "compose.foc.yaml"))
	if err != nil || string(canonical) != string(focInstaller) {
		t.Fatal("operator installer drift", err)
	}
}
