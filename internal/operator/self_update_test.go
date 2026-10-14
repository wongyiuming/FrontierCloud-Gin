package operator

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type installerRunner struct {
	*upgradeRunner
	environment  map[string]string
	installCalls int
}
type operatorImages struct{ *fakeImages }

func (i operatorImages) ProveOperator(ctx context.Context, target, arch string) (release.ImageProof, error) {
	return i.Prove(ctx, target, "web", arch)
}

func (r *installerRunner) RunEnv(_ context.Context, env map[string]string, name string, args ...string) ([]byte, error) {
	r.environment = env
	r.installCalls++
	if name != "docker" || len(args) != 7 || args[0] != "compose" || args[3] != "run" || args[4] != "--rm" || args[5] != "--no-deps" || args[6] != "install" {
		panic("unexpected installer command")
	}
	contents, err := os.ReadFile(args[2])
	if err != nil || string(contents) != string(focInstaller) {
		panic("installer template mismatch")
	}
	return []byte("installed"), nil
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
