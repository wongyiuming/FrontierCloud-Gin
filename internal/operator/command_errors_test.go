package operator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failedPullRunner struct {
	*fakeRunner
	err error
}

func (r failedPullRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "pull" {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		return nil, r.err
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestInstallPreservesPullFailureCategoryAndDropsRawDetail(t *testing.T) {
	for _, category := range []error{ErrDockerPermission, ErrDockerImageMissing, ErrDockerPlatform, ErrDockerIntegrity, ErrDockerNetwork, ErrDockerCommand} {
		t.Run(category.Error(), func(t *testing.T) {
			d, runner := fixture(t)
			d.Runner = failedPullRunner{runner, fmt.Errorf("fixture credential must-not-escape: %w", category)}
			_, err := d.Install(context.Background(), "", "amd64", fakeEvidence{true}, &fakeImages{})
			if !errors.Is(err, category) || strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("installation lost its safe pull failure category", err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, " up ") || strings.Contains(call, " build ") {
					t.Fatal("failed pull initialized or built services", call)
				}
			}
			for _, name := range []string{ReceiptFile, ImagesFile, "data"} {
				if _, err := os.Lstat(filepath.Join(d.Directory, name)); !os.IsNotExist(err) {
					t.Fatal("failed pull created deployment state", name, err)
				}
			}
		})
	}
}
