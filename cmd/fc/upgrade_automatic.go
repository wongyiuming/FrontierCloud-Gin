package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

type automaticReleaseEvidence interface {
	Artifact(context.Context, string) (map[string]any, error)
	MainHead(context.Context) (string, error)
	Publication(context.Context, string) (release.PublicationState, error)
	Relation(context.Context, string, string) (string, error)
}
type automaticReleaseImages interface {
	DiscoverOperator(context.Context, string) (release.ImageProof, error)
	ProveUpgradeCandidate(context.Context, string, string, string) (release.ImageProof, error)
}

func selectUpgradeRelease(ctx context.Context, target, installed, arch string, evidence automaticReleaseEvidence, images automaticReleaseImages, diagnostic io.Writer) (string, error) {
	if target == "" {
		head, err := evidence.MainHead(ctx)
		if err != nil {
			return "", err
		}
		state, err := evidence.Publication(ctx, head)
		if err != nil {
			return "", err
		}
		if state.Stage == "published" {
			target = head
		} else {
			if _, err = fmt.Fprintln(diagnostic, state.Error()); err != nil {
				return "", err
			}
			alias, err := images.DiscoverOperator(ctx, arch)
			if err != nil {
				return "", fmt.Errorf("latest published release discovery failed: %w", err)
			}
			target = alias.Revision
		}
	}
	if !release.ValidSHA(target) {
		return "", release.ErrManifest
	}
	relation, err := evidence.Relation(ctx, installed, target)
	if err != nil {
		return "", err
	}
	if relation == "behind" {
		return "", errors.New("latest published release is older than this deployment; automatic downgrade refused")
	}
	proof, err := evidence.Artifact(ctx, target)
	if err != nil {
		return "", release.SafeVerificationFailure(err)
	}
	if proof["publishable"] != true || proof["sha"] != target || !release.ValidSHA(stringFact(proof["ci_sha"])) {
		return "", errors.New("release lacks matching merged source tree and successful exact-source CI")
	}
	state, err := evidence.Publication(ctx, target)
	if err != nil {
		return "", err
	}
	if state.Stage != "published" {
		return "", state
	}
	generation := 0
	for _, component := range []string{"web", "nginx"} {
		image, err := images.ProveUpgradeCandidate(ctx, target, component, arch)
		if err != nil {
			return "", fmt.Errorf("publication succeeded but exact %s image verification failed: %w", component, err)
		}
		if image.Revision != target || image.Platform != "linux/"+arch || image.Generation < 1 || generation != 0 && generation != image.Generation {
			return "", release.ErrImageIntegrity
		}
		generation = image.Generation
	}
	if _, err = fmt.Fprintf(diagnostic, "Selected published release: %s\n", target); err != nil {
		return "", err
	}
	return target, nil
}

func stringFact(value any) string { s, _ := value.(string); return s }

func refreshUpgradeOperator(ctx context.Context, current, target string, evidence automaticReleaseEvidence, refresh func() error, continuation func() int) (bool, int, error) {
	if current == target {
		return false, 0, nil
	}
	relation, err := evidence.Relation(ctx, current, target)
	if err != nil {
		return false, 2, err
	}
	if relation != "ahead" {
		return false, 0, nil
	}
	if err = refresh(); err != nil {
		return false, 2, err
	}
	return true, continuation(), nil
}

// Restart only the backend at the fixed path owned by the Compose installer.
// The pinned revision prevents rediscovery or an update loop in the child.
func continueWithUpdatedOperator(ctx context.Context, directory, target string, args []string, input io.Reader, out, diagnostic io.Writer, structured bool) int {
	return continueAtOperatorPath(ctx, "/usr/local/lib/frontiercloud/foc/fc", directory, target, args, input, out, diagnostic, structured)
}

func continueAtOperatorPath(ctx context.Context, path, directory, target string, args []string, input io.Reader, out, diagnostic io.Writer, structured bool) int {
	check := exec.CommandContext(ctx, path, "version")
	version, err := check.Output()
	if err != nil || strings.TrimSpace(string(version)) != target {
		fmt.Fprintln(diagnostic, "operator refresh did not install the selected version; business upgrade not started")
		return 2
	}
	childArgs := []string{"--directory", directory, "--revision", target}
	if structured {
		childArgs = append(childArgs, "--json")
	}
	childArgs = append(childArgs, args...)
	child := exec.CommandContext(ctx, path, childArgs...)
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
	child.WaitDelay = 5 * time.Second
	child.Stdin, child.Stdout, child.Stderr = input, out, diagnostic
	if err = child.Run(); err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			return failure.ExitCode()
		}
		fmt.Fprintln(diagnostic, "updated operator could not continue; business state and journal retained")
		return 2
	}
	return 0
}
