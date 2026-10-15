package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

func TestDockerCommandFailureHelper(t *testing.T) {
	if os.Getenv("FC_TEST_DOCKER_DELAY") == "1" {
		time.Sleep(time.Second)
	}
	if detail := os.Getenv("FC_TEST_DOCKER_FAILURE"); detail != "" {
		fmt.Fprintln(os.Stderr, detail+" https://fixture.invalid/?token=must-not-escape")
		fmt.Fprintln(os.Stdout, "must-not-escape")
		os.Exit(19)
	}
}

func TestDockerRunnerReportsCancellationAndDeadline(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FC_TEST_DOCKER_DELAY", "1")
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		want := operator.ErrDockerTimeout
		if !deadline {
			cancel()
			want = operator.ErrDockerCanceled
		}
		output, err := (dockerRunner{t.TempDir()}).Run(ctx, program, "-test.run=^TestDockerCommandFailureHelper$")
		cancel()
		if output != nil || !errors.Is(err, want) {
			t.Fatal("wrong cancellation category", deadline, err)
		}
	}
}

func TestDockerRunnerClassifiesFailuresWithoutCredentialOutput(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		diagnostic string
		want       error
	}{
		{"unauthorized: denied", operator.ErrDockerPermission},
		{"manifest unknown", operator.ErrDockerImageMissing},
		{"no matching manifest for linux/arm64", operator.ErrDockerPlatform},
		{"checksum mismatch", operator.ErrDockerIntegrity},
		{"TLS handshake timeout", operator.ErrDockerNetwork},
		{"rpc error: code = Canceled desc = context canceled", operator.ErrDockerCanceled},
		{"context deadline exceeded", operator.ErrDockerTimeout},
		{"failed to fetch digest: unexpected EOF", operator.ErrDockerNetwork},
		{"extracting snapshot\nfailed to fetch digest: unexpected EOF", operator.ErrDockerNetwork},
		{"snapshot does not exist", operator.ErrDockerStorage},
		{"no space left on device", operator.ErrDockerStorage},
		{"no space left on device\ncontext canceled", operator.ErrDockerStorage},
		{"unexpected EOF\ncontext canceled", operator.ErrDockerNetwork},
		{"Another host installation is active or interrupted", operator.ErrInstallerLock},
		{"Global foc command differs from managed identity", operator.ErrInstallerOwnership},
		{"unrecognized fixture failure", operator.ErrDockerCommand},
	} {
		t.Run(test.diagnostic, func(t *testing.T) {
			t.Setenv("FC_TEST_DOCKER_FAILURE", test.diagnostic)
			output, err := (dockerRunner{t.TempDir()}).Run(context.Background(), program, "-test.run=^TestDockerCommandFailureHelper$")
			if !errors.Is(err, test.want) || output != nil || strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("unsafe or unclassified Docker failure", err)
			}
			var failure *operator.CommandFailure
			if !errors.As(err, &failure) || failure.ExitCode != 19 {
				t.Fatal("missing process exit code", err)
			}
		})
	}
}
