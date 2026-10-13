package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

func TestDockerCommandFailureHelper(t *testing.T) {
	if detail := os.Getenv("FC_TEST_DOCKER_FAILURE"); detail != "" {
		fmt.Fprintln(os.Stderr, detail+" https://fixture.invalid/?token=must-not-escape")
		fmt.Fprintln(os.Stdout, "must-not-escape")
		os.Exit(19)
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
		{"unrecognized fixture failure", operator.ErrDockerCommand},
	} {
		t.Run(test.diagnostic, func(t *testing.T) {
			t.Setenv("FC_TEST_DOCKER_FAILURE", test.diagnostic)
			output, err := (dockerRunner{t.TempDir()}).Run(context.Background(), program, "-test.run=^TestDockerCommandFailureHelper$")
			if !errors.Is(err, test.want) || output != nil || strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("unsafe or unclassified Docker failure", err)
			}
		})
	}
}
