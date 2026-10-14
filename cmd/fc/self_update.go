package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"io"
)

func selfUpdateCommand(ctx context.Context, directory, revision string, args []string, out, diagnostic io.Writer) int {
	if len(args) != 1 || !release.ValidSHA(revision) {
		fmt.Fprintln(diagnostic, "self-update requires --revision FULL_PUBLISHED_MAIN_SHA")
		return 2
	}
	d, _, err := operator.Open(directory)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	d.Runner = dockerRunner{d.Directory}
	raw, err := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	verifier, err := hostReleaseVerifier()
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	images := release.NewRegistryClient()
	defer images.Close()
	result, err := d.SelfUpdate(ctx, revision, operator.Architecture(string(raw)), verifier, images)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 2
	}
	if err = json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(diagnostic, "operator result output failed; check foc version")
		return 2
	}
	return 0
}
