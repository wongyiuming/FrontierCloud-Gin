package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

// Read-only public discovery, development-host only. This is not publication
// evidence for the unmerged candidate and never starts a business operation.
func TestAutomaticReleaseDiscoveryLive(t *testing.T) {
	if os.Getenv("FC_FOC_RELEASE_NETWORK_TEST") != "1" {
		t.Skip("explicit development network acceptance only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	v, err := hostReleaseVerifier()
	if err != nil {
		t.Fatal(err)
	}
	images := release.NewRegistryClient()
	defer images.Close()
	var diagnostic bytes.Buffer
	target, err := selectUpgradeRelease(ctx, "", "bb1b1430b4a7066b9c706e53757331e78cb5595d", "amd64", v, images, &diagnostic)
	if err != nil || !release.ValidSHA(target) {
		t.Fatal(err, diagnostic.String())
	}
	t.Log(diagnostic.String())
}
