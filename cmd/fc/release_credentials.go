package main

import (
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

func hostReleaseVerifier() (*release.Verifier, error) {
	return release.NewVerifier(release.DefaultPolicy(), os.Getenv("GITHUB_API_TOKEN"))
}
