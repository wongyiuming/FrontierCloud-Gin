package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

type autoEvidence struct {
	head, stage, relation string
	invalid               bool
	failure               error
}

func (e autoEvidence) MainHead(context.Context) (string, error) { return e.head, e.failure }
func (e autoEvidence) Publication(_ context.Context, target string) (release.PublicationState, error) {
	stage := "published"
	if target == e.head {
		stage = e.stage
	}
	return release.PublicationState{Revision: target, Stage: stage}, e.failure
}

func TestUpdatedOperatorContinuationPinsArgumentsAndPropagatesFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Linux development host")
	}
	target := strings.Repeat("a", 40)
	for _, kind := range []string{"success", "wrong-version", "child-fails"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fc")
			version := target
			if kind == "wrong-version" {
				version = strings.Repeat("b", 40)
			}
			script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo " + version + "; exit 0; fi\nprintf '%s\\n' \"$@\"\nread answer\nprintf 'answer=%s\\n' \"$answer\"\n"
			if kind == "child-fails" {
				script += "exit 2\n"
			}
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			var out, diagnostic bytes.Buffer
			code := continueAtOperatorPath(context.Background(), path, "/private/deployment", target, []string{"upgrade", "--yes"}, strings.NewReader("y\n"), &out, &diagnostic, true)
			if kind != "success" {
				if code != 2 {
					t.Fatal(code)
				}
				return
			}
			want := "--directory\n/private/deployment\n--revision\n" + target + "\n--json\nupgrade\n--yes\nanswer=y\n"
			if code != 0 || out.String() != want {
				t.Fatal(code, out.String(), diagnostic.String())
			}
		})
	}
}
func (e autoEvidence) Relation(context.Context, string, string) (string, error) {
	return e.relation, e.failure
}
func (e autoEvidence) Artifact(_ context.Context, target string) (map[string]any, error) {
	return map[string]any{"publishable": !e.invalid, "sha": target, "ci_sha": strings.Repeat("c", 40)}, e.failure
}

type autoImages struct {
	alias              string
	failure            error
	discovered, proved int
}

func (i *autoImages) DiscoverOperator(context.Context, string) (release.ImageProof, error) {
	i.discovered++
	return release.ImageProof{Revision: i.alias}, i.failure
}
func (i *autoImages) ProveUpgradeCandidate(_ context.Context, target, component, arch string) (release.ImageProof, error) {
	i.proved++
	return release.ImageProof{Revision: target, Platform: "linux/" + arch, Generation: 7}, i.failure
}

func TestAutomaticSelectionPinsLatestPublishedAndExplainsNewerBuild(t *testing.T) {
	for _, stage := range []string{"published", "main_ci_running", "image_publication_waiting", "image_build_or_publication_running", "image_publication_failed"} {
		t.Run(stage, func(t *testing.T) {
			head, older := strings.Repeat("a", 40), strings.Repeat("b", 40)
			e := autoEvidence{head: head, stage: stage, relation: "ahead"}
			i := &autoImages{alias: older}
			var out bytes.Buffer
			target, err := selectUpgradeRelease(context.Background(), "", strings.Repeat("d", 40), "amd64", e, i, &out)
			want := head
			if stage != "published" {
				want = older
				if !strings.Contains(out.String(), stage) {
					t.Fatal(out.String())
				}
			}
			if err != nil || target != want || i.proved != 2 || i.discovered != map[bool]int{true: 0, false: 1}[stage == "published"] {
				t.Fatal(target, err, i)
			}
		})
	}
}

func TestAutomaticSelectionNeverSubstitutesOrDeploysUnprovenTarget(t *testing.T) {
	for _, kind := range []string{"explicit-building", "invalid-proof", "downgrade", "registry-network", "API-failure"} {
		t.Run(kind, func(t *testing.T) {
			head := strings.Repeat("a", 40)
			e := autoEvidence{head: head, stage: "published", relation: "ahead"}
			i := &autoImages{alias: strings.Repeat("b", 40)}
			switch kind {
			case "explicit-building":
				e.stage = "image_build_or_publication_running"
			case "invalid-proof":
				e.invalid = true
			case "downgrade":
				e.relation = "behind"
			case "registry-network":
				i.failure = release.ErrImageNetwork
			case "API-failure":
				e.failure = errors.New("unavailable")
			}
			_, err := selectUpgradeRelease(context.Background(), head, strings.Repeat("d", 40), "amd64", e, i, &bytes.Buffer{})
			if err == nil || i.discovered != 0 {
				t.Fatal("explicit target substituted", err, i)
			}
			if kind == "explicit-building" && !strings.Contains(err.Error(), "image_build_or_publication_running") {
				t.Fatal(err)
			}
			if kind == "registry-network" && !errors.Is(err, release.ErrImageNetwork) {
				t.Fatal(err)
			}
		})
	}
}

func TestAutomaticFallbackNeverHidesRegistryFailure(t *testing.T) {
	for _, failure := range []error{release.ErrImageNetwork, release.ErrImagePermission, release.ErrImageIntegrity, release.ErrImagePlatform, release.ErrImageUnavailable} {
		e := autoEvidence{head: strings.Repeat("a", 40), stage: "image_build_or_publication_running", relation: "ahead"}
		i := &autoImages{alias: strings.Repeat("b", 40), failure: failure}
		_, err := selectUpgradeRelease(context.Background(), "", strings.Repeat("d", 40), "amd64", e, i, &bytes.Buffer{})
		if !errors.Is(err, failure) || i.discovered != 1 || i.proved != 0 {
			t.Fatal(err, i)
		}
	}
}

func TestAutomaticRefreshOnlyWhenNeededAndStopsOnInstallationFailure(t *testing.T) {
	target := strings.Repeat("a", 40)
	for _, kind := range []string{"same", "newer-tool", "refresh", "refresh-fails", "continuation-fails"} {
		t.Run(kind, func(t *testing.T) {
			current := strings.Repeat("b", 40)
			e := autoEvidence{relation: "ahead"}
			if kind == "same" {
				current = target
			}
			if kind == "newer-tool" {
				e.relation = "behind"
			}
			refreshes, continuations := 0, 0
			handled, code, err := refreshUpgradeOperator(context.Background(), current, target, e, func() error {
				refreshes++
				if kind == "refresh-fails" {
					return errors.New("installer lock")
				}
				return nil
			}, func() int {
				continuations++
				if kind == "continuation-fails" {
					return 2
				}
				return 0
			})
			switch kind {
			case "same", "newer-tool":
				if handled || err != nil || refreshes != 0 || continuations != 0 {
					t.Fatal(handled, err)
				}
			case "refresh-fails":
				if err == nil || handled || refreshes != 1 || continuations != 0 {
					t.Fatal(handled, err)
				}
			default:
				want := 0
				if kind == "continuation-fails" {
					want = 2
				}
				if !handled || err != nil || code != want || refreshes != 1 || continuations != 1 {
					t.Fatal(handled, code, err)
				}
			}
		})
	}
}
