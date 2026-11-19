//go:build linux

package ownerfence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStageStopDrainsPublishAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	s := StageOperation{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	if err = fence.PrepareStage(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if err = fence.PrepareStage(context.Background(), s); err != nil {
		t.Fatal("retry", err)
	}
	conflict := s
	conflict.OperationID = strings.Repeat("d", 64)
	if err = fence.PrepareStage(context.Background(), conflict); !errors.Is(err, ErrUnsafe) {
		t.Fatal("blob rebound", err)
	}
	pub, err := fence.AcquireStagePublish(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = fence.StopStageAndAcquireCleanup(ctx, s)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup overtook publisher", err)
	}
	pub.Release()
	clean, err := fence.StopStageAndAcquireCleanup(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if err = clean.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	clean.Release()
	reopened, err := Open(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.AcquireStagePublish(context.Background(), s); !errors.Is(err, ErrUnsafe) {
		t.Fatal("late publish accepted", err)
	}
	clean, err = reopened.StopStageAndAcquireCleanup(context.Background(), s)
	if err != nil {
		t.Fatal("cleanup recovery", err)
	}
	clean.Release()
	if err = reopened.PrepareStage(context.Background(), s); !errors.Is(err, ErrUnsafe) {
		t.Fatal("stopped operation restarted", err)
	}
}

func TestStageAtomicStopRecordSurvivesProcessExit(t *testing.T) {
	const rootEnv = "FRONTIERCLOUD_STAGE_ATOMIC_ROOT"
	const phaseEnv = "FRONTIERCLOUD_STAGE_ATOMIC_PHASE"
	s := StageOperation{strings.Repeat("7", 64), strings.Repeat("8", 64), strings.Repeat("9", 64)}
	if dir := os.Getenv(rootEnv); dir != "" {
		root, err := os.OpenRoot(dir)
		if err != nil {
			os.Exit(10)
		}
		fence, err := Open(root, dir, fixtureCodec{})
		if err != nil {
			os.Exit(11)
		}
		lease, err := fence.Acquire(context.Background(), true)
		if err != nil {
			os.Exit(12)
		}
		raw, err := json.Marshal(s)
		if err != nil {
			os.Exit(13)
		}
		err = fence.stageWriteOnceWithHook(stageName("stopped", s.OperationID), raw, func(phase string) {
			if phase == os.Getenv(phaseEnv) {
				os.Exit(0)
			}
		})
		runtime.KeepAlive(lease)
		if err != nil {
			os.Exit(14)
		}
		os.Exit(15)
	}
	for _, phase := range []string{"before_rename", "after_rename"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			fence, err := Create(root, dir, fixtureCodec{})
			if err != nil {
				t.Fatal(err)
			}
			if err = fence.PrepareStage(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestStageAtomicStopRecordSurvivesProcessExit$")
			child.Env = append(os.Environ(), rootEnv+"="+dir, phaseEnv+"="+phase)
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("child: %v: %s", err, output)
			}
			if phase == "before_rename" {
				lease, e := fence.AcquireStagePublish(context.Background(), s)
				if e != nil {
					t.Fatal("partial temp blocked publication", e)
				}
				lease.Release()
			} else if _, e := fence.AcquireStagePublish(context.Background(), s); !errors.Is(e, ErrUnsafe) {
				t.Fatal("committed stop allowed publication", e)
			}
			lease, err := fence.StopStageAndAcquireCleanup(context.Background(), s)
			if err != nil {
				t.Fatal("cleanup recovery", err)
			}
			lease.Release()
		})
	}
}

// Tests process exit, not hardware power loss or malicious rollback.
func TestStageStoppedOperationSurvivesProcessExit(t *testing.T) {
	const variable = "FRONTIERCLOUD_STAGE_EXIT_FIXTURE"
	s := StageOperation{strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64)}
	if dir := os.Getenv(variable); dir != "" {
		root, err := os.OpenRoot(dir)
		if err != nil {
			os.Exit(10)
		}
		fence, err := Open(root, dir, fixtureCodec{})
		if err != nil {
			os.Exit(11)
		}
		if fence.PrepareStage(context.Background(), s) != nil {
			os.Exit(12)
		}
		if _, err = fence.StopStageAndAcquireCleanup(context.Background(), s); err != nil {
			os.Exit(13)
		}
		os.Exit(0) // Intentionally keep the exclusive lease held on exit.
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = Create(root, dir, fixtureCodec{}); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestStageStoppedOperationSurvivesProcessExit$")
	child.Env = append(os.Environ(), variable+"="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child: %v: %s", err, output)
	}
	fence, err := Open(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireStagePublish(context.Background(), s); !errors.Is(err, ErrUnsafe) {
		t.Fatal("publish after crash", err)
	}
	lease, err := fence.StopStageAndAcquireCleanup(context.Background(), s)
	if err != nil {
		t.Fatal("resume cleanup", err)
	}
	lease.Release()
}

func TestStagePartialAndTamperedClaimsFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, directory), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := Create(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	s := StageOperation{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)}
	if err = fence.PrepareStage(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, stageName("operation", s.OperationID))); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireStagePublish(context.Background(), s); !errors.Is(err, ErrUnsafe) {
		t.Fatal("partial claims published", err)
	}
	if err = fence.PrepareStage(context.Background(), s); err != nil {
		t.Fatal("same-scope recovery", err)
	}
	if err = os.WriteFile(filepath.Join(dir, stageName("blob", s.BlobID)), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.StopStageAndAcquireCleanup(context.Background(), s); !errors.Is(err, ErrUnsafe) {
		t.Fatal("tampered scope accepted", err)
	}
}
