//go:build linux

package business

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedS3RecoveryExclusiveAndTransition(t *testing.T) {
	root, gate, tree := selectedS3FileGateFixture(t)
	id := strings.Repeat("a", 32)
	var pending atomic.Bool
	pending.Store(true)
	audit := func(context.Context) error {
		if pending.Load() {
			return ErrSelectedS3RecoveryRequired
		}
		return nil
	}
	startup, stopStartup := context.WithCancel(context.Background())
	allowMember := func(_ context.Context, member string) error {
		if member == strings.Repeat("b", 32) {
			return nil
		}
		return errors.New("not pending")
	}
	if err := gate.StartSelectedS3(startup, tree, audit, allowMember, func(context.Context) error {
		return gate.ConfigureSelectedS3Origins("https://admin.example", "https://public.example")
	}); err != nil {
		t.Fatal(err)
	}
	stopStartup() // The retained lock belongs to runtime, not the startup wait.
	run := func(expected string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+root.Name(), "FC_S3_GATE_CHILD_UPLOAD="+id, "FC_S3_GATE_CHILD_EXPECT="+expected)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child %s: %v %s", expected, err, output)
		}
	}
	run("busy")
	if err := gate.checkRead(context.Background(), tree); err == nil {
		t.Fatal("public S3 read allowed during recovery")
	}
	member := store.S3Member{StorageMember: store.StorageMember{ID: strings.Repeat("b", 32), Kind: "S3", Transport: "S3"}, Location: store.S3Location{Endpoint: "https://s3.example", Bucket: "fixture", Region: "us-east-1", Style: "path"}, SealedCredentials: "sealed", CredentialRevision: 1, Revision: 1, ProbeRevision: 1, ProbeState: "ready"}
	if _, err := gate.WithSelectedS3Probe(context.Background(), tree, member.ID, "https://admin.example", "https://public.example", func(context.Context) (store.S3Member, error) {
		run("busy")
		return member, nil
	}); err != nil {
		t.Fatal("recovery probe", err)
	}
	if _, err := gate.WithSelectedS3Probe(context.Background(), tree, strings.Repeat("c", 32), "https://admin.example", "https://public.example", func(context.Context) (store.S3Member, error) {
		t.Fatal("unrelated member reached provider")
		return member, nil
	}); err == nil {
		t.Fatal("unrelated member probe accepted")
	}
	listed := false
	if err := gate.WithSelectedS3Listing(context.Background(), tree, func(context.Context) error { listed = true; return nil }); err != nil || !listed {
		t.Fatal("authenticated listing unavailable", err)
	}
	if err := gate.WithSelectedS3ManagementRead(context.Background(), tree, func(context.Context) error { t.Fatal("management mutation allowed"); return nil }); err == nil {
		t.Fatal("management mutation allowed during recovery")
	}
	if lease, err := gate.AcquireSelectedS3Admission(context.Background(), tree, id); err == nil {
		lease.Release()
		t.Fatal("new admission during recovery")
	}
	lease, err := gate.AcquireSelectedS3(context.Background(), tree, id)
	if err != nil || lease.Check(context.Background()) != nil {
		t.Fatal("recovery borrow", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if err = gate.FinishSelectedS3Recovery(ctx, tree); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("settlement crossed active borrower", err)
	}
	cancel()
	lease.Release()
	if err = gate.FinishSelectedS3Recovery(context.Background(), tree); !errors.Is(err, ErrSelectedS3RecoveryRequired) {
		t.Fatal("pending audit released gate", err)
	}
	run("busy")
	pending.Store(false)
	if err = gate.FinishSelectedS3Recovery(context.Background(), tree); err != nil {
		t.Fatal("terminal transition", err)
	}
	run("available")
	lease, err = gate.AcquireSelectedS3Admission(context.Background(), tree, id)
	if err != nil {
		t.Fatal("normal admission not restored", err)
	}
	lease.Release()
}

func TestSelectedS3RecoveryCloseWaitsForBorrower(t *testing.T) {
	root, gate, tree := selectedS3FileGateFixture(t)
	if err := gate.StartSelectedS3(context.Background(), tree, func(context.Context) error { return ErrSelectedS3RecoveryRequired }, func(context.Context, string) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	lease, err := gate.AcquireSelectedS3(context.Background(), tree, strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if err = gate.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close did not wait", err)
	}
	cancel()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+root.Name(), "FC_S3_GATE_CHILD_UPLOAD="+strings.Repeat("c", 32), "FC_S3_GATE_CHILD_EXPECT=busy")
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("close released lock early: %v %s", e, output)
	}
	lease.Release()
	if err = gate.CloseContext(context.Background()); err != nil {
		t.Fatal("close after drain", err)
	}
}

func TestSelectedS3RecoveryRejectsUnverifiedStartup(t *testing.T) {
	_, gate, tree := selectedS3FileGateFixture(t)
	want := errors.New("unauthenticated journal")
	installed := false
	err := gate.StartSelectedS3(context.Background(), tree, func(context.Context) error { return want }, nil, func(context.Context) error { installed = true; return nil })
	if !errors.Is(err, want) || installed {
		t.Fatal("unverified startup installed S3", err)
	}
	err = gate.StartSelectedS3(context.Background(), tree, func(context.Context) error { return ErrSelectedS3RecoveryRequired }, nil, func(context.Context) error { installed = true; return nil })
	if err == nil || installed {
		t.Fatal("recovery enabled without member proof", err)
	}
	lease, err := gate.AcquireSelectedS3(context.Background(), tree, strings.Repeat("d", 32))
	if err != nil {
		t.Fatal("failed startup retained control lock", err)
	}
	lease.Release()
}

func TestSelectedS3RecoveryCloseWaitsForStartup(t *testing.T) {
	root, gate, tree := selectedS3FileGateFixture(t)
	entered, proceed, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- gate.StartSelectedS3(context.Background(), tree, func(context.Context) error {
			close(entered)
			<-proceed
			return ErrSelectedS3RecoveryRequired
		}, func(context.Context, string) error { return nil }, func(context.Context) error { return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if err := gate.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close did not wait for startup", err)
	}
	cancel()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+root.Name(), "FC_S3_GATE_CHILD_UPLOAD="+strings.Repeat("e", 32), "FC_S3_GATE_CHILD_EXPECT=busy")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("startup lock released early: %v %s", err, output)
	}
	close(proceed)
	if err := <-finished; err == nil {
		t.Fatal("cancelled startup installed runtime")
	}
	if err := gate.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}
