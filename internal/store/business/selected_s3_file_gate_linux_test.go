//go:build linux

package business

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func selectedS3FileGateFixture(t *testing.T) (*os.Root, *SelectedS3FileGate, *sealedtree.SQLStore) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err = PrepareSelectedS3FileGate(root, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	tree := &sealedtree.SQLStore{}
	gate, err := OpenSelectedS3FileGate(root, tree, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gate.Close() })
	return root, gate, tree
}

func TestSelectedS3FileGateChild(t *testing.T) {
	name := os.Getenv("FC_S3_GATE_CHILD_ROOT")
	if name == "" {
		return
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tree := &sealedtree.SQLStore{}
	gate, err := OpenSelectedS3FileGate(root, tree, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	lease, err := gate.AcquireSelectedS3(ctx, tree, os.Getenv("FC_S3_GATE_CHILD_UPLOAD"))
	if os.Getenv("FC_S3_GATE_CHILD_EXPECT") == "busy" {
		if lease != nil {
			lease.Release()
			t.Fatal("operation crossed the process lock")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expected bounded lock wait", err)
		}
		return
	}
	if err != nil || lease == nil {
		t.Fatal("independent operation rejected", err)
	}
	lease.Release()
}

func TestSelectedS3FileGateCrossProcessAndDrain(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = PrepareSelectedS3FileGate(root, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	tree := &sealedtree.SQLStore{}
	gate, err := OpenSelectedS3FileGate(root, tree, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	id := strings.Repeat("a", 32)
	hash := sha256.Sum256([]byte(id))
	other := ""
	for i := 0; i < 100; i++ {
		candidate := fmt.Sprintf("%032x", i)
		h := sha256.Sum256([]byte(candidate))
		if h[0]%selectedS3Stripes != hash[0]%selectedS3Stripes {
			other = candidate
			break
		}
	}
	if other == "" {
		t.Fatal("no independent stripe")
	}
	lease, err := gate.AcquireSelectedS3(context.Background(), tree, id)
	if err != nil {
		t.Fatal(err)
	}
	run := func(upload, expected string) {
		t.Helper()
		childCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+dir, "FC_S3_GATE_CHILD_UPLOAD="+upload, "FC_S3_GATE_CHILD_EXPECT="+expected)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("child %s: %v %s", expected, e, output)
		}
	}
	run(id, "busy")
	run(other, "available")
	lease.Release()
	if err = gate.WithSelectedS3Startup(context.Background(), tree, func(context.Context) error {
		run(id, "busy")
		run(other, "busy")
		return nil
	}); err != nil {
		t.Fatal("startup audit lease", err)
	}
	run(id, "available")
	expected := errors.New("startup failed")
	if err = gate.WithSelectedS3Startup(context.Background(), tree, func(context.Context) error { return expected }); !errors.Is(err, expected) {
		t.Fatal("startup failure not propagated", err)
	}
	run(id, "available")
	entered := make(chan struct{})
	finished := make(chan error, 1)
	drainCtx, stopDrain := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopDrain()
	go func() {
		finished <- gate.withDrain(drainCtx, tree, 300*time.Millisecond, func(context.Context) error { close(entered); return nil })
	}()
	limit := time.Now().Add(time.Second)
	for gate.checkRead(context.Background(), tree) == nil {
		if time.Now().After(limit) {
			t.Fatal("drain did not acquire control lock")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-entered:
		t.Fatal("mutation ran before draining")
	default:
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("mutation never ran")
	}
	cancelled, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	called := false
	if err = gate.WithConfigurationDrain(cancelled, tree, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("cancelled full drain mutated configuration", err)
	}
	if err = gate.checkRead(context.Background(), tree); err != nil {
		t.Fatal("cancelled drain retained lock", err)
	}
}

func TestSelectedS3FileGateRejectsReplacedInode(t *testing.T) {
	root, gate, tree := selectedS3FileGateFixture(t)
	name := filepath.Join(selectedS3LockDir, "control.lock")
	if err := root.Rename(name, name+".old"); err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err = gate.AcquireSelectedS3(context.Background(), tree, strings.Repeat("a", 32)); err == nil {
		t.Fatal("replaced control inode accepted")
	}
}

func TestSelectedS3OriginProofExpiresOnRestartAndFailure(t *testing.T) {
	root, gate, tree := selectedS3FileGateFixture(t)
	ctx := context.Background()
	adminOrigin, publicOrigin := "https://admin.example", "https://public.example"
	if err := gate.ConfigureSelectedS3Origins(adminOrigin, publicOrigin); err != nil {
		t.Fatal(err)
	}
	member := store.S3Member{StorageMember: store.StorageMember{ID: strings.Repeat("b", 32), Kind: "S3", Transport: "S3"}, Location: store.S3Location{Endpoint: "https://s3.example", Bucket: "fixture", Region: "us-east-1", Style: "path"}, SealedCredentials: "sealed", CredentialRevision: 1, Revision: 1, ProbeRevision: 1, ProbeState: "ready"}
	if gate.CheckSelectedS3Member(ctx, tree, member) == nil {
		t.Fatal("old durable ready became origin proof")
	}
	if _, err := gate.WithSelectedS3Probe(ctx, tree, member.ID, "https://other.example", publicOrigin, func(context.Context) (store.S3Member, error) {
		t.Fatal("wrong admin origin reached provider")
		return member, nil
	}); err == nil {
		t.Fatal("wrong origin accepted")
	}
	if _, err := gate.WithSelectedS3Probe(ctx, tree, member.ID, adminOrigin, publicOrigin, func(context.Context) (store.S3Member, error) { return member, nil }); err != nil {
		t.Fatal(err)
	}
	if gate.CheckSelectedS3Member(ctx, tree, member) != nil {
		t.Fatal("verified member rejected")
	}
	if gate.CheckSelectedS3PublicOrigin(ctx, tree, member, "https://other.example") == nil {
		t.Fatal("unprobed ingress accepted")
	}
	if gate.CheckSelectedS3AdminOrigin(ctx, tree, member, adminOrigin) != nil || gate.CheckSelectedS3AdminOrigin(ctx, tree, member, publicOrigin) == nil {
		t.Fatal("Admin download origin proof was confused with public ingress proof")
	}
	if _, err := gate.WithSelectedS3Probe(ctx, tree, member.ID, adminOrigin, "https://other.example", func(context.Context) (store.S3Member, error) { return member, nil }); err != nil {
		t.Fatal(err)
	}
	if gate.CheckSelectedS3PublicOrigin(ctx, tree, member, publicOrigin) == nil || gate.CheckSelectedS3PublicOrigin(ctx, tree, member, "https://other.example") != nil {
		t.Fatal("origin switch retained old proof")
	}
	updated := member
	updated.Revision++
	updated.ProbeRevision++
	if gate.CheckSelectedS3Member(ctx, tree, updated) != nil {
		t.Fatal("unchanged provider rejected after enable")
	}
	changed := member
	changed.SealedCredentials = "other"
	if gate.CheckSelectedS3Member(ctx, tree, changed) == nil {
		t.Fatal("changed credentials retained origin proof")
	}
	reopened, err := OpenSelectedS3FileGate(root, tree, func(c context.Context) error { return c.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.ConfigureSelectedS3Origins(adminOrigin, publicOrigin); err != nil {
		t.Fatal(err)
	}
	if reopened.CheckSelectedS3Member(ctx, tree, member) == nil {
		t.Fatal("restart reused process-local origin proof")
	}
	if reopened.CheckSelectedS3AdminOrigin(ctx, tree, member, adminOrigin) == nil {
		t.Fatal("restart reused Admin download origin proof")
	}
	if _, err = gate.WithSelectedS3Probe(ctx, tree, member.ID, adminOrigin, publicOrigin, func(context.Context) (store.S3Member, error) { return store.S3Member{}, errors.New("probe failed") }); err == nil {
		t.Fatal("failed probe succeeded")
	}
	if gate.CheckSelectedS3Member(ctx, tree, member) == nil {
		t.Fatal("failed probe retained origin proof")
	}
}

func TestSelectedS3FileGateInheritsRuntimeOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Log("cross-UID case requires a root-run isolated fixture")
		return
	}
	dir, err := os.MkdirTemp("", "fc-s3-gate-owner-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	const runtimeUID = 65534
	const runtimeGID = 65534
	if err = os.Chown(dir, runtimeUID, runtimeGID); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = PrepareSelectedS3FileGate(root, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	names := []string{selectedS3LockDir}
	for _, lock := range selectedS3LockNames() {
		names = append(names, filepath.Join(selectedS3LockDir, lock))
	}
	for _, name := range names {
		info, e := root.Lstat(name)
		if e != nil {
			t.Fatal(e)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != runtimeUID || st.Gid != runtimeGID {
			t.Fatal("lock did not inherit runtime volume owner")
		}
	}
	binary := filepath.Join(dir, "gate-test")
	if err = os.Link(os.Args[0], binary); err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, binary, "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+dir, "FC_S3_GATE_CHILD_UPLOAD="+strings.Repeat("a", 32), "FC_S3_GATE_CHILD_EXPECT=available")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runtimeUID, Gid: runtimeGID}}
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("runtime UID could not acquire prepared gate: %v %s", e, output)
	}
	t.Log("cross-UID runtime acquired prepared S3 gate")
}
