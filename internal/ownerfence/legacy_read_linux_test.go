//go:build linux

package ownerfence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyReadFenceDrainsAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
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
	scope := LegacyReadScope{MasterID: strings.Repeat("a", 32), OwnerID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), RelationshipBinding: strings.Repeat("d", 64), OwnerBinding: strings.Repeat("e", 64)}
	op := strings.Repeat("f", 32)
	challenge := strings.Repeat("7", 64)
	expiresAt := time.Now().Unix() + 60
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("missing state accepted", err)
	}
	if err = fence.InitializeLegacyReadState(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err = fence.InitializeLegacyReadState(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("state recreated", err)
	}
	reader, err := fence.AcquireLegacyRead(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if reader.Check(ctx) != nil {
		t.Fatal("reader lost lease")
	}
	started := make(chan struct{})
	finish := make(chan struct{})
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- reader.WithStream(ctx, func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }, func(context.Context) error {
			close(started)
			<-finish
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not start")
	}
	committed := false
	authorize := func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }
	commit := func(context.Context, *Lease) error { committed = true; return nil }
	failSync := func() error { return errors.New("injected directory sync failure") }
	if err = other.revokeLegacyRead(ctx, scope, op, challenge, expiresAt, authorize, commit, failSync); !errors.Is(err, ErrUnsafe) || committed {
		t.Fatal("failed post-rename sync acknowledged", err)
	}
	if err = other.revokeLegacyRead(ctx, scope, op, challenge, expiresAt, authorize, commit, failSync); !errors.Is(err, ErrUnsafe) || committed {
		t.Fatal("retry skipped failed directory sync", err)
	}
	status := ""
	if err = other.ObserveLegacyReadStatus(ctx, scope, op, challenge, expiresAt, authorize, func(_ context.Context, _ *Lease, state string) error { status = state; return nil }); err != nil || status != "draining" {
		t.Fatal("draining status not available while stream held", status, err)
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("new read admitted during draining", err)
	}
	reader.Release()
	if reader.Check(ctx) == nil {
		t.Fatal("released borrow remained usable")
	}
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	err = other.RevokeLegacyRead(short, scope, op, challenge, expiresAt, authorize, commit)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || committed {
		t.Fatal("release unlocked an active stream", err)
	}
	close(finish)
	if err = <-streamDone; !errors.Is(err, ErrUnsafe) {
		t.Fatal("concurrent release was not reported", err)
	}
	if err = other.RevokeLegacyRead(ctx, scope, op, challenge, expiresAt, func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }, func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("revoked state accepted", err)
	}
	reopened, err := Open(root, dir, fixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("restart accepted revoked state", err)
	}
	status = ""
	if err = reopened.ObserveLegacyReadStatus(ctx, scope, op, challenge, expiresAt, authorize, func(_ context.Context, _ *Lease, state string) error { status = state; return nil }); err != nil || status != "revoked" {
		t.Fatal("revoked status after reopen", status, err)
	}
	if err = reopened.ObserveLegacyReadStatus(ctx, scope, op, strings.Repeat("8", 64), expiresAt, authorize, func(context.Context, *Lease, string) error { return nil }); !errors.Is(err, ErrUnsafe) {
		t.Fatal("wrong original challenge observed", err)
	}
	if err = reopened.RevokeLegacyRead(ctx, scope, op, challenge, expiresAt, func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }, func(ctx context.Context, lease *Lease) error { return lease.Check(ctx) }); err != nil {
		t.Fatal("same operation retry failed", err)
	}
	if err = reopened.RevokeLegacyRead(ctx, scope, strings.Repeat("1", 32), challenge, expiresAt, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { return nil }); !errors.Is(err, ErrUnsafe) {
		t.Fatal("different operation accepted", err)
	}
	if err = reopened.RevokeLegacyRead(ctx, scope, op, strings.Repeat("8", 64), expiresAt, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { return nil }); !errors.Is(err, ErrUnsafe) {
		t.Fatal("changed challenge accepted", err)
	}
	wrong := scope
	wrong.RelationshipBinding = strings.Repeat("9", 64)
	if _, err = reopened.AcquireLegacyRead(ctx, wrong); !errors.Is(err, ErrUnsafe) {
		t.Fatal("changed relation accepted", err)
	}
	if err = os.WriteFile(filepath.Join(dir, legacyReadName), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("corrupt state accepted", err)
	}
	if err = os.Remove(filepath.Join(dir, legacyReadName)); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("deleted state accepted", err)
	}
	if err = reopened.InitializeLegacyReadState(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("missing registered state reinitialized", err)
	}
}

func TestLegacyReadLostEnrollmentNeverRepairsState(t *testing.T) {
	ctx := context.Background()
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
	scope := LegacyReadScope{MasterID: strings.Repeat("a", 32), OwnerID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), RelationshipBinding: strings.Repeat("d", 64), OwnerBinding: strings.Repeat("e", 64)}
	if err = fence.InitializeLegacyReadState(ctx, scope); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, directory, "old-stream")
	if err = os.Rename(filepath.Join(dir, legacyReadStreamName), old); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, legacyReadStreamName), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced stream lock accepted", err)
	}
	if err = os.Remove(filepath.Join(dir, legacyReadStreamName)); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(old, filepath.Join(dir, legacyReadStreamName)); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(dir, legacyReadStreamName), old); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(".owner-control-lock", filepath.Join(dir, legacyReadStreamName)); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlinked stream lock accepted", err)
	}
	if err = os.Remove(filepath.Join(dir, legacyReadStreamName)); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(old, filepath.Join(dir, legacyReadStreamName)); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, legacyReadEnrollmentName)); err != nil {
		t.Fatal(err)
	}
	if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("missing enrollment accepted", err)
	}
	if err = fence.InitializeLegacyReadState(ctx, scope); !errors.Is(err, ErrUnsafe) {
		t.Fatal("lost enrollment silently replaced", err)
	}
	if _, err = os.Stat(filepath.Join(dir, legacyReadEnrollmentName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing enrollment recreated", err)
	}
}

func TestLegacyReadDrainRechecksStreamLockAfterCommit(t *testing.T) {
	ctx := context.Background()
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
	scope := LegacyReadScope{MasterID: strings.Repeat("a", 32), OwnerID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), RelationshipBinding: strings.Repeat("d", 64), OwnerBinding: strings.Repeat("e", 64)}
	if err = fence.InitializeLegacyReadState(ctx, scope); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, directory, "held-stream")
	err = fence.RevokeLegacyRead(ctx, scope, strings.Repeat("f", 32), strings.Repeat("7", 64), time.Now().Unix()+60, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error {
		if e := os.Rename(filepath.Join(dir, legacyReadStreamName), old); e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dir, legacyReadStreamName), make([]byte, 32), 0600)
	})
	if !errors.Is(err, ErrUnsafe) {
		t.Fatal("replacement after signing accepted", err)
	}
}

func TestLegacyReadDrainExpiryNeverReturnsReceiptOrReactivates(t *testing.T) {
	for _, phase := range []string{"received_expired", "during_auth", "waiting_stream", "during_sign"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
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
			scope := LegacyReadScope{MasterID: strings.Repeat("a", 32), OwnerID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), RelationshipBinding: strings.Repeat("d", 64), OwnerBinding: strings.Repeat("e", 64)}
			if err = fence.InitializeLegacyReadState(ctx, scope); err != nil {
				t.Fatal(err)
			}
			op, challenge := strings.Repeat("f", 32), strings.Repeat("7", 64)
			expiresAt := time.Now().Unix() + 2
			if phase == "received_expired" {
				expiresAt = time.Now().Unix()
			}
			var reader *LegacyReadLease
			if phase == "waiting_stream" {
				reader, err = fence.AcquireLegacyRead(ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Release()
			}
			committed := false
			authorize := func(held context.Context, _ *Lease) error {
				if phase == "during_auth" {
					<-held.Done()
				}
				return nil
			}
			commit := func(held context.Context, _ *Lease) error {
				if phase == "during_sign" {
					<-held.Done()
					return nil
				}
				committed = true
				return nil
			}
			if err = fence.RevokeLegacyRead(ctx, scope, op, challenge, expiresAt, authorize, commit); err == nil || committed {
				t.Fatal("expired operation returned success", phase, err)
			}
			if phase == "received_expired" || phase == "during_auth" {
				lease, err := fence.AcquireLegacyRead(ctx, scope)
				if err != nil {
					t.Fatal("unstarted drain changed active state", err)
				}
				lease.Release()
				return
			}
			if reader != nil {
				reader.Release()
			}
			if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
				t.Fatal("expired drain reactivated reads", err)
			}
			state := ""
			if err = fence.ObserveLegacyReadStatus(ctx, scope, op, challenge, expiresAt, func(context.Context, *Lease) error { return nil }, func(_ context.Context, _ *Lease, observed string) error { state = observed; return nil }); err != nil {
				t.Fatal("fresh status failed", err)
			}
			want := "draining"
			if phase == "during_sign" {
				want = "revoked"
			}
			if state != want {
				t.Fatal("wrong retained state", phase, state)
			}
			if err = fence.ResumeLegacyRead(ctx, scope, op, strings.Repeat("8", 64), expiresAt, time.Now().Unix()+10, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { t.Error("wrong operation signed"); return nil }); err == nil {
				t.Fatal("wrong original challenge resumed")
			}
			if err = fence.ResumeLegacyRead(ctx, scope, op, challenge, expiresAt, time.Now().Unix(), func(context.Context, *Lease) error { t.Error("expired resume authenticated"); return nil }, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { t.Error("expired resume signed"); return nil }); err == nil {
				t.Fatal("expired resume accepted")
			}
			resumed := false
			if err = fence.ResumeLegacyRead(ctx, scope, op, challenge, expiresAt, time.Now().Unix()+10, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { return nil }, func(context.Context, *Lease) error { resumed = true; return nil }); err != nil || !resumed {
				t.Fatal("fresh resume failed", err)
			}
			if _, err = fence.AcquireLegacyRead(ctx, scope); !errors.Is(err, ErrUnsafe) {
				t.Fatal("resume reactivated reads", err)
			}
			state = ""
			if err = fence.ObserveLegacyReadStatus(ctx, scope, op, challenge, expiresAt, func(context.Context, *Lease) error { return nil }, func(_ context.Context, _ *Lease, observed string) error { state = observed; return nil }); err != nil || state != "revoked" {
				t.Fatal("resumed state not durable", state, err)
			}
		})
	}
}
