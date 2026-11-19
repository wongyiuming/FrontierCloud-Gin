package media

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOwnedPlainVersionHoldsLeaseAndRejectsReplacement(t *testing.T) {
	root, db, service, relationship := ownedFixture(t)
	ctx := context.Background()
	object := store.MediaObject{ID: strings.Repeat("1", 64), Path: "music/version/track.mp3", Kind: "audio"}
	receipt, err := service.OwnedUpload(ctx, relationship, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if stream, reader, release, err := service.OpenVerifiedOwnedPlain(ctx, object.ID, strings.Repeat("0", 64)); !errors.Is(err, store.ErrNodeState) || stream != nil || reader != nil || release != nil {
		t.Fatal("incorrect digest admitted", err)
	}
	stream, reader, release, err := service.OpenVerifiedOwnedPlain(ctx, object.ID, receipt.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		unlock, err := service.acquire(wait, true)
		if err == nil {
			unlock()
		}
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatal("writer bypassed verified read", err)
	case <-time.After(100 * time.Millisecond):
	}
	content, err := io.ReadAll(reader)
	if err != nil || string(content) != "ID3payload" {
		t.Fatal("verified content", err)
	}
	_ = stream.File.Close()
	release()
	release()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal("writer remained blocked", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer deadlocked")
	}
	// A second service instance shares only the OS lease. A same-size in-place
	// replacement that restores the old mtime must fail content verification.
	other := &Service{root: service.root}
	writeLease, err := other.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, filepath.FromSlash(object.Path))
	if err := os.WriteFile(name, []byte("ID3changed"), 0600); err != nil {
		writeLease()
		t.Fatal(err)
	}
	if err := os.Chtimes(name, stream.Info.ModTime(), stream.Info.ModTime()); err != nil {
		writeLease()
		t.Fatal(err)
	}
	writeLease()
	// Replacing the coordination inode cannot make a cached chunk proof
	// authorize changed content; cache validity does not rely on that inode.
	lockPath := filepath.Join(root, ".media-mutation.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	assertPlainReplacementRejected(t, service, object.ID, receipt.SHA256)
	restarted, err := New(root, db.Media(), service.identity)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if len(restarted.plainIndexes) != 0 {
		t.Fatal("process-local proofs survived service restart")
	}
	assertPlainReplacementRejected(t, restarted, object.ID, receipt.SHA256)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if stream, reader, release, err := service.OpenVerifiedOwnedPlain(cancelled, object.ID, receipt.SHA256); !errors.Is(err, context.Canceled) || stream != nil || reader != nil || release != nil {
		t.Fatal("cancelled verification admitted", err)
	}
}

func TestOwnedPlainLeaseAcrossProcesses(t *testing.T) {
	root, _, service, relationship := ownedFixture(t)
	ctx := context.Background()
	object := store.MediaObject{ID: strings.Repeat("2", 64), Path: "music/epoch/track.mp3", Kind: "audio"}
	receipt, err := service.OwnedUpload(ctx, relationship, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	stream, _, release, err := service.OpenVerifiedOwnedPlain(ctx, object.ID, receipt.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer stream.File.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestOwnedPlainEpochWriterProcess$", "-test.v")
	child.Env = append(os.Environ(), "FC_PLAIN_EPOCH_HELPER=1", "FC_PLAIN_EPOCH_ROOT="+root, "FC_PLAIN_EPOCH_PATH="+object.Path)
	pipe, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() })
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	waitLine := func(want string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatal("writer exited before", want)
				}
				if line == want {
					return
				}
			case <-deadline:
				t.Fatal("writer did not reach", want)
			}
		}
	}
	waitLine("START")
	select {
	case line := <-lines:
		if line == "DONE" {
			t.Fatal("other process changed object under read lease")
		}
	case <-time.After(150 * time.Millisecond):
	}
	_ = stream.File.Close()
	release()
	waitLine("DONE")
	if err := child.Wait(); err != nil {
		t.Fatal("writer subprocess failed", err)
	}
	assertPlainReplacementRejected(t, service, object.ID, receipt.SHA256)
}

func assertPlainReplacementRejected(t *testing.T, service *Service, id, digest string) {
	t.Helper()
	stream, reader, release, err := service.OpenVerifiedOwnedPlain(context.Background(), id, digest)
	if err != nil {
		if !errors.Is(err, store.ErrNodeState) {
			t.Fatal("unexpected replacement error", err)
		}
		return
	}
	defer release()
	defer stream.File.Close()
	buffer := make([]byte, 16)
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, store.ErrNodeState) {
		t.Fatal("same-size replacement exposed bytes", n, err)
	}
}

func TestOwnedPlainEpochWriterProcess(t *testing.T) {
	if os.Getenv("FC_PLAIN_EPOCH_HELPER") != "1" {
		t.Skip("subprocess fixture only")
	}
	root, err := os.OpenRoot(os.Getenv("FC_PLAIN_EPOCH_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	service := &Service{root: root}
	name := os.Getenv("FC_PLAIN_EPOCH_PATH")
	info, err := root.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("START\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := service.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err == nil {
		_, err = file.WriteString("ID3changed")
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}
	if err == nil {
		err = os.Chtimes(filepath.Join(os.Getenv("FC_PLAIN_EPOCH_ROOT"), filepath.FromSlash(name)), info.ModTime(), info.ModTime())
	}
	release()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("DONE\n")
}
