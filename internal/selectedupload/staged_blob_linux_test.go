//go:build linux

package selectedupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestStagedBlobCancellationNeverPublishes(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("only a synthetic encrypted object")
	digest := sha256.Sum256(payload)
	sum := hex.EncodeToString(digest[:])
	op, blob := strings.Repeat("1", 64), strings.Repeat("2", 64)
	dest, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease := &testLease{}
	body := io.NopCloser(bytes.NewReader(payload))
	err = RunStaged(ctx, lease, &testDeadline{}, body, time.Second, func(ctx context.Context) error {
		if e := publisher.Stage(ctx, op, blob, int64(len(payload)), sum, body); e != nil {
			return e
		}
		cancel()
		return nil
	}, func(ctx context.Context) error {
		return publisher.PublishStaged(ctx, op, blob, int64(len(payload)), sum)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled staged transfer accepted", err)
	}
	if _, err = root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled stage became visible", err)
	}
	lease = &testLease{}
	body = io.NopCloser(bytes.NewReader(payload))
	err = RunStaged(context.Background(), lease, &testDeadline{}, body, time.Second, func(ctx context.Context) error {
		return publisher.Stage(ctx, op, blob, int64(len(payload)), sum, body)
	}, func(ctx context.Context) error {
		return publisher.PublishStaged(ctx, op, blob, int64(len(payload)), sum)
	})
	if err != nil {
		t.Fatal("verified stage retry failed", err)
	}
	got, err := root.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	actual, err := io.ReadAll(got)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("published bytes differ", err)
	}
}
