package logarchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogPendingRestartCoalescingAndImmutablePublication(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	master := strings.Repeat("a", 32)
	c, e := OpenCatalog(root, key, master)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Configure(ctx, Target{strings.Repeat("b", 32), strings.Repeat("c", 32), "https://logs.test"}, 0); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Add(-time.Minute)
	raw := []byte(`[{"message":"pending-private-marker"}]`)
	for i := range 20 {
		stamp := now.Add(time.Duration(i) * time.Second)
		if e = c.QueueCapture(ctx, Access, stamp, stamp.Add(time.Millisecond), raw); e != nil {
			t.Fatal(e)
		}
	}
	status, e := c.QueueStatus(ctx, 1)
	if e != nil || status["records"] != 0 || status["durable_pending"] != 1 {
		t.Fatal("small captures created immutable manifests", status, e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c, e = OpenCatalog(root, key, master)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	pending, e := c.PendingForMaster(ctx, Access)
	if e != nil || len(pending) != 20 {
		t.Fatal("restart lost encrypted pending captures", len(pending), e)
	}
	for _, suffix := range []string{"", "-wal"} {
		p, e := os.ReadFile(filepath.Join(root, ".log-archive/catalog.sqlite") + suffix)
		if e == nil && bytes.Contains(p, []byte("pending-private-marker")) {
			t.Fatal("pending plaintext persisted")
		}
	}
	if e = c.PublishCapture(ctx, time.Now(), Access, true); e != nil {
		t.Fatal(e)
	}
	entries, more, e := c.Query(ctx, now.Add(-time.Second), time.Now(), time.Now(), Access, false, "")
	if e != nil || more || len(entries) != 1 {
		t.Fatal("publication count", len(entries), e)
	}
	first, e := c.Entry(ctx, entries[0].Record.Header.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.QueueCapture(ctx, Access, time.Now(), time.Now().Add(time.Millisecond), raw); e != nil {
		t.Fatal(e)
	}
	unchanged, e := c.Entry(ctx, first.Record.Header.ID)
	if e != nil || !bytes.Equal(first.Ciphertext, unchanged.Ciphertext) {
		t.Fatal("new capture changed granted immutable block", e)
	}
	plain, e := OpenForMaster(key, first.Record, first.Ciphertext)
	if e != nil || bytes.Count(plain, []byte("pending-private-marker")) != 20 {
		t.Fatal("coalesced body mismatch", e)
	}
}
