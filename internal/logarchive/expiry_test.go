package logarchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"strings"
	"testing"
	"time"
)

func TestLogLifecycleExpiresWithOfflineNodeAndPreservesLiveBlocks(t *testing.T) {
	ctx := context.Background()
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	master := strings.Repeat("a", 32)
	c, e := OpenCatalog(t.TempDir(), key, master)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	target := Target{strings.Repeat("b", 32), strings.Repeat("c", 32), "https://log.test"}
	cfg, e := c.Configure(ctx, target, 0)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	old := now.Add(-Retention - time.Second)
	if e = c.Append(ctx, Audit, old, []byte(`{"message":"expired"}`)); e != nil {
		t.Fatal(e)
	}
	page, e := c.ExpiryPage(ctx, now)
	if e != nil || len(page) != 1 {
		t.Fatal(e)
	}
	entry := page[0]
	replica, e := OpenReplica(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer replica.Close()
	expiry := time.UnixMilli(entry.Record.Header.EndMillis).Add(Retention).Unix()
	if e = replica.Put(ctx, master, entry.Record.Reference(), entry.Ciphertext, expiry, now.Add(-time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = c.Acknowledge(ctx, entry, cfg); e != nil {
		t.Fatal(e)
	}
	if e = c.Append(ctx, Audit, now.Add(-time.Second), []byte(`{"message":"retain-live"}`)); e != nil {
		t.Fatal(e)
	}
	remote := &testRemote{nodes: map[string]*Replica{target.MemberID: replica}, fail: true}
	runtime := NewRuntime(c, remote, func() bool { return true })
	runtime.step(ctx, now)
	if _, e = c.Entry(ctx, entry.Record.Header.ID); e == nil {
		t.Fatal("offline archive prevented the 35-day key lifecycle")
	}
	if e = replica.Expire(ctx, now); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = replica.db.QueryRow("SELECT COUNT(*) FROM replicas").Scan(&count); e != nil || count != 0 {
		t.Fatal("replica did not expire without Master", e)
	}
	status, e := c.QueueStatus(ctx, cfg.Generation)
	if e != nil || status["records"] != 1 {
		t.Fatal("expiry removed a live block", status, e)
	}
}
