package logarchive

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type testRemote struct {
	nodes         map[string]*Replica
	pulls, stores int
	fail          bool
}

func TestLogSharedCatalogSnapshotAndBrowserVector(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, e := sql.Open("sqlite", filepath.Join(dir, "business.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, e = db.Exec("CREATE TABLE business_fact(id TEXT PRIMARY KEY,value TEXT NOT NULL)")
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("INSERT INTO business_fact VALUES('preserve','business-unchanged')")
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	c, e := SharedCatalog(db, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	target := Target{strings.Repeat("b", 32), strings.Repeat("c", 32), "https://node.test"}
	if _, e = c.Configure(ctx, target, 0); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	raw := []byte(fmt.Sprintf(`[{"message":"日志浏览器联测","received_at_ms":%d}]`, now.UnixMilli()))
	if e = c.Append(ctx, Application, now, raw); e != nil {
		t.Fatal(e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	if e = db.Ping(); e != nil {
		t.Fatal("archive closed borrowed business DB", e)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, e = db.Exec("VACUUM INTO ?", snapshot); e != nil {
		t.Fatal(e)
	}
	restored, e := sql.Open("sqlite", snapshot)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	var fact string
	if e = restored.QueryRow("SELECT value FROM business_fact WHERE id='preserve'").Scan(&fact); e != nil || fact != "business-unchanged" {
		t.Fatal("snapshot lost unrelated business", e)
	}
	recovered, e := SharedCatalog(restored, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := recovered.Configuration(ctx)
	if e != nil || cfg.Target != target {
		t.Fatal("snapshot lost archive authority", e)
	}
	entries, _, e := recovered.Query(ctx, now.Add(-time.Hour), now.Add(time.Second), now.Add(time.Second), Application, false, "")
	if e != nil || len(entries) != 1 {
		t.Fatal("snapshot lost queue", e)
	}
	entry := entries[0]
	if len(entry.Ciphertext) != 0 {
		t.Fatal("metadata query loaded log bytes on Master")
	}
	entry, e = recovered.Entry(ctx, entry.Record.Header.ID)
	if e != nil {
		t.Fatal(e)
	}
	decrypt, e := OpenForMaster(key, entry.Record, entry.Ciphertext)
	if e != nil || !bytes.Equal(decrypt, raw) {
		t.Fatal("restored ciphertext cannot decrypt", e)
	}
	// Synthetic fixture only: no deployed identity or credential is printed.
	dataKey, e := recovered.ReadKey(entry.Record)
	if e != nil {
		t.Fatal(e)
	}
	vector, _ := json.Marshal(map[string]any{"header": entry.Record.Header, "reference": entry.Record.Reference(), "key": base64.RawURLEncoding.EncodeToString(dataKey[:]), "ciphertext": base64.StdEncoding.EncodeToString(entry.Ciphertext), "plaintext": json.RawMessage(raw)})
	clear(dataKey[:])
	fmt.Println("LOG_BROWSER_VECTOR=" + base64.StdEncoding.EncodeToString(vector))
}

func (r *testRemote) Store(c context.Context, t Target, ref Reference, p []byte, exp int64) error {
	r.stores++
	if r.fail {
		return ErrBlock
	}
	return r.nodes[t.MemberID].Put(c, strings.Repeat("a", 32), ref, p, exp, time.Now())
}
func (r *testRemote) Pull(c context.Context, target, source Target, ref Reference, exp int64) error {
	r.pulls++
	if r.fail {
		return ErrBlock
	}
	p, e := r.nodes[source.MemberID].Read(c, strings.Repeat("a", 32), ref, time.Now())
	if e != nil {
		return e
	}
	return r.nodes[target.MemberID].Put(c, strings.Repeat("a", 32), ref, p, exp, time.Now())
}
func (r *testRemote) Verify(c context.Context, t Target, ref Reference) error {
	_, e := r.nodes[t.MemberID].Read(c, strings.Repeat("a", 32), ref, time.Now())
	return e
}
func (r *testRemote) Release(c context.Context, t Target, ref Reference, expired bool) error {
	if r.fail {
		return ErrBlock
	}
	return r.nodes[t.MemberID].Release(c, strings.Repeat("a", 32), ref, expired, time.Now())
}

func TestLogCatalogRestartAndDirectMoveWithoutMasterBytes(t *testing.T) {
	ctx := context.Background()
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	root := t.TempDir()
	c, e := OpenCatalog(root, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	a := Target{strings.Repeat("b", 32), strings.Repeat("c", 32), "https://a.test"}
	b := Target{strings.Repeat("d", 32), strings.Repeat("e", 32), "https://b.test"}
	if e = c.Append(ctx, Audit, time.Now(), []byte(`{"message":"not enabled"}`)); !errors.Is(e, ErrPolicy) {
		t.Fatal("capture before activation", e)
	}
	cfg, e := c.Configure(ctx, a, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Configure(ctx, b, 0); !errors.Is(e, ErrPolicy) {
		t.Fatal("stale Admin generation accepted")
	}
	now := time.Now()
	raw := []byte(`[{"message":"must-not-leak-record","source":"Master"}]`)
	if e = c.AppendBatch(ctx, Audit, now.Add(-13*time.Hour), now.Add(-13*time.Hour+time.Second), raw); e != nil {
		t.Fatal(e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c, e = OpenCatalog(root, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	got, e := c.Configuration(ctx)
	if e != nil || got != cfg {
		t.Fatal("restart lost configuration", e)
	}
	one, e := OpenReplica(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer one.Close()
	two, e := OpenReplica(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer two.Close()
	remote := &testRemote{nodes: map[string]*Replica{a.MemberID: one, b.MemberID: two}}
	r := NewRuntime(c, remote, func() bool { return true })
	r.step(ctx, now)
	r.step(ctx, now)
	page, more, e := c.Query(ctx, now.Add(-14*time.Hour), now, now, Audit, false, "")
	if e != nil || more || len(page) != 1 {
		t.Fatal("bounded query", len(page), e)
	}
	v := page[0]
	if len(v.Ciphertext) != 0 || v.Remote != a {
		t.Fatal("12h release or destination acknowledgement failed")
	}
	if !c.UsesNode(ctx, a.MemberID) {
		t.Fatal("archive node lost protection")
	}
	_, e = c.Configure(ctx, b, cfg.Generation)
	if e != nil {
		t.Fatal(e)
	}
	remote.fail = true
	r.step(ctx, now)
	retained, e := c.Entry(ctx, v.Record.Header.ID)
	if e != nil || retained.Remote != a {
		t.Fatal("failed move lost old placement")
	}
	if _, e = one.Read(ctx, strings.Repeat("a", 32), v.Record.Reference(), now); e != nil {
		t.Fatal("failed move removed source")
	}
	remote.fail = false
	r.step(ctx, now.Add(2*time.Minute))
	r.step(ctx, now.Add(2*time.Minute))
	if remote.stores != 1 || remote.pulls < 1 {
		t.Fatal("move used Master cached bytes instead of source pull", remote.stores, remote.pulls)
	}
	final, e := c.Entry(ctx, v.Record.Header.ID)
	if e != nil || final.Remote != b || final.Cleanup.MemberID != "" {
		t.Fatal("move cleanup not committed", e)
	}
	if _, e = one.Read(ctx, strings.Repeat("a", 32), v.Record.Reference(), now); e == nil {
		t.Fatal("old owned copy retained after successful move")
	}
	p, e := two.Read(ctx, strings.Repeat("a", 32), v.Record.Reference(), now)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := OpenForMaster(key, final.Record, p)
	if e != nil || !bytes.Equal(plain, raw) {
		t.Fatal("move changed log contents", e)
	}
	if c.UsesNode(ctx, a.MemberID) || !c.UsesNode(ctx, b.MemberID) {
		t.Fatal("node protection did not follow placement")
	}
	for _, suffix := range []string{"", "-wal"} {
		p, e := os.ReadFile(filepath.Join(root, ".log-archive/catalog.sqlite") + suffix)
		if e == nil && bytes.Contains(p, []byte("must-not-leak-record")) {
			t.Fatal("plaintext entered SQL/WAL")
		}
	}
}
