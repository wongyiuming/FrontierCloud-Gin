package logarchive

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogNodeOutboxPublicKeyOnlyAndDurableAcknowledgement(t *testing.T) {
	ctx := context.Background()
	master, node := strings.Repeat("a", 32), strings.Repeat("b", 32)
	v, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	catalog, e := OpenCatalog(t.TempDir(), v, master)
	if e != nil {
		t.Fatal(e)
	}
	defer catalog.Close()
	if _, e = catalog.Configure(ctx, Target{node, strings.Repeat("c", 32), "https://log.test"}, 0); e != nil {
		t.Fatal(e)
	}
	public, e := catalog.IngestPublic(ctx)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "producer.sqlite")
	db, e := sql.Open("sqlite", file)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	producer, e := OpenProducer(db, node)
	if e != nil {
		t.Fatal(e)
	}
	if e = producer.Configure(ctx, master, public, true, nil); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if handled, e := producer.AppendTransaction(ctx, tx, Node, map[string]any{"message": "node-private-marker"}); e != nil || !handled {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	// Reopening requires only the persisted public-key configuration.
	producer, e = OpenProducer(db, node)
	if e != nil || !producer.Enabled() {
		t.Fatal("producer restart lost binding", e)
	}
	packets, e := producer.Packets(ctx, master)
	if e != nil || len(packets) != 1 {
		t.Fatal("outbox lost packet", e)
	}
	packet := packets[0]
	fake, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = openIngest(fake.Bytes(), packet); e == nil {
		t.Fatal("producer-side key decrypted Master packet")
	}
	bad := packet
	bad.Cipher = append([]byte{}, packet.Cipher...)
	bad.Cipher[0] ^= 1
	if e = catalog.Ingest(ctx, node, bad); e == nil {
		t.Fatal("corrupt ingest accepted")
	}
	if e = catalog.Ingest(ctx, strings.Repeat("d", 32), packet); e == nil {
		t.Fatal("cross-node packet accepted")
	}
	if e = catalog.Ingest(ctx, node, packet); e != nil {
		t.Fatal(e)
	}
	if e = catalog.Ingest(ctx, node, packet); e != nil {
		t.Fatal("lost ack replay", e)
	}
	status, e := catalog.QueueStatus(ctx, 1)
	if e != nil || status["records"] != 1 {
		t.Fatal("replay duplicated archived log", status, e)
	}
	pending, _ := producer.Packets(ctx, master)
	if len(pending) != 1 {
		t.Fatal("producer discarded before Master acknowledgement")
	}
	acks, e := catalog.IngestReceipts(ctx, node)
	if e != nil {
		t.Fatal(e)
	}
	if e = producer.Configure(ctx, master, public, true, acks); e != nil {
		t.Fatal(e)
	}
	pending, _ = producer.Packets(ctx, master)
	if len(pending) != 0 {
		t.Fatal("durable ack did not release exact producer copy")
	}
	for _, suffix := range []string{"", "-wal"} {
		raw, e := os.ReadFile(file + suffix)
		if e == nil && bytes.Contains(raw, []byte("node-private-marker")) {
			t.Fatal("node log plaintext entered disk")
		}
	}
	now := time.Now()
	entries, _, e := catalog.Query(ctx, now.Add(-time.Hour), now, now, Node, false, "")
	if e != nil || len(entries) != 1 {
		t.Fatal(e)
	}
	entry, e := catalog.Entry(ctx, entries[0].Record.Header.ID)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := OpenForMaster(v, entry.Record, entry.Ciphertext)
	if e != nil || !bytes.Contains(plain, []byte("node-private-marker")) || !bytes.Contains(plain, []byte(node)) {
		t.Fatal("Master lost source-bound log", e)
	}
}
