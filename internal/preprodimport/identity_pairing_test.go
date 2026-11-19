package preprodimport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	storeSQLite "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// This in-process transport exercises real SQLite identities, vaults, signed
// pairing and HMAC confirmation; it is deliberately not evidence of live TLS.
type pairingNode struct {
	service         *node.Service
	db              *storeSQLite.Store
	origin, profile string
}
type pairingTransport struct{ nodes map[string]*pairingNode }

func (p *pairingTransport) Identity(ctx context.Context, origin, id, key, role string) (node.Peer, error) {
	n := p.nodes[origin]
	if n == nil {
		return node.Peer{}, errors.New("synthetic peer not found")
	}
	env, err := n.service.SignedIdentity(ctx, strings.Repeat("a", 32))
	if err != nil {
		return node.Peer{}, err
	}
	nodeID, _ := env.Payload["node_id"].(string)
	actualRole, _ := env.Payload["role"].(string)
	public, _ := env.Payload["public_key"].(string)
	if protocol.Verify(public, env.Payload, env.Signature) != nil || id != "" && id != nodeID || key != "" && key != public || role != "" && role != actualRole {
		return node.Peer{}, errors.New("synthetic identity mismatch")
	}
	return node.Peer{ID: nodeID, Endpoint: origin, PublicKey: public, Role: actualRole, StorageTransport: n.profile}, nil
}
func envelopeFromWire(v any) (node.Envelope, error) {
	x, ok := v.(map[string]any)
	if !ok {
		return node.Envelope{}, errors.New("invalid envelope")
	}
	p, ok := x["payload"].(map[string]any)
	if !ok {
		return node.Envelope{}, errors.New("invalid payload")
	}
	s, ok := x["signature"].(string)
	if !ok {
		return node.Envelope{}, errors.New("invalid signature")
	}
	return node.Envelope{Payload: p, Signature: s}, nil
}
func (p *pairingTransport) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	n := p.nodes[origin]
	if n == nil {
		return nil, errors.New("synthetic peer not found")
	}
	raw, err := protocol.Canonical(value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body map[string]any
	if err = dec.Decode(&body); err != nil {
		return nil, err
	}
	if route == "/internal/v1/pair" {
		pair, e := envelopeFromWire(body["package"])
		if e != nil {
			return nil, e
		}
		master, e := envelopeFromWire(body["master"])
		if e != nil {
			return nil, e
		}
		id, _ := body["relationship_id"].(string)
		secret, _ := body["credential"].(string)
		if e = n.service.ConsumePair(ctx, pair, master, id, secret); e != nil {
			return nil, e
		}
		return map[string]any{"state": "pending"}, nil
	}
	if route != "/internal/v1/confirm" {
		return nil, errors.New("unexpected synthetic route")
	}
	values, err := protocol.AuthHeaders(credential, relationship, method, route, raw, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for k, v := range values {
		headers.Set(k, v)
	}
	relation, err := n.service.Authenticate(ctx, headers, method, route, raw, true, false)
	if err != nil {
		return nil, err
	}
	if err = n.service.Confirm(ctx, relation); err != nil {
		return nil, err
	}
	return map[string]any{"state": "active"}, nil
}

func syntheticPairNode(t *testing.T, transport *pairingTransport, origin, profile string) *pairingNode {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "media")
	recordings := filepath.Join(root, "recordings")
	for _, name := range []string{filepath.Join(data, "music"), filepath.Join(data, "vido"), filepath.Join(data, "lyrics"), recordings} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := storeSQLite.Open(filepath.Join(root, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := node.Initialize(ctx, db.Nodes(), filepath.Join(root, "private"))
	if err != nil {
		t.Fatal(err)
	}
	volume, err := media.New(data, db.Media(), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { volume.Close() })
	recordRoot, err := os.OpenRoot(recordings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recordRoot.Close() })
	service := node.NewService(db.Nodes(), id, transport)
	service.ConfigureVolumes(db.Pool(), volume, recordRoot)
	if profile != "" {
		if err = service.ConfigureStorageTransport(profile); err != nil {
			t.Fatal(err)
		}
	}
	n := &pairingNode{service: service, db: db, origin: origin, profile: profile}
	transport.nodes[origin] = n
	return n
}

func TestFreshSQLiteIdentitiesUseNativePromotionAndPairing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native private ACL ownership unavailable")
	}
	ctx := context.Background()
	transport := &pairingTransport{nodes: map[string]*pairingNode{}}
	master := syntheticPairNode(t, transport, "https://master.invalid", "")
	direct := syntheticPairNode(t, transport, "https://direct.invalid", "direct")
	relay := syntheticPairNode(t, transport, "https://relay.invalid:8443", "relay")
	for _, entry := range []struct {
		n          *pairingNode
		role       string
		allocation int64
	}{{master, "Master", 2 * store.GiB}, {direct, "Follower", 0}, {relay, "Follower", 0}} {
		if _, err := entry.n.service.Promote(ctx, entry.role, entry.n.origin, entry.allocation, store.NodeAudit{Actor: "synthetic"}); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]bool{}
	for _, n := range []*pairingNode{master, direct, relay} {
		id, err := n.db.Nodes().ReadIdentity(ctx)
		if err != nil || ids[id.ID] || id.ID == strings.Repeat("1", 32) || id.ID == strings.Repeat("2", 32) || id.ID == strings.Repeat("3", 32) {
			t.Fatalf("identity not distinct: %v", err)
		}
		ids[id.ID] = true
	}
	for _, follower := range []*pairingNode{direct, relay} {
		pkg, err := follower.service.CreatePair(ctx, store.NodeAudit{Actor: "synthetic"})
		if err != nil {
			t.Fatal(err)
		}
		relID, err := master.service.ImportPair(ctx, pkg, store.NodeAudit{Actor: "synthetic"})
		if err != nil {
			t.Fatal(err)
		}
		mrel, err := master.db.Nodes().Relationship(ctx, relID)
		if err != nil || mrel.State != "active" || mrel.Direction != "downstream" {
			t.Fatalf("master relationship not active: %v", err)
		}
		frel, err := follower.db.Nodes().Relationship(ctx, relID)
		if err != nil || frel.State != "active" || frel.Direction != "upstream" {
			t.Fatalf("follower relationship not active: %v", err)
		}
		if mrel.Credential == "" || frel.Credential == "" || mrel.Credential == frel.Credential {
			t.Fatal("relationships lack independently sealed credentials")
		}
	}
}
