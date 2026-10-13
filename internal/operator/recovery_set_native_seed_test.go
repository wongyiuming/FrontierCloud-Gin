package operator

// This opt-in fixture constructor runs only against new private SQLite roots.
// It requires completed native startup, then uses native store promotion/pairing APIs; production fc has no seed path.
import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type recoverySeedNode struct{ Directory, Secrets, Endpoint, Role string }

func TestOperatorRecoverySetNativeSeed(t *testing.T) {
	input := os.Getenv("FRONTIERCLOUD_TEST_RECOVERY_SET_SEED")
	if input == "" {
		t.Skip("requires freshly bootstrapped isolated native Compose fixture")
	}
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	var specs []recoverySeedNode
	if json.Unmarshal(raw, &specs) != nil || len(specs) != 2 || specs[0].Role != "Master" || specs[1].Role != "Follower" {
		t.Fatal("two explicit fresh fixture identities required")
	}
	ctx := context.Background()
	dbs := make([]*sqlite.Store, 2)
	identities := make([]*node.Identity, 2)
	public := make([]string, 2)
	vaults := make([]*vault.Vault, 2)
	for i, spec := range specs {
		if !strings.HasPrefix(filepath.Base(filepath.Dir(spec.Directory)), "fc-ops-set-") || !filepath.IsAbs(spec.Secrets) || !strings.HasSuffix(spec.Endpoint, ".fixture.test") && !strings.HasSuffix(spec.Endpoint, ".fixture.test:8443") {
			t.Fatal("non-fixture seed target refused")
		}
		database := filepath.Join(spec.Directory, "data", "frontiercloud.db")
		if info, err := os.Lstat(database); err != nil || !info.Mode().IsRegular() {
			t.Fatal("fixture seed requires a database from actual native startup")
		}
		db, e := sqlite.Open(database)
		if e != nil {
			t.Fatal(e)
		}
		dbs[i] = db
		defer db.Close()
		identity, e := node.OpenExisting(ctx, db.Nodes(), spec.Secrets)
		if e != nil {
			t.Fatal(e)
		}
		if e = identity.CheckNativeRuntime(ctx, filepath.Join(spec.Directory, "data")); e != nil {
			t.Fatal("native startup receipt required before fixture role setup", e)
		}
		if identity.Role != "Standalone" && !(spec.Role == "Follower" && identity.Role == "Follower" && identity.Endpoint == spec.Endpoint) {
			t.Fatal("fixture seed cannot replace an existing cluster identity")
		}
		relations, err := db.Nodes().Relationships(ctx, true)
		if err != nil || len(relations) != 0 {
			t.Fatal("fixture seed requires no preexisting relationships", err)
		}
		identities[i] = identity
		v, e := vault.OpenExisting(spec.Secrets)
		if e != nil {
			t.Fatal(e)
		}
		vaults[i] = v
		seed, e := v.Unseal(identity.PrivateKey)
		if e != nil {
			t.Fatal(e)
		}
		private, e := protocol.Decode(seed)
		if e != nil {
			t.Fatal(e)
		}
		public[i] = protocol.Encode(ed25519.NewKeyFromSeed(private).Public().(ed25519.PublicKey))
		service, e := media.NewContext(ctx, filepath.Join(spec.Directory, "data", "media"), db.Media(), identity)
		if e != nil {
			t.Fatal(e)
		}
		if identity.Role == "Standalone" {
			e = service.WithPromotion(ctx, spec.Role, func(p store.NodePromotion) error {
				p.Endpoint = spec.Endpoint
				if spec.Role == "Master" {
					p.Allocation = store.GiB
				}
				_, e := db.Nodes().PromoteIdentity(ctx, p, store.NodeAudit{Actor: "isolated-recovery-fixture"})
				return e
			})
		}
		service.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().Unix()
	token := protocol.Encode([]byte(strings.Repeat("r", 48)))
	digest := sha256.Sum256([]byte(token))
	pair := store.PairPackage{Nonce: strings.Repeat("a", 32), TokenHash: hex.EncodeToString(digest[:]), ExpiresAt: now + 300}
	if _, e = dbs[1].Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("b", 32)
	for i := range specs {
		peer := 1 - i
		credential, e := vaults[i].Seal(token)
		if e != nil {
			t.Fatal(e)
		}
		direction := "downstream"
		if i == 1 {
			direction = "upstream"
		}
		relation := store.Relationship{ID: id, PeerID: identities[peer].ID, Endpoint: specs[peer].Endpoint, PublicKey: public[peer], Credential: credential, Direction: direction, Mode: "Relay", State: "pending", PeerVersion: "isolated-recovery-fixture", Protocol: 2, CreatedAt: now}
		if i == 0 {
			e = dbs[i].Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{})
		} else {
			e = dbs[i].Nodes().ConsumePair(ctx, pair, relation, now, store.NodeAudit{})
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = dbs[i].Nodes().ActivateRelationship(ctx, id, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	summary := map[string]any{"master_id": identities[0].ID, "storage_id": identities[1].ID, "relationship_id": id, "seed": "native store APIs after actual fresh native startup; no network pairing assertion"}
	raw, e = json.Marshal(summary)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(filepath.Dir(input), "seed-evidence.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
}

// The verify entrypoint never initializes or repairs restored databases/keys.
func TestOperatorRecoverySetNativeVerify(t *testing.T) {
	input := os.Getenv("FRONTIERCLOUD_TEST_RECOVERY_SET_VERIFY")
	if input == "" {
		t.Skip("requires restored private native set")
	}
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	var spec struct {
		Target  string
		Master  string
		Storage string
	}
	if json.Unmarshal(raw, &spec) != nil || !strings.HasPrefix(filepath.Base(filepath.Dir(spec.Target)), "fc-ops-set-") || !node.ValidIdentifier(spec.Master) || !node.ValidIdentifier(spec.Storage) {
		t.Fatal("isolated restored roster required")
	}
	ctx := context.Background()
	for i, id := range []string{spec.Master, spec.Storage} {
		root := filepath.Join(spec.Target, id)
		db, e := sqlite.OpenReadOnly(ctx, filepath.Join(root, "data", "frontiercloud.db"))
		if e != nil {
			t.Fatal(e)
		}
		identity, e := node.OpenExisting(ctx, db.Nodes(), filepath.Join(root, "runtime_secrets"))
		if e != nil || identity.ID != id {
			db.Close()
			t.Fatal("original native identity did not decrypt", e)
		}
		relations, e := db.Nodes().Relationships(ctx, false)
		if e != nil || len(relations) != 1 || relations[0].State != "active" {
			db.Close()
			t.Fatal("restored relationship differs", e)
		}
		peer := spec.Storage
		direction := "downstream"
		if i == 1 {
			peer = spec.Master
			direction = "upstream"
		}
		if relations[0].PeerID != peer || relations[0].Direction != direction {
			db.Close()
			t.Fatal("restored relationship ownership differs")
		}
		v, e := vault.OpenExisting(filepath.Join(root, "runtime_secrets"))
		if e != nil {
			db.Close()
			t.Fatal(e)
		}
		token, e := v.Unseal(relations[0].Credential)
		db.Close()
		if e != nil || token != protocol.Encode([]byte(strings.Repeat("r", 48))) {
			t.Fatal("sealed pair credential was not recovered")
		}
	}
}
