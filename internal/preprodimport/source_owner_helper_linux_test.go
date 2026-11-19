//go:build linux && owner_publish_fixture && ledger_fixture

package preprodimport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestSignedSourceOwnerFixtureBindsMasterAndProof(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, e := sqlite.Open(filepath.Join(dir, "master.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	secrets := filepath.Join(dir, "secrets")
	if e = os.Mkdir(secrets, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = node.Initialize(ctx, db.Nodes(), secrets); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://target.test", Allocation: store.GiB, PhysicalFree: 5 * store.GiB}, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	v, e := vault.OpenExisting(secrets)
	if e != nil {
		t.Fatal(e)
	}
	owner := strings.Repeat("e", 32)
	fixture := makeSignedSourceForOwnerFixture(t, db, v, owner, strings.Repeat("b", 64), strings.Repeat("d", 64), []byte("fixture bytes"))
	ok, e := recoverSourceEvidence(ctx, fixture.EvidenceDB, fixture.EvidenceRoot, fixture.Receiver, fixture.Pin, fixture.EvidenceRef, func(c context.Context) error { return c.Err() })
	if e != nil || !ok {
		t.Fatal("persisted source evidence", e)
	}
	scope := objectProofScope{TargetOwnerID: owner, TargetBlobID: strings.Repeat("a", 64), TargetReadAlias: strings.Repeat("c", 64), Challenge: strings.Repeat("2", 64)}
	envelope := fixture.objectProof(t, scope)
	if e = verifySSHObjectProof(envelope, fixture.Receiver, fixture.Pin, fixture.Source, fixture.SourceDigest, fixture.Media, scope, time.Now()); e != nil {
		t.Fatal("signed object proof", e)
	}
	wrong := scope
	wrong.TargetOwnerID = strings.Repeat("f", 32)
	if e = verifySSHObjectProof(envelope, fixture.Receiver, fixture.Pin, fixture.Source, fixture.SourceDigest, fixture.Media, wrong, time.Now()); e == nil {
		t.Fatal("wrong owner accepted")
	}
}
