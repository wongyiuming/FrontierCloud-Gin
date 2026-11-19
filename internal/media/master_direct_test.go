package media

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type masterDirectRouting struct {
	store.NodeRepository
	store.PublicRoutingRepository
	current store.PublicIngress
	policy  store.NativeTransportPolicy
}

type masterPolicyTestLease struct{}

func (masterPolicyTestLease) Commit() error { return nil }
func (masterPolicyTestLease) Release()      {}
func (r *masterDirectRouting) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return r.current, masterPolicyTestLease{}, nil
}

func prepareMasterPolicyTest(t *testing.T, control *node.Service) {
	t.Helper()
	if err := control.ConfigureMasterResourceReadiness("https://resource.test", func(context.Context, store.PublicIngress, string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := control.PrepareMasterResourcePolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (r *masterDirectRouting) PublicIngress(context.Context) (store.PublicIngress, error) {
	return r.current, nil
}
func (r *masterDirectRouting) NativeTransport(context.Context, string) (store.NativeTransportPolicy, error) {
	return r.policy, nil
}

func TestMasterDirectSourceRetainsIdentityAndRechecksVisibility(t *testing.T) {
	_, db, service := masterFixture(t)
	ctx := context.Background()
	identity, err := service.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Resources(ctx, "music/artist/song.mp3", true)
	if err != nil || len(rows) != 1 {
		t.Fatal("global source", rows, err)
	}
	row := rows[0]
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectRouting{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), current: ingress,
		policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 2}}
	control := node.NewService(routing, service.identity, nil)
	prepareMasterPolicyTest(t, control)
	service.ConfigureCluster(routing, db.Pool(), control)
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	manager, err := mediacrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("c", 64)
	session, err := manager.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	admitted, err = manager.WithDirectSession(admitted, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := service.CryptoObject(admitted, row.Path, row.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.MasterDirectSource(admitted, object, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing resource origin accepted", err)
	}
	source, token, err := service.MasterDirectSource(admitted, object, "https://resource.test")
	if err != nil || source != "https://resource.test/api/v1/media/master-direct/"+row.ID || strings.Contains(source, "?") || token == "" {
		t.Fatal("direct source", source, err)
	}
	stream, claim, err := service.OpenMasterDirect(ctx, token, "https://resource.test", row.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream.File)
	stream.File.Close()
	if err != nil || string(data) != "ID3payload" || claim.ResourceID != row.ID || stream.ObjectID != row.ObjectID || stream.OwnerID != row.MemberID {
		t.Fatal("direct object mismatch", string(data), claim, err)
	}
	// Simulate a durable tree marker after a real legacy capability has been
	// minted. It must no longer reopen the plaintext legacy path. The marker is
	// removed only in this isolated test so the remaining legacy cases can run.
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.OpenMasterDirect(ctx, token, "https://resource.test", row.ID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("pre-tree direct bearer reopened", err)
	}
	if _, err = db.Database().ExecContext(ctx, `DELETE FROM sealed_tree_meta WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.OpenMasterDirect(ctx, token, "https://other.test", row.ID); err == nil {
		t.Fatal("wrong resource origin accepted")
	}
	// An explicit policy/entry change cannot mint a stale grant, while the
	// already issued one drains until its original deadline.
	routing.current.Generation++
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if _, _, err = service.MasterDirectSource(admitted, object, "https://resource.test"); err == nil {
		t.Fatal("stale context minted a grant")
	}
	stream, _, err = service.OpenMasterDirect(ctx, token, "https://resource.test", row.ID)
	if err != nil {
		t.Fatal("existing grant did not drain", err)
	}
	stream.File.Close()
	if err = service.Hide(ctx, []string{row.Path}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.OpenMasterDirect(ctx, token, "https://resource.test", row.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hidden object remained readable", err)
	}
}
