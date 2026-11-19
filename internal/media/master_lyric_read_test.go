package media

import (
	"bytes"
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

func TestMasterLyricDirectRequiresCurrentVisibleRelation(t *testing.T) {
	_, db, service := masterFixture(t)
	ctx := context.Background()
	name, ciphertext := publishCryptoLyric(t, service, "direct-lyric.lrc")
	if _, err := service.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{name}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	identity, err := service.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
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
	object, err := service.CryptoObject(admitted, name, "", false)
	if err != nil {
		t.Fatal(err)
	}
	associated, err := service.EncryptedLyric(admitted, "music/artist/song.mp3", "")
	if err != nil || associated.ID != object.ID {
		t.Fatal("current ingress could not authorize the lyric relation", associated, err)
	}
	source, token, err := service.MasterLyricDirectSource(admitted, object, "https://resource.test")
	if err != nil || source != "https://resource.test/api/v1/media/master-direct-lyric/"+object.ID || token == "" {
		t.Fatal(source, err)
	}
	stream, claim, err := service.OpenMasterLyricDirect(ctx, token, "https://resource.test", object.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream.File)
	stream.File.Close()
	if err != nil || !bytes.Equal(data, ciphertext) || claim.ResourceID != object.ID {
		t.Fatal("lyric changed", err)
	}
	if _, _, err := service.OpenMasterLyricDirect(ctx, token, "https://other.test", object.ID); err == nil {
		t.Fatal("other origin accepted")
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Relay", "Relay"
	if err := control.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	relaySource, relayToken, err := service.MasterLyricRelaySource(admitted, object)
	if err != nil || relaySource != ingress.PublicOrigin+"/api/v1/media/master-relay/"+object.ID {
		t.Fatal("relay source", relaySource, err)
	}
	if _, _, err := service.OpenMasterLyricRelay(ctx, relayToken, object.ID); err == nil {
		t.Fatal("anonymous relay accepted")
	}
	if _, _, err := service.OpenMasterLyricDirect(ctx, relayToken, "https://resource.test", object.ID); err == nil {
		t.Fatal("relay grant accepted as direct")
	}
	stream, _, err = service.OpenMasterLyricRelay(verified, relayToken, object.ID)
	if err != nil {
		t.Fatal("authenticated relay read", err)
	}
	data, err = io.ReadAll(stream.File)
	stream.File.Close()
	if err != nil || !bytes.Equal(data, ciphertext) {
		t.Fatal("relay lyric changed", err)
	}
	if err := service.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.OpenMasterLyricDirect(ctx, token, "https://resource.test", object.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hidden relation remained readable", err)
	}
	if _, _, err := service.OpenMasterLyricRelay(verified, relayToken, object.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hidden relation remained relay-readable", err)
	}
	if err := service.Hide(ctx, []string{"music/artist"}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE cluster_storage_members SET health='offline' WHERE member_id=?", identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.OpenMasterLyricDirect(ctx, token, "https://resource.test", object.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable associated track authorized lyric", err)
	}
}
