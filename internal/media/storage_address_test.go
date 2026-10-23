package media

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type addressNodes struct {
	store.NodeRepository
	identity store.NodeIdentity
	rows     []store.Relationship
}

func (r addressNodes) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	return r.identity, nil
}
func (r addressNodes) Relationships(context.Context, bool) ([]store.Relationship, error) {
	return r.rows, nil
}

type addressMembers struct {
	store.PoolRepository
	rows []store.StorageMember
}

func (r addressMembers) Members(context.Context) ([]store.StorageMember, error) { return r.rows, nil }

func TestAdminStorageAddressUsesExactOwnerBindingWithoutOnlineFallback(t *testing.T) {
	master, direct, relay := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	d, r, foreign, upstream, unsafe := "direct", "relay", "foreign", "upstream", "unsafe"
	service := &Service{nodes: addressNodes{identity: store.NodeIdentity{ID: master, Role: "Master", Endpoint: "https://MASTER.test:443/"}, rows: []store.Relationship{
		{ID: d, PeerID: direct, Direction: "downstream", Status: "offline", Endpoint: "https://direct.test:8443"},
		{ID: r, PeerID: relay, Direction: "downstream", State: "revoked", Endpoint: "https://relay.test"},
		{ID: foreign, PeerID: "other-node", Direction: "downstream", Endpoint: "https://wrong.test"},
		{ID: upstream, PeerID: "upstream-owner", Direction: "upstream", Endpoint: "https://wrong.test"},
		{ID: unsafe, PeerID: "unsafe-owner", Direction: "downstream", Endpoint: "https://secret:password@node.test/?token=private"},
	}}, pool: addressMembers{rows: []store.StorageMember{
		{ID: master, Kind: "MasterLocal", Transport: "Local"},
		{ID: direct, Kind: "Follower", Transport: "Direct", RelationshipID: &d},
		{ID: relay, Kind: "Follower", Transport: "Relay", RelationshipID: &r},
		{ID: "foreign-owner", Kind: "Follower", Transport: "Direct", RelationshipID: &foreign},
		{ID: "upstream-owner", Kind: "Follower", Transport: "Relay", RelationshipID: &upstream},
		{ID: "unsafe-owner", Kind: "Follower", Transport: "Direct", RelationshipID: &unsafe},
		{ID: "missing", Kind: "Follower", Transport: "Direct"},
		{ID: "not-current-master", Kind: "MasterLocal", Transport: "Local"},
	}}}
	items := []TreeItem{{Kind: "directory", Path: "music/album"}}
	for _, owner := range []string{master, direct, relay, "foreign-owner", "upstream-owner", "unsafe-owner", "missing", "unknown", "not-current-master"} {
		items = append(items, TreeItem{Kind: "file", Path: "music/album/song.mp3", MemberID: owner})
	}
	if err := service.treeStorageAddresses(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"https://master.test", "https://direct.test:8443", "https://relay.test"} {
		item := items[i+1]
		if item.StorageAddress == nil || *item.StorageAddress != want || item.StorageAddressLocal != (i == 0) {
			t.Fatal("wrong owner", item, want)
		}
	}
	for _, item := range items[4:] {
		if item.StorageAddress != nil || item.StorageAddressLocal {
			t.Fatal("unknown owner borrowed an address", item)
		}
	}
	for i, item := range items {
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("invalid tree JSON")
		}
		_, has := value["storage_address"]
		if has != (i != 0) {
			t.Fatal("address field must describe files only", string(raw))
		}
		if i >= 4 && (value["storage_address"] != nil || value["storage_address_local"] != false) {
			t.Fatal("unknown must serialize null/false", string(raw))
		}
	}
}

func TestAdminTreeAndSearchObserveCurrentLocalAddress(t *testing.T) {
	_, _, service := masterFixture(t)
	ctx := context.Background()
	tree, err := service.Tree(ctx, "music/artist")
	if err != nil {
		t.Fatal(err)
	}
	search, err := service.Search(ctx, "song", "music")
	if err != nil {
		t.Fatal(err)
	}
	for _, items := range [][]TreeItem{tree.Items, search.Items} {
		if len(items) == 0 {
			t.Fatal("missing fixture items")
		}
		for _, item := range items {
			if item.Kind == "file" && (item.StorageAddress == nil || *item.StorageAddress != "https://master.test" || !item.StorageAddressLocal || item.MediaID == "") {
				t.Fatal(item)
			}
		}
	}
}

func TestAdminStorageAddressRejectsSecretBearingOrNonRootEndpoints(t *testing.T) {
	for _, raw := range []string{"", "https://user:password@node.test", "https://node.test/?token=x", "https://node.test/#secret", "https://node.test/path", "https://node.test?", "javascript:alert(1)", "https://node.test:65536"} {
		if storageAddress(raw) != nil {
			t.Fatal("unsafe endpoint exposed", raw)
		}
	}
	for raw, want := range map[string]string{"https://NODE.test:443/": "https://node.test", "http://NODE.test:80/": "http://node.test", "http://node.test:443/": "http://node.test:443"} {
		value := storageAddress(raw)
		if value == nil || *value != want {
			t.Fatal(raw, value, want)
		}
	}
}
