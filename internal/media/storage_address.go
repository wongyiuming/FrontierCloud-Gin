package media

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Addresses are administrative observations of durable ownership, never public
// delivery destinations. Offline owners keep their address; unknown bindings do
// not inherit the Master endpoint. No object URL or credential is exposed.
func storageAddress(raw string) *string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil
	}
	scheme := u.Scheme
	u.Scheme = "https"
	address, err := node.Endpoint(u.String())
	if err != nil {
		return nil
	}
	if scheme == "http" {
		address = "http://" + strings.TrimPrefix(address, "https://")
		if u.Port() == "443" {
			address += ":443"
		}
		if u.Port() == "80" {
			address = strings.TrimSuffix(address, ":80")
		}
	}
	return &address
}

func (item TreeItem) MarshalJSON() ([]byte, error) {
	type plain TreeItem
	if item.Kind != "file" {
		return json.Marshal(plain(item))
	}
	return json.Marshal(struct {
		plain
		Address *string `json:"storage_address"`
		Local   bool    `json:"storage_address_local"`
	}{plain(item), item.StorageAddress, item.StorageAddressLocal})
}

func (s *Service) treeStorageAddresses(ctx context.Context, items []TreeItem) error {
	files := false
	for _, item := range items {
		files = files || item.Kind == "file"
	}
	if !files {
		return nil
	}
	identity := store.NodeIdentity{}
	if s.nodes != nil {
		var err error
		identity, err = s.nodes.ReadIdentity(ctx)
		if err != nil {
			return err
		}
	} else if s.identity != nil {
		identity = s.identity.NodeIdentity
	}
	type address struct {
		endpoint *string
		local    bool
	}
	owners := map[string]address{}
	if identity.Role == "Master" && s.pool != nil && s.nodes != nil {
		members, err := s.pool.Members(ctx)
		if err != nil {
			return err
		}
		relations, err := s.nodes.Relationships(ctx, true)
		if err != nil {
			return err
		}
		byID := map[string]store.Relationship{}
		for _, rel := range relations {
			byID[rel.ID] = rel
		}
		for _, member := range members {
			if member.Kind == "MasterLocal" && member.ID == identity.ID && member.Transport == "Local" {
				owners[member.ID] = address{storageAddress(identity.Endpoint), true}
			} else if member.Kind == "Follower" && (member.Transport == "Direct" || member.Transport == "Relay") && member.RelationshipID != nil {
				rel, ok := byID[*member.RelationshipID]
				if ok && rel.PeerID == member.ID && rel.Direction == "downstream" {
					owners[member.ID] = address{endpoint: storageAddress(rel.Endpoint)}
				}
			}
		}
	}
	for i := range items {
		if items[i].Kind != "file" {
			continue
		}
		value := address{}
		if identity.Role != "Master" || strings.HasPrefix(items[i].Path, "lyrics/") {
			value = address{storageAddress(identity.Endpoint), true}
		} else {
			value = owners[items[i].MemberID]
		}
		items[i].StorageAddress, items[i].StorageAddressLocal = value.endpoint, value.local
	}
	return nil
}
