package media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// UploadDestination contains display observations, never credentials or an
// upload URL. Reservations re-read the selected member inside their transaction.
type UploadDestination struct {
	MemberID  string  `json:"member_id"`
	Kind      string  `json:"member_kind"`
	Site      string  `json:"site_type"`
	Transport string  `json:"transport"`
	Address   *string `json:"address"`
	Bucket    string  `json:"bucket,omitempty"`
	Writable  bool    `json:"writable"`
}

func (s *Service) uploadDestinations(ctx context.Context, members []store.StorageMember, ready func(context.Context, string) error) ([]UploadDestination, error) {
	identity, err := s.IdentityState(ctx)
	if err != nil {
		return nil, err
	}
	relations := map[string]store.Relationship{}
	if s.nodes != nil {
		rows, err := s.nodes.Relationships(ctx, false)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			relations[row.ID] = row
		}
	}
	buckets := map[string]store.S3Member{}
	if s.s3 != nil {
		rows, err := s.s3.Members(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			buckets[row.ID] = row
		}
	}
	result := []UploadDestination{}
	now := time.Now().Unix()
	for _, member := range members {
		d := UploadDestination{MemberID: member.ID, Kind: member.Kind, Transport: member.Transport,
			Writable: member.Enabled != 0 && member.Writable != 0 && member.Health == "online" && !member.Draining && member.Available > 0}
		switch {
		case member.Kind == "MasterLocal" && member.ID == identity.ID && member.Transport == "Local":
			d.Site, d.Address = "primary", storageAddress(identity.Endpoint)
		case member.Kind == "Follower" && member.RelationshipID != nil && (member.Transport == "Direct" || member.Transport == "Relay"):
			relation, ok := relations[*member.RelationshipID]
			if !ok || relation.PeerID != member.ID || relation.Direction != "downstream" || relation.State != "active" {
				continue
			}
			d.Site = "direct"
			if member.Transport == "Relay" {
				d.Site = "relay"
			}
			d.Address = storageAddress(relation.Endpoint)
			d.Writable = d.Writable && relation.Status == "online" && relation.LastHeartbeat > 0 && now >= relation.LastHeartbeat && now-relation.LastHeartbeat < 120
			if ready == nil {
				d.Writable = d.Writable && s.control.CheckLegacySelectedUploadRelationship(ctx, member) == nil
			}
		case member.Kind == "S3" && member.Transport == "S3":
			bucket, ok := buckets[member.ID]
			if !ok {
				continue
			}
			d.Site, d.Address, d.Bucket = "s3", storageAddress(bucket.Location.Endpoint), bucket.Location.Bucket
			d.Writable = d.Writable && !bucket.CleanupOnly && bucket.ProbeRevision == bucket.Revision && bucket.ProbeState == "ready" && bucket.SealedCredentials != "" && (bucket.CredentialExpiresAt == 0 || bucket.CredentialExpiresAt > now)
		default:
			continue
		}
		d.Writable = d.Writable && d.Address != nil
		if d.Writable && ready != nil {
			d.Writable = ready(ctx, member.ID) == nil
		} else if d.Writable && member.Kind != "S3" {
			observer, ok := s.pool.(interface {
				LegacySelectedUploadReady(context.Context, string) error
			})
			d.Writable = ok && observer.LegacySelectedUploadReady(ctx, member.ID) == nil
		}
		result = append(result, d)
	}
	return result, nil
}
