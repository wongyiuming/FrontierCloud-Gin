package media

import (
	"context"
	"errors"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterRelaySource authorizes only a Master-owned encrypted object and uses
// the already selected ingress as a fixed target. It never chooses a fallback
// transport or accepts a browser-supplied destination.
func (s *Service) MasterRelaySource(ctx context.Context, expected store.MediaObject) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || s.control == nil || s.pool == nil || expected.ID == "" || expected.Path == "" {
		return "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil {
		return "", "", err
	}
	if object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || !reflect.DeepEqual(object.Encryption, expected.Encryption) {
		return "", "", store.ErrNodeState
	}
	row, err := s.pool.Resource(ctx, object.ID)
	if err != nil {
		return "", "", err
	}
	if row.MemberID == assertion.NodeID {
		return "", "", ErrUnavailable
	}
	row, stream, err := s.masterDirectOpen(ctx, row.ID, row.ObjectID)
	if err != nil {
		return "", "", err
	}
	defer stream.File.Close()
	if !reflect.DeepEqual(stream.Encryption, expected.Encryption) {
		return "", "", store.ErrNodeState
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil {
		return "", "", err
	}
	capability, err := s.control.IssueMasterRelayCapability(ctx, row.ID, row.ObjectID, masterDirectRevision(row, stream), descriptor)
	if err != nil {
		return "", "", err
	}
	return assertion.PublicOrigin + "/api/v1/media/master-relay/" + row.ID, capability, nil
}

// OpenMasterRelay revalidates the same object and descriptor for each new
// authenticated read; the caller owns and streams the returned descriptor.
func (s *Service) OpenMasterRelay(ctx context.Context, token, resourceID string) (*Stream, node.MasterRelayClaim, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	if s.control == nil {
		return nil, node.MasterRelayClaim{}, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterRelayCapability(ctx, token, resourceID)
	if err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	defer release()
	row, stream, err := s.masterDirectOpen(ctx, resourceID, claim.ObjectID)
	if err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil || descriptor != claim.Descriptor || masterDirectRevision(row, stream) != claim.Revision {
		stream.File.Close()
		if err != nil {
			return nil, node.MasterRelayClaim{}, err
		}
		return nil, node.MasterRelayClaim{}, errors.New("authorized media revision changed")
	}
	return stream, claim, nil
}
