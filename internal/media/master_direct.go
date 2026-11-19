package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterOwnsIngressObject classifies an already authorized object by its
// durable owner. It never picks a transport based on connection failure.
func (s *Service) MasterOwnsIngressObject(ctx context.Context, object store.MediaObject) (bool, error) {
	if _, ok := network.AuthenticatedIngressFromContext(ctx); !ok || s.pool == nil || object.ID == "" {
		return false, ErrUnavailable
	}
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		return false, ErrUnavailable
	}
	row, err := s.pool.Resource(ctx, object.ID)
	if err != nil {
		return false, err
	}
	if row.ID != object.ID || row.Path != object.Path || row.Kind != object.Kind || row.State != "active" {
		return false, store.ErrNodeState
	}
	return row.MemberID == identity.ID && row.RelationshipID == nil && row.Transport != "S3", nil
}

// MasterIngressPolicy reads the administrator's applied policy under the
// caller's already-held public admission; it does not infer a transport.
func (s *Service) MasterIngressPolicy(ctx context.Context) (store.NativeTransportPolicy, error) {
	if _, ok := network.AuthenticatedIngressFromContext(ctx); !ok || !network.HasActivePublicAdmission(ctx) {
		return store.NativeTransportPolicy{}, ErrUnavailable
	}
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		return store.NativeTransportPolicy{}, ErrUnavailable
	}
	if s.control == nil {
		return store.NativeTransportPolicy{}, ErrUnavailable
	}
	return s.control.MasterNativePolicy(ctx)
}

// masterDirectOpen is called with the shared media mutation fence held. It
// rechecks visibility, ownership, the on-disk object and encryption metadata.
func (s *Service) masterDirectOpen(ctx context.Context, resourceID, objectID string) (store.GlobalMedia, *Stream, error) {
	var empty store.GlobalMedia
	if err := s.ready(); err != nil {
		return empty, nil, err
	}
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" || s.pool == nil {
		return empty, nil, ErrUnavailable
	}
	row, err := s.pool.Resource(ctx, resourceID)
	if err != nil {
		return empty, nil, err
	}
	if row.ID != resourceID || row.MemberID != identity.ID || row.ObjectID != objectID || row.RelationshipID != nil || row.State != "active" || row.Transport == "S3" {
		return empty, nil, os.ErrNotExist
	}
	checked, err := s.ValidateTrack(row.Path)
	if err != nil || checked.Path != row.Path || checked.Kind != row.Kind {
		return empty, nil, ErrPath
	}
	hiddenPaths, err := s.hiddenPaths(ctx, false)
	if err != nil {
		return empty, nil, err
	}
	if hidden(row.Path, hiddenPaths) {
		return empty, nil, os.ErrNotExist
	}
	object, err := s.repository.ObjectByID(ctx, objectID)
	if err != nil {
		return empty, nil, err
	}
	if object == nil || object.ID != objectID || object.Path != row.Path || object.Kind != row.Kind {
		return empty, nil, os.ErrNotExist
	}
	meta, err := s.Encryption(ctx, resourceID)
	if err != nil {
		return empty, nil, err
	}
	if !reflect.DeepEqual(meta, object.Encryption) {
		return empty, nil, store.ErrNodeState
	}
	before, err := s.safeInfo(row.Path)
	if err != nil || !before.Mode().IsRegular() || before.Size() != row.Bytes {
		return empty, nil, store.ErrNodeState
	}
	f, err := s.root.Open(row.Path)
	if err != nil {
		return empty, nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		f.Close()
		return empty, nil, store.ErrNodeState
	}
	return row, &Stream{File: f, Info: after, Path: row.Path, ResourceID: row.ID, OwnerID: row.MemberID, ObjectID: row.ObjectID, Encryption: meta}, nil
}

func masterDirectRevision(row store.GlobalMedia, stream *Stream) string {
	raw, _ := json.Marshal([]string{row.ID, row.MemberID, row.ObjectID, row.Path, row.Kind, row.ETag, strconv.FormatInt(row.Bytes, 10), strconv.FormatInt(row.UpdatedAt, 10), strconv.FormatInt(stream.Info.ModTime().UnixNano(), 10)})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// MasterDirectSource obtains a header-only grant for an already authorized
// object while the peer verifier holds its ingress admission lease. Only an
// explicitly configured resource origin is accepted; the control endpoint is
// never used as a fallback. It does not modify resource policy or placement.
func (s *Service) MasterDirectSource(ctx context.Context, expected store.MediaObject, resourceOrigin string) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	if s.control == nil || expected.ID == "" || expected.Path == "" || node.ValidateMasterResourceOrigin(resourceOrigin) != nil {
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
	capability, err := s.control.IssueMasterDirectCapability(ctx, resourceOrigin, row.ID, row.ObjectID, masterDirectRevision(row, stream), descriptor)
	if err != nil {
		return "", "", err
	}
	return resourceOrigin + "/api/v1/media/master-direct/" + row.ID, capability, nil
}

// OpenMasterDirect verifies the signed grant, then reopens the same current
// visible object under the mutation fence. Once opened, the caller streams
// the existing descriptor with normal bounded HTTP Range semantics.
func (s *Service) OpenMasterDirect(ctx context.Context, token, resourceOrigin, resourceID string) (*Stream, node.MasterDirectClaim, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	if s.control == nil {
		return nil, node.MasterDirectClaim{}, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterDirectCapability(ctx, token, resourceOrigin, resourceID)
	if err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	defer release()
	row, stream, err := s.masterDirectOpen(ctx, resourceID, claim.ObjectID)
	if err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil || descriptor != claim.Descriptor || masterDirectRevision(row, stream) != claim.Revision {
		stream.File.Close()
		if err != nil {
			return nil, node.MasterDirectClaim{}, err
		}
		return nil, node.MasterDirectClaim{}, errors.New("authorized media revision changed")
	}
	return stream, claim, nil
}
