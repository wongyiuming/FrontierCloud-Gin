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
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This marker is private to the verified lyric read below. It permits the
// visibility check to inspect related tracks without claiming a new ingress
// admission or authorizing their bytes.
type verifiedLyricReadKey struct{}

func hasVerifiedLyricRead(ctx context.Context) bool {
	value, _ := ctx.Value(verifiedLyricReadKey{}).(bool)
	return value
}

// masterLyricOpen requires the media mutation fence. Lyric identity is local
// to Master and is distinct from the global identity of any associated song.
func (s *Service) masterLyricOpen(ctx context.Context, objectID string) (*Stream, string, error) {
	identity, err := s.IdentityState(ctx)
	if err != nil || identity.Role != "Master" {
		return nil, "", ErrUnavailable
	}
	object, err := s.repository.ObjectByID(ctx, objectID)
	if err != nil || object == nil || object.ID != objectID || object.Kind != "lyric" || !strings.HasPrefix(object.Path, "lyrics/") {
		return nil, "", os.ErrNotExist
	}
	checked, err := s.cryptoObject(ctx, object.Path, "", false)
	if err != nil {
		return nil, "", err
	}
	if checked.ID != object.ID || checked.Kind != object.Kind || checked.Path != object.Path || !reflect.DeepEqual(checked.Encryption, object.Encryption) {
		return nil, "", store.ErrNodeState
	}
	before, err := s.safeInfo(object.Path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, "", os.ErrNotExist
	}
	f, err := s.root.Open(object.Path)
	if err != nil {
		return nil, "", err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		f.Close()
		return nil, "", store.ErrNodeState
	}
	raw, err := json.Marshal([]string{identity.ID, object.ID, object.Path, object.Kind, strconv.FormatInt(after.Size(), 10), strconv.FormatInt(after.ModTime().UnixNano(), 10)})
	if err != nil {
		f.Close()
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return &Stream{File: f, Info: after, Path: object.Path, ResourceID: object.ID, OwnerID: identity.ID, ObjectID: object.ID, Encryption: checked.Encryption}, hex.EncodeToString(sum[:]), nil
}

// MasterLyricDirectSource issues a header-only read grant after the existing
// lyric visibility and relation checks and an authenticated ingress admission.
func (s *Service) MasterLyricDirectSource(ctx context.Context, expected store.MediaObject, resourceOrigin string) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	_, verified := network.AuthenticatedIngressFromContext(ctx)
	if !verified || !network.HasActivePublicAdmission(ctx) || s.control == nil || expected.Kind != "lyric" || node.ValidateMasterResourceOrigin(resourceOrigin) != nil {
		return "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	stream, revision, err := s.masterLyricOpen(ctx, expected.ID)
	if err != nil {
		return "", "", err
	}
	defer stream.File.Close()
	if stream.Path != expected.Path || !reflect.DeepEqual(stream.Encryption, expected.Encryption) {
		return "", "", store.ErrNodeState
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil {
		return "", "", err
	}
	token, err := s.control.IssueMasterDirectCapability(ctx, resourceOrigin, expected.ID, expected.ID, revision, descriptor)
	if err != nil {
		return "", "", err
	}
	return resourceOrigin + "/api/v1/media/master-direct-lyric/" + expected.ID, token, nil
}

// OpenMasterLyricDirect accepts only an existing signed lyric grant, then
// rechecks its current relation, visibility, descriptor and file revision.
func (s *Service) OpenMasterLyricDirect(ctx context.Context, token, resourceOrigin, resourceID string) (*Stream, node.MasterDirectClaim, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	if s.control == nil {
		return nil, node.MasterDirectClaim{}, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterDirectCapability(ctx, token, resourceOrigin, resourceID)
	if err != nil || claim.ObjectID != resourceID {
		return nil, node.MasterDirectClaim{}, node.ErrCapability
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	stream, revision, err := s.masterLyricOpen(ctx, resourceID)
	if err != nil {
		return nil, node.MasterDirectClaim{}, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil || descriptor != claim.Descriptor || revision != claim.Revision {
		stream.File.Close()
		return nil, node.MasterDirectClaim{}, errors.New("authorized lyric revision changed")
	}
	return stream, claim, nil
}

// MasterLyricRelaySource uses the same Master-owned lyric and relation checks,
// but issues only the distinct ingress-bound Relay capability.
func (s *Service) MasterLyricRelaySource(ctx context.Context, expected store.MediaObject) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	assertion, verified := network.AuthenticatedIngressFromContext(ctx)
	if !verified || !network.HasActivePublicAdmission(ctx) || s.control == nil || expected.Kind != "lyric" {
		return "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	stream, revision, err := s.masterLyricOpen(ctx, expected.ID)
	if err != nil {
		return "", "", err
	}
	defer stream.File.Close()
	if stream.Path != expected.Path || !reflect.DeepEqual(stream.Encryption, expected.Encryption) {
		return "", "", store.ErrNodeState
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil {
		return "", "", err
	}
	token, err := s.control.IssueMasterRelayCapability(ctx, expected.ID, expected.ID, revision, descriptor)
	if err != nil {
		return "", "", err
	}
	return assertion.PublicOrigin + "/api/v1/media/master-relay/" + expected.ID, token, nil
}

func (s *Service) OpenMasterLyricRelay(ctx context.Context, token, resourceID string) (*Stream, node.MasterRelayClaim, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	if s.control == nil {
		return nil, node.MasterRelayClaim{}, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterRelayCapability(ctx, token, resourceID)
	if err != nil || claim.ObjectID != resourceID {
		return nil, node.MasterRelayClaim{}, node.ErrCapability
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	defer release()
	ctx = context.WithValue(ctx, verifiedLyricReadKey{}, true)
	stream, revision, err := s.masterLyricOpen(ctx, resourceID)
	if err != nil {
		return nil, node.MasterRelayClaim{}, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
	if err != nil || descriptor != claim.Descriptor || revision != claim.Revision {
		stream.File.Close()
		return nil, node.MasterRelayClaim{}, errors.New("authorized lyric revision changed")
	}
	return stream, claim, nil
}
