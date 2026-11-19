package migrationdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const opaqueMediaResource = "opaque-media"

// OpaqueMediaBinding identifies one immutable ciphertext transfer between
// paired storage owners. The catalog identities and keys stay with Master.
type OpaqueMediaBinding struct {
	TaskID string                      `json:"task_id"`
	Source protocol.OpaqueOwnerBinding `json:"source"`
	Target protocol.OpaqueOwnerBinding `json:"target"`
}

type OpaqueMediaProgress struct {
	Offset    int64  `json:"offset"`
	PrefixSHA string `json:"prefix_sha256"`
	State     string `json:"state"`
}

// OpaqueMediaTransfer owns a private checkpoint. The target's opaque storage
// service is responsible for publication and the Master for ownership changes.
type OpaqueMediaTransfer struct {
	receiver *Receiver
	spec     Spec
}

// OpenOpaqueMediaTransfer binds an authenticated local target and a durable
// admission check to the checkpoint. The caller must hold the service lease
// that excludes conflicting activation, and authenticate the binding itself.
func OpenOpaqueMediaTransfer(root *os.Root, targetID string, b OpaqueMediaBinding, guard func(context.Context) error) (*OpaqueMediaTransfer, error) {
	source, target := b.Source, b.Target
	if root == nil || guard == nil || !source.Valid() || !target.Valid() ||
		source.MasterID != target.MasterID || source.RelationshipID == target.RelationshipID ||
		source.Alias == target.Alias || source.Blob == target.Blob ||
		source.Size != target.Size || source.Digest != target.Digest || source.Descriptor != target.Descriptor {
		return nil, ErrState
	}
	if source.Size > 0 {
		plainDescriptor, err := protocol.IngressMediaDescriptor(source.Size, nil)
		if err != nil || source.Descriptor == plainDescriptor {
			return nil, ErrState
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	version := sha256.Sum256(append([]byte("frontiercloud/opaque-media-migration/v1\x00"), raw...))
	spec := Spec{
		TaskID: b.TaskID, MasterID: source.MasterID, SourceID: source.OwnerID,
		TargetID: target.OwnerID, LogicalID: source.Alias, ObjectID: target.Blob,
		Resource: opaqueMediaResource, SourceVersion: hex.EncodeToString(version[:]),
		Bytes: source.Size, SHA256: source.Digest,
	}
	receiver := &Receiver{root: root, node: targetID, resource: opaqueMediaResource, guard: guard}
	if !receiver.valid(spec) {
		return nil, ErrState
	}
	return &OpaqueMediaTransfer{receiver: receiver, spec: spec}, nil
}

func validOpaqueMediaSpec(s Spec) bool {
	return digest.MatchString(s.LogicalID) && digest.MatchString(s.ObjectID) &&
		s.TargetPath == "" && s.Encryption == nil && s.Recording == nil
}

func opaqueMediaProgress(c Checkpoint, err error) (OpaqueMediaProgress, error) {
	return OpaqueMediaProgress{Offset: c.Offset, PrefixSHA: c.PrefixSHA, State: c.State}, err
}

func (t *OpaqueMediaTransfer) Begin(ctx context.Context) (OpaqueMediaProgress, error) {
	return opaqueMediaProgress(t.receiver.Begin(ctx, t.spec))
}

func (t *OpaqueMediaTransfer) Status(ctx context.Context) (OpaqueMediaProgress, error) {
	if err := t.receiver.check(ctx); err != nil {
		return OpaqueMediaProgress{}, err
	}
	return opaqueMediaProgress(t.receiver.Status(ctx, t.spec))
}

func (t *OpaqueMediaTransfer) Append(ctx context.Context, offset int64, data []byte, chunkSHA string) (OpaqueMediaProgress, error) {
	return opaqueMediaProgress(t.receiver.AppendAdmitted(ctx, t.spec, offset, data, chunkSHA, func() error { return t.receiver.check(ctx) }))
}

func (t *OpaqueMediaTransfer) Verify(ctx context.Context) (OpaqueMediaProgress, error) {
	return opaqueMediaProgress(t.receiver.Verify(ctx, t.spec, func() error { return t.receiver.check(ctx) }))
}

// Publish runs the target installation while the private stage lease and its
// verified file are held. The callback receives the file's pre-hash stat and
// must durably install that inode and complete the target's local journal.
// The caller holds the service lease and supplies a current admission check.
func (t *OpaqueMediaTransfer) Publish(ctx context.Context, admission func() error, install func(string, *os.File, os.FileInfo) error) (OpaqueMediaProgress, error) {
	return opaqueMediaProgress(t.receiver.publish(ctx, t.spec, admission, install))
}

func (t *OpaqueMediaTransfer) Abort(ctx context.Context, confirmUnpublished func() error) (OpaqueMediaProgress, error) {
	return opaqueMediaProgress(t.receiver.Abort(ctx, t.spec, confirmUnpublished))
}
