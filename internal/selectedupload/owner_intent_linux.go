//go:build linux

package selectedupload

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// persistOwnerIntent runs under the policy and operation leases. The caller
// must already have verified the capability against the real relationship and
// applied policy. The immutable encrypted record survives process death; a
// later authenticated retry may use a new session and expiry, but may not
// change the durable operation, scope, descriptor, or bytes.
func persistOwnerIntent(ctx context.Context, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload, requireExisting, cleanup bool) error {
	if ctx == nil || ctx.Err() != nil || root == nil || v == nil || !validOperationID(claim.OperationID) {
		return errOperationLease
	}
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: claim.Master, OwnerID: claim.Owner, RelationshipID: claim.Relationship, RelationshipBinding: claim.RelationshipBinding, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.PublishChallenge, Bytes: claim.Size, State: "published"}
	if _, err := receipt.Payload(); err != nil || !validOperationID(claim.CleanupChallenge) || claim.CleanupChallenge == claim.PublishChallenge || claim.CleanupChallenge == claim.OperationID || claim.CleanupChallenge == claim.ObjectID || claim.CleanupChallenge == claim.StageID {
		return errOperationLease
	}
	recording := claim.IsRecordingOperation()
	claim.ExpiresAt, claim.AdminBinding, claim.Operation, claim.AdminOrigin = 0, "", "", ""
	if recording {
		// Each request has already passed current ingress and Direct policy
		// admission. Reissuing on the same pair must retain the same durable
		// scope across ingress switches or a new Direct revision/origin.
		claim.Operation = "recording-v1"
		claim.RecordingIngressNode, claim.RecordingIngressGeneration = "", 0
		claim.Revision, claim.ResourceOrigin = 0, ""
	}
	raw, err := json.Marshal(claim)
	if err != nil || len(raw) > 8192 {
		return errOperationLease
	}
	defer clear(raw)
	const dir = ".selected-upload-intents"
	if root.MkdirAll(dir, 0700) != nil || syncOperationDir(root, ".") != nil {
		return errOperationLease
	}
	info, err := root.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errOperationLease
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errOperationLease
	}
	name := path.Join(dir, claim.OperationID+".intent")
	tombstone := path.Join(dir, claim.OperationID+".cancelled")
	if !cleanup {
		if _, e := root.Lstat(tombstone); e == nil || !os.IsNotExist(e) {
			return errOperationLease
		}
	}
	match := func() bool {
		entry, err := root.Lstat(name)
		if err != nil || !entry.Mode().IsRegular() {
			return false
		}
		f, err := root.Open(name)
		if err != nil {
			return false
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(entry, info) || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 16384 {
			return false
		}
		data, err := io.ReadAll(io.LimitReader(f, 16385))
		if err != nil {
			return false
		}
		opened, err := v.Unseal(string(data))
		return err == nil && bytes.Equal([]byte(opened), raw)
	}
	if _, err = root.Lstat(name); err == nil {
		if !match() {
			return errOperationLease
		}
		return ctx.Err()
	} else if !os.IsNotExist(err) {
		return errOperationLease
	}
	if requireExisting {
		return errOperationLease
	}
	sealed, err := v.Seal(string(raw))
	if err != nil || len(sealed) < 1 || len(sealed) > 16384 {
		return errOperationLease
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return errOperationLease
	}
	temp := path.Join(dir, ".tmp-"+hex.EncodeToString(random[:]))
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errOperationLease
	}
	defer root.Remove(temp)
	n, writeErr := f.WriteString(sealed)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || n != len(sealed) || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		return errOperationLease
	}
	if err = root.Link(temp, name); err != nil && !match() {
		return errOperationLease
	}
	if syncOperationDir(root, dir) != nil || !match() || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}

// markOwnerCancelled must run under the same operation lease as upload and
// recovery, after matching a verified cleanup capability to the durable
// intent. Its hard link is a permanent encrypted tombstone; no subsequent
// upload may proceed, even if cleanup is interrupted or the process dies.
func markOwnerCancelled(ctx context.Context, root *os.Root, v *vault.Vault, claim protocol.SelectedStorageUpload) error {
	const dir = ".selected-upload-intents"
	name := path.Join(dir, claim.OperationID+".intent")
	_, err := root.Lstat(name)
	if os.IsNotExist(err) {
		// A cleanup may arrive before the first byte. Under the same operation
		// lock, create a tombstone only if no unaccounted stage or blob exists.
		// Unknown existing objects are never adopted or deleted.
		blob, e := sealedtree.BlobPath(claim.ObjectID)
		if e != nil {
			return errOperationLease
		}
		for _, item := range []string{path.Join("staging", claim.OperationID+".part"), blob} {
			if _, e = root.Lstat(item); !os.IsNotExist(e) {
				return errOperationLease
			}
		}
		if err = persistOwnerIntent(ctx, root, v, claim, false, true); err != nil {
			return err
		}
	} else if err != nil {
		return errOperationLease
	} else if err = persistOwnerIntent(ctx, root, v, claim, true, true); err != nil {
		return err
	}
	tombstone := path.Join(dir, claim.OperationID+".cancelled")
	if err := root.Link(name, tombstone); err != nil {
		if !os.IsExist(err) {
			return errOperationLease
		}
		a, e1 := root.Lstat(name)
		b, e2 := root.Lstat(tombstone)
		if e1 != nil || e2 != nil || !a.Mode().IsRegular() || !b.Mode().IsRegular() || !os.SameFile(a, b) {
			return errOperationLease
		}
	}
	if syncOperationDir(root, dir) != nil || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}
