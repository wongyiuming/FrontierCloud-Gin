//go:build linux

package node

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

// ImportLegacyOwnerOffline executes a Master-signed plan on the actual stopped
// SQLite Owner. It retains the old file, persists an encrypted immutable intent
// and returns a signed receipt only after the new opaque file is verified. It
// does not grant Master placement or complete Owner reconciliation.
func ImportLegacyOwnerOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath, secretsDir string, db *sql.DB, plan protocol.LegacyOwnerImportPlan, signature string) (Envelope, error) {
	var result Envelope
	if ctx == nil || gate == nil || db == nil || dataRoot == "" || databasePath == "" || secretsDir == "" || signature == "" {
		return result, ErrCapability
	}
	payload, err := plan.Payload()
	if err != nil || len(plan.SourcePath) > 1024 {
		return result, ErrCapability
	}
	repo := business.New(db, "sqlite")
	var identity *Identity
	var service *Service
	var fence *ownerfence.Fence
	var lease *ownerfence.Lease
	var root *os.Root
	var binding string
	checkScope := func(held context.Context, check func() error) error {
		if check() != nil || held.Err() != nil || plan.ExpiresAt <= time.Now().Unix() || plan.ExpiresAt > time.Now().Unix()+3600 {
			return ErrCapability
		}
		var mainPath string
		if db.QueryRowContext(held, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&mainPath) != nil {
			return ErrCapability
		}
		a, e1 := filepath.Abs(mainPath)
		b, e2 := filepath.Abs(databasePath)
		if e1 != nil || e2 != nil || filepath.Clean(a) != filepath.Clean(b) {
			return ErrCapability
		}
		first, e1 := os.Stat(a)
		second, e2 := os.Lstat(b)
		if e1 != nil || e2 != nil || !second.Mode().IsRegular() || second.Mode()&os.ModeSymlink != 0 || !os.SameFile(first, second) {
			return ErrCapability
		}
		if lease == nil || lease.Check(held) != nil {
			return ErrCapability
		}
		currentBinding, e := lease.Binding(held)
		if e != nil || !hmac.Equal([]byte(binding), []byte(currentBinding)) || !hmac.Equal([]byte(plan.FenceBinding), []byte(binding)) {
			return ErrCapability
		}
		scope, e := service.LegacyReadScope(held, plan.RelationshipID)
		if e != nil || scope.MasterID != plan.MasterID || scope.OwnerID != plan.OwnerID || scope.RelationshipBinding != plan.RelationshipBinding || scope.OwnerBinding != plan.OwnerBinding {
			return ErrCapability
		}
		relation, e := repo.Relationship(held, plan.RelationshipID)
		if e != nil || protocol.Verify(relation.PublicKey, payload, signature) != nil {
			return ErrCapability
		}
		var oldPath, oldKind, oldLocator string
		if db.QueryRowContext(held, `SELECT media_path,object_kind,path_locator FROM media_objects WHERE media_id=?`, plan.SourceID).Scan(&oldPath, &oldKind, &oldLocator) != nil {
			return ErrCapability
		}
		oldPathSum := sha256.Sum256([]byte(oldPath))
		if oldPath != plan.SourcePath || oldLocator != hex.EncodeToString(oldPathSum[:]) || oldKind != "audio" && oldKind != "video" || oldKind == "audio" && !strings.HasPrefix(oldPath, "music/") || oldKind == "video" && !strings.HasPrefix(oldPath, "vido/") {
			return ErrCapability
		}
		mediaPath := filepath.Join(dataRoot, "media")
		info, e := os.Lstat(mediaPath)
		opened, e2 := root.Stat(".")
		if e != nil || e2 != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) {
			return ErrCapability
		}
		return held.Err()
	}
	authorize := func(held context.Context, check func() error) (func(), error) {
		release := func() {
			if lease != nil {
				lease.Release()
				lease = nil
			}
			if root != nil {
				root.Close()
				root = nil
			}
		}
		if check() != nil {
			return release, ErrCapability
		}
		var e error
		identity, e = OpenExisting(held, repo, secretsDir)
		if e != nil || identity.Role != "Follower" || identity.ID != plan.OwnerID {
			return release, ErrCapability
		}
		service = NewService(repo, identity, nil)
		mediaPath, e := filepath.Abs(filepath.Join(dataRoot, "media"))
		if e != nil {
			return release, ErrCapability
		}
		info, e := os.Lstat(mediaPath)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return release, ErrCapability
		}
		root, e = os.OpenRoot(mediaPath)
		if e != nil {
			return release, ErrCapability
		}
		fence, e = ownerfence.Open(root, mediaPath, identity)
		if e != nil {
			return release, ErrCapability
		}
		lease, e = fence.Acquire(held, true)
		if e != nil {
			return release, ErrCapability
		}
		binding, e = lease.Binding(held)
		if e != nil {
			return release, ErrCapability
		}
		return release, checkScope(held, check)
	}
	work := func(held context.Context, check func() error) error {
		// Challenge and expiry may be renewed, but all durable source and target
		// fields must match the first authenticated plan for this operation.
		stable := plan
		stable.ExpiresAt = 0
		stable.Challenge = ""
		raw, e := json.Marshal(stable)
		if e != nil || len(raw) > 2048 {
			return ErrCapability
		}
		defer clear(raw)
		name := ".opaque-aliases/legacy-" + plan.OperationID + ".intent"
		if e = persistLegacyOwnerIntent(root, identity, name, raw); e != nil {
			return e
		}
		if e = checkScope(held, check); e != nil {
			return e
		}
		source, e := sealedtree.OpenLegacyOwnerSource(root, plan.SourcePath)
		if e != nil {
			return e
		}
		defer source.Close()
		before, e := source.File().Stat()
		if e != nil || !before.Mode().IsRegular() || before.Size() != plan.Bytes {
			return ErrCapability
		}
		sourceHash := sha256.New()
		sourceN, e := io.Copy(sourceHash, io.LimitReader(&legacyOwnerReader{ctx: held, r: source.File()}, plan.Bytes+1))
		if e != nil || sourceN != plan.Bytes || !hmac.Equal([]byte(hex.EncodeToString(sourceHash.Sum(nil))), []byte(plan.Digest)) || source.Check() != nil {
			return ErrCapability
		}
		if _, e = source.File().Seek(0, io.SeekStart); e != nil {
			return ErrCapability
		}
		publisher, e := sealedtree.NewBlobPublisher(root)
		if e != nil {
			return e
		}
		stageInfo, stageErr := root.Lstat("staging/" + plan.OperationID + ".part")
		existingStage := stageErr == nil
		if existingStage && (!stageInfo.Mode().IsRegular() || stageInfo.Size() != plan.Bytes) || stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
			return ErrCapability
		}
		_, free, e := fsutil.DiskUsage(root)
		if e != nil || free < store.PhysicalReserve || !existingStage && plan.Bytes > free-store.PhysicalReserve {
			return ErrCapability
		}
		if e = publisher.Stage(held, plan.OperationID, plan.BlobID, plan.Bytes, plan.Digest, source.File()); e != nil {
			return e
		}
		current, e := source.File().Stat()
		if e != nil || source.Check() != nil || !os.SameFile(before, current) || current.Size() != before.Size() || !current.ModTime().Equal(before.ModTime()) || checkScope(held, check) != nil {
			return ErrCapability
		}
		if e = publisher.PublishStaged(held, plan.OperationID, plan.BlobID, plan.Bytes, plan.Digest); e != nil {
			return e
		}
		destination, e := sealedtree.BlobPath(plan.BlobID)
		if e != nil {
			return e
		}
		target, e := sealedtree.OpenLegacyOwnerSource(root, destination)
		if e != nil {
			return e
		}
		defer target.Close()
		targetBefore, e := target.File().Stat()
		if e != nil || targetBefore.Size() != plan.Bytes {
			return ErrCapability
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(&legacyOwnerReader{ctx: held, r: target.File()}, plan.Bytes+1))
		targetAfter, e2 := target.File().Stat()
		sourceAfter, e3 := source.File().Stat()
		if e != nil || e2 != nil || e3 != nil || n != plan.Bytes || target.Check() != nil || source.Check() != nil || !os.SameFile(targetBefore, targetAfter) || !os.SameFile(before, sourceAfter) || !targetBefore.ModTime().Equal(targetAfter.ModTime()) || !before.ModTime().Equal(sourceAfter.ModTime()) || !hmac.Equal([]byte(hex.EncodeToString(h.Sum(nil))), []byte(plan.Digest)) || checkScope(held, check) != nil {
			return ErrCapability
		}
		relation, e := repo.Relationship(held, plan.RelationshipID)
		if e != nil {
			return ErrCapability
		}
		receipt, e := plan.PublishedReceipt()
		if e != nil {
			return ErrCapability
		}
		result, e = service.signOpaqueOwnerReceipt(held, relation, plan.MasterID, plan.OwnerID, plan.RelationshipID, receipt)
		lastSource, sourceErr := source.File().Stat()
		lastTarget, targetErr := target.File().Stat()
		if e != nil || sourceErr != nil || targetErr != nil || checkScope(held, check) != nil || source.Check() != nil || target.Check() != nil || !os.SameFile(before, lastSource) || !os.SameFile(targetBefore, lastTarget) || lastSource.Size() != before.Size() || lastTarget.Size() != targetBefore.Size() || !lastSource.ModTime().Equal(before.ModTime()) || !lastTarget.ModTime().Equal(targetBefore.ModTime()) {
			return ErrCapability
		}
		return nil
	}
	if err = gate.InspectSQLiteOwnerImport(ctx, dataRoot, databasePath, authorize, work); err != nil {
		return Envelope{}, err
	}
	return result, nil
}

type legacyOwnerReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *legacyOwnerReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func persistLegacyOwnerIntent(root *os.Root, identity *Identity, name string, raw []byte) error {
	info, err := root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 8192 {
			return ErrCapability
		}
		f, e := root.Open(name)
		if e != nil {
			return ErrCapability
		}
		defer f.Close()
		opened, e := f.Stat()
		if e != nil || !os.SameFile(info, opened) {
			return ErrCapability
		}
		sealed, e := io.ReadAll(io.LimitReader(f, 8193))
		if e != nil || len(sealed) > 8192 {
			return ErrCapability
		}
		plain, e := identity.OpenOpaqueOwnerRecord(name, string(sealed))
		if e != nil || !bytes.Equal(plain, raw) {
			return ErrCapability
		}
		clear(plain)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrCapability
	}
	sealed, err := identity.SealOpaqueOwnerRecord(name, raw)
	if err != nil {
		return ErrCapability
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ErrCapability
	}
	temp := ".opaque-aliases/.legacy-tmp-" + hex.EncodeToString(random[:])
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrCapability
	}
	defer root.Remove(temp)
	n, writeErr := f.WriteString(sealed)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || n != len(sealed) || syncErr != nil || closeErr != nil {
		return ErrCapability
	}
	if err = root.Link(temp, name); err != nil {
		return ErrCapability
	}
	if fsutil.SyncDirectory(root, ".opaque-aliases") != nil {
		return ErrCapability
	}
	return nil
}
