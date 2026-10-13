package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"strconv"
)

// Reverification exposes only bounded cold-byte integrity facts. It does not
// export archive contents, restore business state or authorize retention purge.
func RegisterNodeBackupObservation(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, repository store.BackupRepository) (func() error, error) {
	manifests, ok := repository.(store.BackupObservationRepository)
	if !ok {
		return nil, store.ErrBackupState
	}
	resolve := func(ctx context.Context, request resourceinventory.ContentRequest) (store.BackupManifest, error) {
		var empty store.BackupManifest
		generation, e := strconv.ParseInt(request.ObjectID, 10, 64)
		if e != nil || generation <= 0 || strconv.FormatInt(generation, 10) != request.ObjectID || request.Resource != "backup" {
			return empty, store.ErrBackupState
		}
		manifest, e := manifests.ReadyBackupManifest(ctx, request.Binding.RelationshipID, request.Binding.MemberID, request.Binding.MasterID, generation)
		if e != nil {
			return empty, e
		}
		digest, e := store.MigrationDigest(manifest)
		if e != nil || digest != request.MetadataSHA || manifest.Bytes != request.Bytes {
			return empty, store.ErrBackupState
		}
		return manifest, nil
	}
	jobs, e := resourceinventory.NewBackupJobs(context.Background(), func(ctx context.Context, request resourceinventory.ContentRequest) (resourceinventory.ContentObservation, error) {
		var empty resourceinventory.ContentObservation
		before, e := resolve(ctx, request)
		if e != nil {
			return empty, e
		}
		digest := sha256.New()
		var bytes int64
		observed, e := repository.ReadReadyBackup(ctx, before.MasterID, before.Generation, func(manifest store.BackupManifest, reader io.Reader) error {
			if manifest != before {
				return store.ErrBackupState
			}
			var e error
			bytes, e = io.CopyBuffer(digest, reader, make([]byte, 64<<10))
			return e
		})
		if e != nil {
			return empty, e
		}
		after, e := resolve(ctx, request)
		actual := hex.EncodeToString(digest.Sum(nil))
		if e != nil || after != before || observed != before || bytes != before.Bytes || actual != before.Checksum {
			return empty, store.ErrBackupState
		}
		return resourceinventory.ContentObservation{Path: "backup/" + request.ObjectID, Bytes: bytes, SHA256: actual}, nil
	}, nil)
	if e != nil {
		return nil, e
	}
	registerContentObservationRPC(router, "/internal/v1/backup-observation", settings, resolver, control, jobs, func(ctx context.Context, request resourceinventory.ContentRequest) error {
		_, e := resolve(ctx, request)
		return e
	})
	return func() error { jobs.Close(); return nil }, nil
}
