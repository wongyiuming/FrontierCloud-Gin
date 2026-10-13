package main

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/diagnostics"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/karaoke"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/observation"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/security"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// runtimeHTTP is the single production registration path, also exercised by
// route and behavior acceptance. It does not alter startup admission policy.
type runtimeHTTP struct {
	Database   store.Store
	Identity   *node.Identity
	Media      *media.Service
	Control    *node.Service
	Recordings *recording.Storage
	Manager    *recording.Manager
	Security   *security.Service
	Redis      *redis.Client
	Resolver   *network.Resolver
}

func newRuntimeHTTP(settings config.Config, services runtimeHTTP) (*gin.Engine, func() error, error) {
	if settings.DeploymentMode == config.DeploymentStorage {
		return newStorageHTTP(settings, services)
	}
	database, identity := services.Database, services.Identity
	mediaService, controlService := services.Media, services.Control
	recordingStorage, recordingManager := services.Recordings, services.Manager
	securityService, redisClient := services.Security, services.Redis
	resolver := services.Resolver
	if database == nil || identity == nil || mediaService == nil || controlService == nil || recordingStorage == nil || recordingManager == nil || securityService == nil || redisClient == nil || resolver == nil {
		return nil, nil, errors.New("incomplete native HTTP services")
	}
	var closers []func() error
	closeHTTP := func() error {
		var result error
		for i := len(closers) - 1; i >= 0; i-- {
			result = errors.Join(result, closers[i]())
		}
		closers = nil
		return result
	}
	ready := false
	defer func() {
		if !ready {
			closeHTTP()
		}
	}()
	handler := httpapi.NewWithResolver(func(ctx context.Context) error {
		if err := database.Ping(ctx); err != nil {
			return err
		}
		if err := mediaService.Ready(ctx); err != nil {
			return err
		}
		if err := recordingStorage.Ready(ctx); err != nil {
			return err
		}
		return securityService.Ready(ctx)
	}, func(ctx context.Context) error {
		return redisClient.Ping(ctx).Err()
	}, resolver, httpapi.SecurityMiddleware(securityService, resolver))
	public, err := httpapi.RegisterPublic(handler, settings, mediaService)
	if err != nil {
		return nil, nil, err
	}
	closers = append(closers, public.Close)
	public.ConfigureNetwork(controlService)
	adminService, err := admin.New(settings, admin.NewRedisCache(redisClient), database.Admin())
	if err != nil {
		return nil, nil, err
	}
	adminHTTP, err := httpapi.RegisterAdmin(handler, settings, adminService, public, identity)
	if err != nil {
		return nil, nil, err
	}
	httpapi.RegisterAdminNodes(handler, adminHTTP, controlService)
	httpapi.RegisterAdminRetirement(handler, adminHTTP, &noderetirement.Service{Repository: database.Pool().(store.RetirementRepository), Nodes: database.Nodes(), Client: controlService})
	httpapi.RegisterOperational(handler, adminHTTP)
	httpapi.RegisterPlaybackDiagnostics(handler, settings, resolver, controlService, adminHTTP, diagnostics.New())
	siteService, err := sitecontrol.Open(settings.DataRoot, nil)
	if err != nil {
		return nil, nil, err
	}
	closers = append(closers, siteService.Close)
	httpapi.RegisterSiteAdmin(handler, adminHTTP, siteService)
	httpapi.RegisterSecurityAdmin(handler, adminHTTP, securityService)
	accountsHTTP := httpapi.RegisterKaraokeAccounts(handler, karaoke.New(database.Karaoke(), database.Nodes(), karaoke.NewRedisCache(redisClient)), public, adminHTTP, resolver)
	httpapi.RegisterKaraokeRecordings(handler, accountsHTTP, recordingManager, recordingStorage)
	httpapi.RegisterKaraokeMedia(handler, public, resolver)
	httpapi.RegisterNodeRecordings(handler, settings, resolver, controlService, recordingStorage)
	httpapi.RegisterNodeIdentity(handler, settings, resolver, controlService)
	httpapi.RegisterNodeControl(handler, settings, resolver, controlService)
	httpapi.RegisterNodeBackups(handler, settings, resolver, controlService, database.Backups())
	httpapi.RegisterNodeMedia(handler, settings, resolver, controlService, mediaService)
	httpapi.RegisterNodeStorage(handler, settings, resolver, controlService, mediaService)
	if peers, ok := database.Pool().(store.MigrationPeerRepository); ok {
		httpapi.RegisterNodeMigrationControl(handler, settings, resolver, controlService, mediaService, peers)
		closers = append(closers, httpapi.RegisterNodeMigrationData(handler, settings, resolver, controlService, mediaService, recordingStorage, peers))
	}
	closeInventory, err := httpapi.RegisterNodePhysicalInventory(handler, settings, resolver, controlService, database.Pool().(store.PhysicalInventoryRepository), mediaService.InventoryRoot(), recordingStorage.InventoryRoot())
	if err != nil {
		return nil, nil, err
	}
	closers = append(closers, closeInventory)
	closeContent, err := httpapi.RegisterNodeContentObservation(handler, settings, resolver, controlService, database.Pool().(store.ManagedPhysicalRepository), mediaService, recordingStorage)
	if err != nil {
		return nil, nil, err
	}
	closers = append(closers, closeContent)
	if migrations, ok := database.Pool().(store.MigrationRepository); ok {
		runner := &resourcemigration.Runner{Repository: migrations, Nodes: database.Nodes(), Client: controlService}
		httpapi.RegisterAdminMigrations(handler, adminHTTP, database.Pool().(store.MigrationAdminRepository), runner)
		stop, err := runner.Start(context.Background())
		if err != nil {
			return nil, nil, err
		}
		closers = append(closers, stop)
	}
	httpapi.RegisterObservations(handler, adminHTTP, observation.New(database.Observations(), redisClient, settings.WebRTCCooldown), resolver)

	ready = true
	return handler, closeHTTP, nil
}
