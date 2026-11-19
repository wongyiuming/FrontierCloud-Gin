package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logsafe"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/bootstrap"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certmanager"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/security"
	storecontract "github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/stun"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"path/filepath"
)

func main() {
	if err := command(os.Args[1:]); err != nil {
		slog.Error("FrontierCloud stopped", "error_type", logsafe.ErrorType(err))
		os.Exit(1)
	}
}

func command(arguments []string) error {
	name := "serve"
	if len(arguments) > 0 {
		name = arguments[0]
	}
	switch name {
	case "serve":
		return serve()
	case "log-query":
		return logQueryCommand(arguments[1:], os.Stdout)
	case "migrate":
		settings, err := config.Load()
		if err != nil {
			return err
		}
		return guardedCommand(settings, func(parent context.Context) error {
			database, err := openRuntimeStore(parent, settings)
			if err != nil {
				return err
			}
			defer database.Close()
			ctx, cancel := context.WithTimeout(parent, 90*time.Second)
			defer cancel()
			return database.Initialize(ctx)
		})
	case "init-secrets":
		settings, err := config.Load()
		if err != nil {
			return err
		}
		return guardedCommand(settings, func(context.Context) error { return bootstrap.InitializeSecrets(settings.SecretsDirectory) })
	case "init-media":
		settings, err := config.Load()
		if err != nil {
			return err
		}
		return guardedCommand(settings, func(ctx context.Context) error { return bootstrap.InitializeMediaContext(ctx, settings.DataRoot) })
	case "healthcheck":
		return healthcheck()
	case "certificate-agent":
		if os.Getenv("PROJECT_LOG_FORWARD") == "1" {
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logarchive.ForwardWriter{}, nil)))
		}
		return certificateAgentCommand(arguments[1:])
	case "init-certificate":
		return initializeCertificateVolumes(arguments[1:])
	case "certificate-healthcheck":
		if len(arguments) != 1 {
			return errors.New("certificate-healthcheck accepts no arguments")
		}
		return certificateHealthcheck()
	case "certificate-status":
		if len(arguments) != 1 {
			return errors.New("certificate-status accepts no arguments")
		}
		return certificateContainerStatus(os.Stdout)
	case "certificate-ready":
		if len(arguments) != 1 {
			return errors.New("certificate-ready accepts no arguments")
		}
		v, err := queryCertificateContainerStatus()
		if err != nil {
			return err
		}
		if !v.ControllerRunning || v.Enabled && (!v.HTTPSReady || !v.ServingMatches) {
			return errors.New("automatic TLS has not verified the serving certificate")
		}
		return nil
	case "certificate-renew":
		if len(arguments) != 1 {
			return errors.New("certificate-renew accepts no arguments")
		}
		return certificateContainerRenew(os.Stdout)
	case "storage-pair":
		if len(arguments) != 1 {
			return errors.New("storage-pair accepts no arguments")
		}
		return storagePairCommand(os.Stdout)
	case "storage-status":
		if len(arguments) != 1 {
			return errors.New("storage-status accepts no arguments")
		}
		return storageStatusCommand(os.Stdout)
	case "storage-owner-prepare":
		return storageOwnerPrepareCommand(arguments[1:], os.Stdout)
	case "operator-status":
		if len(arguments) != 1 {
			return errors.New("operator-status accepts no arguments")
		}
		return operatorStatusCommand(os.Stdout)
	case "tree-backup-runtime-inspect":
		return treeBackupRuntimeInspect(arguments[1:], os.Stdout)
	case "tree-backup-capture":
		if len(arguments) != 1 {
			return errors.New("tree-backup-capture accepts no arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		return treeBackupCapture(ctx, os.Stdin, os.Stdout, [3]string{"/fc-tree-data", "/fc-tree-secrets", "/fc-tree-tmp"})
	case "tree-retained-recovery":
		if len(arguments) != 1 {
			return errors.New("tree-retained-recovery accepts no arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		return treeRetainedRecovery(ctx, os.Stdin, os.Stdout, [2]string{"/fc-tree-data", "/fc-tree-secrets"})
	case "sealed-tree-inventory":
		if len(arguments) != 1 {
			return errors.New("sealed-tree-inventory accepts no arguments")
		}
		return sealedTreeInventoryCommand(os.Stdout)
	case "sealed-tree-prepare":
		return sealedTreePrepareCommand(arguments[1:], os.Stdout)
	case "sealed-s3-prepare":
		return sealedS3PrepareCommand(arguments[1:], os.Stdout)
	case "recovery-verify":
		if len(arguments) != 1 {
			return errors.New("recovery-verify accepts no arguments")
		}
		return recoveryVerifyCommand(os.Stdout)
	case "storage-endpoint", "storage-rebind":
		return storageEndpointCommand(name, arguments[1:], os.Stdout)
	case "delete-storage-recording":
		return deleteStorageRecordingCommand(arguments[1:], os.Stdout)
	case "delete-owned-recording":
		return deleteOwnedRecordingCommand(arguments[1:], os.Stdout)
	case "verify-business-point":
		return verifyBusinessPointCommand(arguments[1:], os.Stdout)
	case "verify-backup":
		return verifyBackupCommand(arguments[1:], os.Stdout)
	case "prepare-business-state":
		return prepareBusinessStateCommand(arguments[1:], os.Stdout)
	case "import-business-state":
		return importBusinessStateCommand(arguments[1:], os.Stdin, os.Stdout)
	case "resume-business-state":
		return resumeBusinessStateCommand(arguments[1:], os.Stdout)
	case "cleanup-backup-cache":
		return cleanupBackupCacheCommand(arguments[1:], os.Stdout)
	case "maintenance":
		return maintenanceCommand(arguments[1:], os.Stdout)
	case "master-migration":
		return masterMigrationCommand(arguments[1:], os.Stdout)
	case "master-to-sqlite":
		return masterToSQLiteCommand(arguments[1:], os.Stdout)
	case "follower-migration":
		return followerMigrationCommand(arguments[1:], os.Stdout)
	case "follower-to-sqlite":
		return followerToSQLiteCommand(arguments[1:], os.Stdout)
	case "adopt-storage":
		return adoptStorageCommand(arguments[1:], os.Stdout)
	case "adopt-recordings":
		return recordingAdoptionCommand(arguments[1:], os.Stdout, false)
	case "recording-inventory":
		return recordingAdoptionCommand(arguments[1:], os.Stdout, true)
	case "drain-rename-history":
		return drainRenameCommand(arguments[1:], os.Stdout)
	case "prepare-release":
		return prepareReleaseCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", name)
	}
}

func serve() error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch settings.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	case "CRITICAL":
		level = slog.Level(12)
	}
	options := &slog.HandlerOptions{Level: level}
	var logging slog.Handler = slog.NewJSONHandler(os.Stdout, options)
	if settings.LogFormat == "text" {
		logging = slog.NewTextHandler(os.Stdout, options)
	}
	slog.SetDefault(slog.New(logging))
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runtime, err := gate.Runtime(parent)
	if err != nil {
		return err
	}
	defer runtime.Close()
	shutdown := runtime.Context()
	database, err := openRuntimeStore(shutdown, settings)
	if err != nil {
		return err
	}
	defer database.Close()
	initialization, cancelInitialization := context.WithTimeout(shutdown, 90*time.Second)
	defer cancelInitialization()
	if err := initializeRuntimeSchema(initialization, database, settings); err != nil {
		return fmt.Errorf("initialize runtime schema: %w", err)
	}
	tree, closeTree, err := openOpaqueMasterTree(initialization, database, settings)
	if err != nil {
		return err
	}
	if closeTree != nil {
		defer closeTree()
	}
	mediaRoot := filepath.Join(settings.DataRoot, "media")
	if err := checkOpaqueRegistryIdentity(initialization, database.Nodes(), mediaRoot, settings.SecretsDirectory); err != nil {
		return err
	}
	identity, err := openRuntimeIdentity(initialization, database, settings)
	if err != nil {
		return fmt.Errorf("open runtime identity: %w", err)
	}
	if err := runtimeIdentityTransport(settings, identity); err != nil {
		return err
	}
	if err := identity.CheckNativeRuntime(initialization, settings.DataRoot); err != nil {
		return err
	}
	owner, err := openRuntimeOwner(initialization, settings, database, identity)
	if err != nil {
		return fmt.Errorf("open runtime Owner: %w", err)
	}
	if owner != nil {
		defer owner.Close()
	}
	if tree != nil && owner == nil {
		return errors.New("encrypted Master tree requires its authenticated Owner volume")
	}
	var mediaService *media.Service
	if tree != nil {
		mediaService, err = media.NewSealedContext(initialization, mediaRoot, database.Media(), identity, tree)
	} else {
		mediaService, err = media.NewContext(shutdown, mediaRoot, database.Media(), identity)
	}
	if err != nil {
		return fmt.Errorf("open runtime media: %w", err)
	}
	defer mediaService.Close()
	mediaService.ConfigureCatalogCache(time.Duration(settings.MediaCatalogCacheTTL) * time.Second)

	var redisClient *redis.Client
	if settings.DeploymentMode != config.DeploymentStorage {
		redisOptions, err := redis.ParseURL(settings.RedisURL)
		if err != nil {
			return err
		}
		redisOptions.ContextTimeoutEnabled = true
		redisOptions.MaxRetries = 1
		redisOptions.DialTimeout = 2 * time.Second
		redisOptions.ReadTimeout = 2 * time.Second
		redisOptions.WriteTimeout = 2 * time.Second
		redisClient = redis.NewClient(redisOptions)
		defer redisClient.Close()
	}

	resolver, err := network.New(settings.TrustedProxyNetworks)
	if err != nil {
		return err
	}
	ingressEdgeResolver, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return fmt.Errorf("invalid PUBLIC_INGRESS_TRUSTED_PROXY_NETWORKS: %w", err)
	}
	controlTransport := node.NewTransport()
	defer controlTransport.Close()
	controlService := node.NewService(database.Nodes(), identity, controlTransport)
	if settings.FollowerResourceOrigin != "" {
		if !settings.TLSEnabled {
			return errors.New("FOLLOWER_RESOURCE_ORIGIN requires TLS")
		}
		if err := node.ValidateFollowerResourceOrigin(settings.FollowerResourceOrigin); err != nil {
			return fmt.Errorf("invalid FOLLOWER_RESOURCE_ORIGIN: %w", err)
		}
	}
	if settings.FollowerIngressOrigin != "" {
		if !settings.TLSEnabled || settings.DeploymentMode != config.DeploymentStorage {
			return errors.New("FOLLOWER_INGRESS_ORIGIN requires TLS and storage deployment")
		}
		if err := node.ValidateFollowerIngressOrigin(settings.FollowerIngressOrigin); err != nil {
			return fmt.Errorf("invalid FOLLOWER_INGRESS_ORIGIN: %w", err)
		}
	}
	if settings.TLSEnabled {
		if err := controlService.ConfigurePublicOrigin(settings.PublicOrigin); err != nil && identity.Role == "Master" {
			return err
		}
		if identity.Role == "Master" {
			if err := controlService.ConfigureSelectedAdminOrigin(context.Background(), settings.AdminOrigin); err != nil {
				return err
			}
		}
	}
	mediaService.ConfigureCluster(database.Nodes(), database.Pool(), controlService)
	if settings.DeploymentMode != config.DeploymentStorage {
		repository, ok := database.Pool().(storecontract.S3Repository)
		if !ok {
			return errors.New("business runtime requires the durable S3 repository")
		}
		private, err := vault.OpenExisting(settings.SecretsDirectory)
		if err != nil {
			return err
		}
		mediaService.ConfigureS3(s3media.New(repository, database.Nodes(), private))
	}
	recordingsRoot, err := os.OpenRoot(filepath.Join(settings.DataRoot, "recordings"))
	if err != nil {
		return err
	}
	defer recordingsRoot.Close()
	controlService.ConfigureVolumes(database.Pool(), mediaService, recordingsRoot)
	if settings.DeploymentMode != config.DeploymentStorage {
		backupBuilder, err := backup.New(database.Backups(), mediaService, filepath.Join(settings.DataRoot, ".business-backups"))
		if err != nil {
			return err
		}
		defer backupBuilder.Close()
		if err := configureBusinessCheckpoint(settings, database, tree, backupBuilder, identity.ID); err != nil {
			return err
		}
		controlService.ConfigureBackups(database.Backups(), backupBuilder)
	}
	var recordingStorage *recording.Storage
	if tree != nil {
		recordingStorage, err = recording.NewSealedContext(initialization, recordingsRoot, database.Recordings(), database.Nodes(), tree)
	} else {
		recordingStorage, err = recording.NewContext(shutdown, recordingsRoot, database.Recordings(), database.Nodes())
	}
	if err != nil {
		return fmt.Errorf("open runtime recording storage: %w", err)
	}
	var recordingManager *recording.Manager
	if settings.DeploymentMode != config.DeploymentStorage {
		recordingManager = recording.NewManager(database.Recordings(), database.Karaoke(), database.Nodes(), database.Pool(), controlService, recordingStorage)
	}
	var securityService *security.Service
	if settings.DeploymentMode != config.DeploymentStorage {
		securityService, err = security.New(settings, database.Security())
		if err != nil {
			return err
		}
		defer securityService.Close()
		edgeInit, edgeCancel := context.WithTimeout(shutdown, 15*time.Second)
		err = securityService.Publish(edgeInit, true)
		edgeCancel()
		if err != nil {
			return err
		}
	}
	var storageTLS *certmanager.Serving
	var certificateMonitor *certificate.AutomaticMonitor
	client := certificate.UnixClient{Socket: certmanager.ControlSocket, Hostname: settings.ServerName}
	certificateMonitor = certificate.NewAutomaticMonitor(client, settings.ServerName, settings.TLSEnabled)
	certificateDone := make(chan struct{})
	go func() { defer close(certificateDone); certificateMonitor.Run(shutdown) }()
	defer func() { stop(); <-certificateDone }()
	controlService.ConfigureNetwork(0, certificateMonitor, certificateMonitor.Status, database.Admin())
	if settings.DeploymentMode == config.DeploymentStorage {
		storageTLS = certmanager.NewServing(settings.ServerName)
		if err = controlService.ConfigureStorageTransport(settings.StorageTransport); err != nil {
			return err
		}
		address, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", settings.STUNPort))
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", address)
		if err != nil {
			slog.Warn("storage STUN unavailable; HTTPS remains independent")
		} else {
			controlService.SetSTUNPort(settings.STUNPort)
			stunDone := make(chan struct{})
			go func() {
				defer close(stunDone)
				defer controlService.SetSTUNPort(0)
				if stun.Serve(shutdown, conn) != nil && shutdown.Err() == nil {
					slog.Warn("storage STUN stopped; HTTPS remains independent")
				}
			}()
			defer func() { stop(); conn.Close(); <-stunDone }()
		}
	}
	admission, cancelAdmission := context.WithTimeout(shutdown, 15*time.Second)
	err = identity.RecordNativeRuntime(admission, settings.DataRoot)
	if err == nil && settings.DeploymentMode == config.DeploymentStorage {
		err = controlService.InitializeStorage(admission, settings.StorageEndpoint)
	}
	cancelAdmission()
	if err != nil {
		return err
	}
	if settings.FollowerResourceOrigin != "" {
		if err := controlService.ConfigureFollowerResourceOrigin(settings.FollowerResourceOrigin); err != nil {
			return fmt.Errorf("invalid FOLLOWER_RESOURCE_ORIGIN: %w", err)
		}
	}
	// Native inventory pins the completed admission records before serving any
	// HTTP requests, including retirement observations.
	var sealed *sealedMasterRuntime
	if tree != nil {
		sealed = &sealedMasterRuntime{tree: tree, runtime: runtime, maintenance: gate}
	}
	var ingressBootstrap *masterIngressBootstrap
	if sealed != nil {
		ingressBootstrap, err = startMasterIngressBootstrap(shutdown, settings.HTTPAddress, runtime, controlService, ingressEdgeResolver)
		if err != nil {
			return fmt.Errorf("open Master ingress bootstrap: %w", err)
		}
		// On any startup failure, stop accepting before the node, tree and
		// database resources unwind; no probe may outlive those resources.
		defer func() {
			runtime.Stop()
			ingressBootstrap.server.Close()
			ingressBootstrap.listener.Close()
			runtime.WaitHTTP()
		}()
	}
	handler, closeHTTP, err := newRuntimeHTTP(settings, runtimeHTTP{Database: database, Identity: identity, Media: mediaService, Control: controlService, Owner: owner, Sealed: sealed, Recordings: recordingStorage, Manager: recordingManager, Security: securityService, Redis: redisClient, Resolver: resolver})
	if err != nil {
		return fmt.Errorf("register native HTTP runtime: %w", err)
	}
	defer closeHTTP()
	var servedHandler http.Handler = handler
	if settings.DeploymentMode != config.DeploymentStorage {
		if sealed != nil {
			servedHandler = masterIngressEdgeWithControls(handler, controlService, ingressEdgeResolver, sealed.catalog, sealed.recordingControlsReady)
			if sealed.recovery != nil {
				servedHandler = wrapRecoveryControl(servedHandler, sealed.recovery, settings.AdminOrigin, ingressEdgeResolver)
			}
		} else {
			servedHandler = masterIngressEdge(handler, controlService, ingressEdgeResolver)
		}
	} else {
		peerIngress := newPeerIngressHTTP(handler, controlService, settings)
		peerIngress.recordingControlsReady = owner != nil && settings.TLSEnabled
		defer peerIngress.Close()
		servedHandler = peerIngress
		if settings.FollowerIngressOrigin != "" {
			if err := controlService.ConfigureFollowerIngressCandidate(settings.FollowerIngressOrigin); err != nil {
				return err
			}
		}
	}
	var server *http.Server
	if ingressBootstrap != nil {
		server = ingressBootstrap.server
	} else {
		server = &http.Server{
			Addr:              settings.HTTPAddress,
			Handler:           runtime.Handler(servedHandler),
			BaseContext:       func(net.Listener) context.Context { return shutdown },
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	publisherDone := make(chan struct{})
	go func() {
		defer close(publisherDone)
		if securityService != nil {
			securityService.Run(shutdown)
		}
	}()
	deletionDone := make(chan struct{})
	go func() {
		defer close(deletionDone)
		if waitIngressRecovery(shutdown, sealed) {
			if sealed != nil && sealed.mediaDeletionRun != nil {
				sealed.mediaDeletionRun(shutdown)
				return
			}
			mediaService.RunGlobalDeletes(shutdown)
		}
	}()
	uploadRecoveryDone := make(chan struct{})
	go func() {
		defer close(uploadRecoveryDone)
		if waitIngressRecovery(shutdown, sealed) {
			mediaService.RunUploadRecovery(shutdown)
		}
	}()
	s3RecoveryDone := make(chan struct{})
	go func() {
		defer close(s3RecoveryDone)
		if settings.DeploymentMode != config.DeploymentStorage && waitIngressRecovery(shutdown, sealed) {
			mediaService.RunS3Recovery(shutdown)
		}
	}()
	recordingDone := make(chan struct{})
	go func() {
		defer close(recordingDone)
		if settings.DeploymentMode != config.DeploymentStorage && waitIngressRecovery(shutdown, sealed) {
			recordingManager.Run(shutdown)
		}
	}()
	backupDone := make(chan struct{})
	go func() {
		defer close(backupDone)
		if waitIngressRecovery(shutdown, sealed) {
			controlService.RunBackups(shutdown)
		}
	}()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		if sealed != nil && sealed.recovery != nil {
			sealed.recovery.retrySelected()
		}
		if waitIngressRecovery(shutdown, sealed) {
			controlService.Run(shutdown)
		}
	}()
	defer func() {
		stop()
		<-publisherDone
		<-deletionDone
		<-uploadRecoveryDone
		<-s3RecoveryDone
		<-recordingDone
		<-backupDone
		<-controlDone
	}()
	// Cancel handlers, close network bodies, then join them BEFORE service roots
	// or the lifecycle lease close. Even ignored-context cleanup holds the fence.
	defer func() { runtime.Stop(); server.Close(); runtime.WaitHTTP() }()
	if err := shutdown.Err(); err != nil {
		return err
	}
	errorsChannel := make(chan error, 1)
	var listener net.Listener
	if ingressBootstrap != nil {
		listener = ingressBootstrap.listener
		errorsChannel = ingressBootstrap.errors
	} else {
		listener, err = net.Listen("tcp", settings.HTTPAddress)
		if err != nil {
			return err
		}
	}
	defer listener.Close()
	if settings.DeploymentMode == config.DeploymentStorage {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: storageTLS.GetCertificate}
		go func() { errorsChannel <- server.ServeTLS(listener, "", "") }()
		// Pair lifetime begins only after the serving certificate has passed
		// a real handshake. Issuance delay never consumes its five-minute TTL.
		pairingDone := make(chan struct{})
		go func() {
			defer close(pairingDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-shutdown.Done():
					return
				case <-ticker.C:
					if !certificateMonitor.Status().HTTPSReady {
						continue
					}
					ctx, cancel := context.WithTimeout(shutdown, 5*time.Second)
					err := printStoragePair(ctx, controlService, database.Nodes(), os.Stdout)
					cancel()
					if err != nil {
						slog.Warn("storage pairing package generation failed; retrying after HTTPS readiness")
						continue
					}
					return
				}
			}
		}()
		defer func() { stop(); <-pairingDone }()
	} else if ingressBootstrap != nil {
		// All routes and prerequisites have been installed. Requests reaching
		// this same listener now enter the complete runtime atomically.
		select {
		case err := <-errorsChannel:
			return fmt.Errorf("Master ingress bootstrap stopped: %w", err)
		default:
		}
		ingressBootstrap.publish(servedHandler)
	} else {
		go func() { errorsChannel <- server.Serve(listener) }()
	}
	if sealed != nil && sealed.recovery != nil && sealed.recovery.Active() {
		slog.Warn("FrontierCloud ingress recovery only", "address", settings.HTTPAddress)
	} else {
		slog.Info("FrontierCloud Go runtime started", "address", settings.HTTPAddress, "database", database.Backend())
	}
	select {
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-shutdown.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func runtimeIdentityTransport(settings config.Config, identity *node.Identity) error {
	if identity == nil {
		return storecontract.ErrNodeState
	}
	switch identity.Role {
	case "Standalone":
		return nil
	case "Master", "Follower":
		if !settings.TLSEnabled {
			return errors.New("fixed Master/Follower identity requires HTTPS; restore TLS_ENABLED, role is never reset automatically")
		}
		if identity.Role == "Follower" && settings.DeploymentMode != config.DeploymentStorage {
			return errors.New("storage identities require only_stroge; business Follower deployment is retired")
		}
		if _, err := node.Endpoint(identity.Endpoint); err != nil {
			return err
		}
		if identity.Role == "Master" {
			if _, err := node.MasterEndpoint(identity.Endpoint); err != nil {
				return err
			}
		}
		return nil
	default:
		return storecontract.ErrNodeState
	}
}

func healthcheck() error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	address, err := healthAddress(settings.HTTPAddress)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	scheme := "http"
	if settings.DeploymentMode == config.DeploymentStorage {
		client, err = storageHealthClient(settings)
		if err != nil {
			return err
		}
		scheme = "https"
	}
	response, err := client.Get(scheme + "://" + address + "/health/ready")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %d", response.StatusCode)
	}
	return nil
}

func healthAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid HTTP_ADDR: %w", err)
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	return net.JoinHostPort(host, port), nil
}

func openStore(settings config.Config) (storecontract.Store, error) {
	if settings.DatabaseType == config.DatabaseSQLite {
		db, err := sqlitestore.Open(settings.SQLitePath)
		if err != nil {
			return nil, err
		}
		if settings.DeploymentMode == config.DeploymentStorage {
			if err := db.ConfigureFileBackups(filepath.Join(settings.DataRoot, ".cold-backups")); err != nil {
				db.Close()
				return nil, err
			}
		}
		return db, nil
	}
	return mysqlstore.Open(mysqlstore.Config{
		Host:         settings.MySQLHost,
		Port:         settings.MySQLPort,
		Database:     settings.MySQLDatabase,
		User:         settings.MySQLUser,
		PasswordFile: settings.MySQLPasswordFile,
	})
}
