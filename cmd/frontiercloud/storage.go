package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certmanager"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Storage has no Redis, Admin session, account, player or business API surface.
// File access still uses the Master's existing signed, expiring capabilities.
func newStorageHTTP(settings config.Config, s runtimeHTTP) (*gin.Engine, func() error, error) {
	if s.Database == nil || s.Identity == nil || s.Media == nil || s.Control == nil || s.Recordings == nil || s.Resolver == nil {
		return nil, nil, errors.New("incomplete storage HTTP services")
	}
	router := httpapi.NewWithResolver(func(ctx context.Context) error {
		if err := s.Database.Ping(ctx); err != nil {
			return err
		}
		if err := s.Media.Ready(ctx); err != nil {
			return err
		}
		return s.Recordings.Ready(ctx)
	}, nil, s.Resolver)
	httpapi.RegisterNodeIdentity(router, settings, s.Resolver, s.Control)
	httpapi.RegisterNodeControl(router, settings, s.Resolver, s.Control)
	httpapi.RegisterNodeCertificate(router, settings, s.Resolver, s.Control)
	httpapi.RegisterNodeMedia(router, settings, s.Resolver, s.Control, s.Media)
	httpapi.RegisterNodeStorage(router, settings, s.Resolver, s.Control, s.Media)
	closeMigration := func() error { return nil }
	if peers, ok := s.Database.Pool().(store.MigrationPeerRepository); ok {
		httpapi.RegisterNodeMigrationControl(router, settings, s.Resolver, s.Control, s.Media, peers)
		closeMigration = httpapi.RegisterNodeMigrationData(router, settings, s.Resolver, s.Control, s.Media, s.Recordings, peers)
	}
	httpapi.RegisterNodeRecordings(router, settings, s.Resolver, s.Control, s.Recordings)
	httpapi.RegisterNodeBackups(router, settings, s.Resolver, s.Control, s.Database.Backups())
	return router, closeMigration, nil
}

func printStoragePair(ctx context.Context, service *node.Service, repo store.NodeRepository, output io.Writer) error {
	relations, err := repo.Relationships(ctx, false)
	if err != nil {
		return err
	}
	for _, rel := range relations {
		if rel.Direction == "upstream" && rel.State != "revoked" {
			return nil // Restart must not leak new credentials or change ownership.
		}
	}
	value, err := service.CreatePair(ctx, store.NodeAudit{Actor: "local-storage-bootstrap"})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(value)
}

func storagePairCommand(output io.Writer) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if settings.DeploymentMode != config.DeploymentStorage {
		return errors.New("storage-pair requires only_stroge")
	}
	// Verify the actual local HTTPS service before starting a fresh pair TTL.
	// Controller readiness alone is insufficient, and its cached observations
	// must not form a circular dependency with pairing or Web health.
	if err = healthcheck(); err != nil {
		return errors.New("storage pairing requires ready HTTPS; automatic TLS is pending or degraded")
	}
	return guardedCommand(settings, func(ctx context.Context) error {
		db, err := openRuntimeStore(ctx, settings)
		if err != nil {
			return err
		}
		defer db.Close()
		identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
		if err != nil {
			return err
		}
		if identity.Role != "Follower" || identity.Endpoint != settings.StorageEndpoint {
			return store.ErrNodeState
		}
		transport := node.NewTransport()
		defer transport.Close()
		service := node.NewService(db.Nodes(), identity, transport)
		if err = service.ConfigureStorageTransport(settings.StorageTransport); err != nil {
			return err
		}
		return printStoragePair(ctx, service, db.Nodes(), output)
	})
}

// Local read-only diagnostics replace a storage Admin GUI. Relationship keys
// are excluded by the repository's JSON contract; no writer/bootstrap is used.
func storageStatusCommand(output io.Writer) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if settings.DeploymentMode != config.DeploymentStorage {
		return errors.New("storage-status requires only_stroge")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := openExistingStore(ctx, settings)
	if err != nil {
		return err
	}
	defer db.Close()
	identity, err := node.OpenExisting(ctx, db.Nodes(), settings.SecretsDirectory)
	if err != nil {
		return err
	}
	if identity.Role != "Follower" || identity.Endpoint != settings.StorageEndpoint {
		return store.ErrNodeState
	}
	value, err := node.NewService(db.Nodes(), identity, nil).Status(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(value)
}

// Health is local transport readiness, not a public control-plane exception.
func storageHealthClient(settings config.Config) (*http.Client, error) {
	// Pin the current complete local pair for loopback readiness only. Remote
	// control clients continue normal CA verification; no InsecureSkipVerify.
	manager := certmanager.NewServing(settings.ServerName)
	pair, err := manager.GetCertificate(nil)
	if err != nil {
		return nil, err
	}
	return storageHealthClientForPair(settings.ServerName, pair)
}
func storageHealthClientForPair(host string, pair *tls.Certificate) (*http.Client, error) {
	if pair == nil || len(pair.Certificate) == 0 {
		return nil, errors.New("TLS pair unavailable")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(host) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, errors.New("TLS pair is expired or has the wrong identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}}}, nil
}
