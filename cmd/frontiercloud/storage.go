package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
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
	httpapi.RegisterNodeMedia(router, settings, s.Resolver, s.Control, s.Media)
	httpapi.RegisterNodeStorage(router, settings, s.Resolver, s.Control, s.Media)
	httpapi.RegisterNodeRecordings(router, settings, s.Resolver, s.Control, s.Recordings)
	httpapi.RegisterNodeBackups(router, settings, s.Resolver, s.Control, s.Database.Backups())
	return router, func() error { return nil }, nil
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
		return printStoragePair(ctx, node.NewService(db.Nodes(), identity, transport), db.Nodes(), output)
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
	// Pin the configured local certificate for loopback readiness only. Remote
	// control clients continue normal CA verification; no InsecureSkipVerify.
	pem, err := os.ReadFile(settings.StorageTLSCert)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid storage TLS certificate")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: settings.ServerName, MinVersion: tls.VersionTLS12}}}, nil
}
