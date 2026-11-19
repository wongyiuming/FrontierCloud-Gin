package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Use a concrete fallback because slog's initial handler writes through log,
// whose output is redirected to our archive handler by slog.SetDefault.
func installArchiveLogger(sink logarchive.CaptureSink, fallback slog.Handler) func() {
	previous := slog.Default()
	output, flags := log.Writer(), log.Flags()
	if fallback == nil {
		fallback = slog.NewTextHandler(output, nil)
	}
	handler := &logarchive.Handler{Runtime: sink, Fallback: fallback}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return func() {
		if slog.Default() == logger {
			slog.SetDefault(previous)
			log.SetOutput(output)
			log.SetFlags(flags)
		}
	}
}

// Project logging reuses the existing Master DB, vault, node HTTPS clients and
// traffic monitor. A logging failure must not make business startup dependent
// on the optional archive node.
func configureProjectLogs(settings config.Config, s runtimeHTTP, router *gin.Engine, a *httpapi.Admin) func() error {
	noop := func() error { return nil }
	disabled := func() func() error {
		close, e := logarchive.OpenCollector(logarchive.DisabledSink{}, os.Stdout)
		if e != nil {
			return noop
		}
		return close
	}
	db, ok := s.Database.(interface{ Database() *sql.DB })
	if !ok || settings.DatabaseType != config.DatabaseSQLite {
		httpapi.RegisterAdminLogs(router, a, s.Control, nil)
		return disabled()
	}
	identity, e := s.Control.IdentityState(context.Background())
	if e != nil {
		httpapi.RegisterAdminLogs(router, a, s.Control, nil)
		return disabled()
	}
	private, e := vault.OpenExisting(settings.SecretsDirectory)
	if e != nil {
		httpapi.RegisterAdminLogs(router, a, s.Control, nil)
		return disabled()
	}
	catalog, e := logarchive.SharedCatalog(db.Database(), private, identity.ID)
	if e != nil {
		httpapi.RegisterAdminLogs(router, a, s.Control, nil)
		return disabled()
	}
	catalog.ConfigureDiskAdmission(settings.DataRoot)
	if s.Sealed != nil && s.Sealed.tree != nil {
		s.Sealed.tree.ConfigureLogArchive(catalog)
	}
	if repository, ok := s.Database.Pool().(interface{ ConfigureLogArchive(*logarchive.Catalog) }); ok {
		repository.ConfigureLogArchive(catalog)
	}
	logs := httpapi.NewProjectLogRuntime(catalog, s.Control, settings.AdminOrigin)
	s.Control.ConfigureLogHeartbeat(&projectLogBridge{master: logs})
	s.Control.ConfigureLogArchiveProtection(catalog.UsesNode)
	restoreLogger := installArchiveLogger(logs, s.LogFallback)
	logs.Start(context.Background())
	closeCollector, collectorError := logarchive.OpenCollector(logs, os.Stdout)
	if collectorError != nil {
		logs.Capture(logarchive.Error, map[string]any{"message": "project_log_collector_unavailable"})
		closeCollector = func() error { return nil }
	}
	httpapi.RegisterAdminLogs(router, a, s.Control, logs)
	return func() error {
		e := errors.Join(closeCollector(), logs.Close())
		restoreLogger()
		return e
	}
}
