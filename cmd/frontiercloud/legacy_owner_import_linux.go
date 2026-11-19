//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func legacyOwnerImportCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 0 || input == nil || output == nil {
		return errors.New("owner import accepts a signed plan on stdin")
	}
	var request struct {
		Plan      protocol.LegacyOwnerImportPlan `json:"plan"`
		Signature string                         `json:"signature"`
	}
	raw, err := io.ReadAll(io.LimitReader(input, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("invalid signed owner plan")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return errors.New("invalid signed owner plan")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("invalid signed owner plan")
	}
	settings, err := config.Load()
	if err != nil || settings.DatabaseType != config.DatabaseSQLite || settings.DeploymentMode != config.DeploymentStorage {
		return errors.New("owner import requires existing SQLite storage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	db, err := sqlitestore.OpenReadOnly(ctx, settings.SQLitePath)
	if err != nil {
		return err
	}
	defer db.Close()
	receipt, err := node.ImportLegacyOwnerOffline(ctx, gate, settings.DataRoot, settings.SQLitePath, settings.SecretsDirectory, db.Database(), request.Plan, request.Signature)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(receipt)
}
