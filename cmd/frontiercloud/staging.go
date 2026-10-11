package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func stagingReleaseCommand(output io.Writer) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if !settings.StagingCD {
		return errors.New("staging-release is forbidden outside the dedicated staging deployment")
	}
	return guardedCommand(settings, func(parent context.Context) error {
		ctx, cancel := context.WithTimeout(parent, 20*time.Second)
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
		if identity.Role != "Master" || identity.Endpoint != "https://www4399.sbs" {
			return store.ErrNodeState
		}
		agent := release.SocketAgent{}
		status := release.AgentStatus(ctx, agent)
		if status["staging_cd"] != true || status["release_branch"] != "main" || release.Busy(status["state"]) || status["state"] == "unavailable" || status["state"] == "failed" {
			return errors.New("staging updater unavailable, busy or failed")
		}
		verifier, err := release.NewVerifier(release.DefaultPolicy(), settings.GitHubAPIToken)
		if err != nil {
			return err
		}
		target, err := verifier.DevelopmentHead(ctx)
		if err != nil {
			return err
		}
		if target == status["current_sha"] {
			return json.NewEncoder(output).Encode(map[string]any{"changed": false, "sha": target})
		}
		current, err := db.Nodes().ReadIdentity(ctx)
		if err != nil {
			return err
		}
		if current.ID != identity.ID || current.Role != "Master" {
			return store.ErrNodeState
		}
		value, err := agent.Request(ctx, map[string]any{"action": "start", "mode": "upgrade", "target_sha": target, "hold_maintenance": false})
		if err != nil {
			return err
		}
		if value["ok"] != true {
			return errors.New("staging updater rejected deployment")
		}
		return json.NewEncoder(output).Encode(value)
	})
}
