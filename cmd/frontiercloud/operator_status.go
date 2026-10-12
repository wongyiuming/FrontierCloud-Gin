package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func operatorStatusCommand(output io.Writer) error {
	settings, err := config.Load()
	if err != nil {
		return err
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
	snapshot, err := db.Maintenance().InspectMaintenance(ctx)
	if err != nil {
		return err
	}
	result := operator.RuntimeFact{NodeID: identity.ID, Role: identity.Role, Database: snapshot, Nodes: []operator.NodeFact{}}
	// Existence is enough to observe fail-closed maintenance. No lock inode is
	// created and no flag is removed/repaired by a status query.
	for _, flag := range []string{sitecontrol.Manual, maintenance.Marker} {
		_, e := os.Lstat(filepath.Join(settings.DataRoot, flag))
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e == nil {
			result.Maintenance = true
			if flag == maintenance.Marker {
				result.NativeMaintenance = true
			}
		}
	}
	relations, err := db.Nodes().Relationships(ctx, false)
	if err != nil {
		return err
	}
	for _, r := range relations {
		result.Nodes = append(result.Nodes, operator.NodeFact{NodeID: r.PeerID, Direction: r.Direction, State: r.State, Health: r.Status, LastHeartbeat: r.LastHeartbeat, Protocol: r.Protocol})
	}
	return json.NewEncoder(output).Encode(result)
}
