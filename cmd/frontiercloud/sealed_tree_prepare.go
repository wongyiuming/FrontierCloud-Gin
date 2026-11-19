package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func sealedTreePrepareCommand(args []string, output io.Writer) error {
	if len(args) != 1 || output == nil {
		return errors.New("sealed-tree-prepare requires the expected existing Master ID")
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	if info, err := os.Lstat(settings.DataRoot); err != nil || !info.IsDir() {
		return errors.New("sealed-tree-prepare requires an existing deployment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gate, err := maintenance.Open(settings.DataRoot)
	if err != nil {
		return err
	}
	defer gate.Close()
	if err := prepareSealedTree(ctx, settings, gate, args[0], ctx.Err); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Prepared bool `json:"prepared"`
	}{Prepared: true})
}

func prepareSealedTree(ctx context.Context, settings config.Config, gate *maintenance.Gate, masterID string, check func() error) error {
	for _, prepare := range []func() error{
		func() error { return prepareEmptyOwner(ctx, settings, gate, masterID, "Master") },
		func() error { return sealedtree.PrepareEmptyMasterSQLite(ctx, settings, gate, masterID) },
		func() error { return prepareSealedS3Control(ctx, settings, gate, masterID) },
	} {
		if err := check(); err != nil {
			return err
		}
		if err := prepare(); err != nil {
			return err
		}
	}
	return check()
}
