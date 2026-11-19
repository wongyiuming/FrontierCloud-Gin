//go:build !linux

package main

import (
	"context"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func prepareSealedS3Control(context.Context, config.Config, *maintenance.Gate, string) error {
	return store.ErrNodeState
}

func sealedS3PrepareCommand([]string, io.Writer) error { return store.ErrNodeState }
