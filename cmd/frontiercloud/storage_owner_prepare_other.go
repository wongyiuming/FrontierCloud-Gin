//go:build !linux

package main

import (
	"context"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func storageOwnerPrepareCommand([]string, io.Writer) error {
	return errors.New("storage-owner-prepare requires Linux")
}

func prepareEmptyOwner(context.Context, config.Config, *maintenance.Gate, string, string) error {
	return errors.New("owner preparation requires Linux")
}
