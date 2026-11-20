//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

func prepareFreshEncryptedRuntime(context.Context, config.Config, *maintenance.Gate) error {
	return errors.New("fresh encrypted deployment requires Linux")
}
