//go:build !linux

package sealedtree

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

// Existing business-tree initialization has no supported non-Linux fence.
func InitializeExistingSQLiteOffline(context.Context, config.Config, *maintenance.Gate, *Tree, string, string) error {
	return ErrLegacyWritersUnfenced
}

func PrepareEmptyMasterSQLite(context.Context, config.Config, *maintenance.Gate, string) error {
	return ErrFenceRequired
}
