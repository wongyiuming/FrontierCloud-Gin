//go:build !linux

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func installSealedMasterRuntime(config.Config, runtimeHTTP, *gin.Engine, *httpapi.Public, *httpapi.Admin, *httpapi.KaraokeAccounts) error {
	return store.ErrNodeState
}
