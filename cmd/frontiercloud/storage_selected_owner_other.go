//go:build !linux

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

func installStorageSelectedOwner(config.Config, runtimeHTTP, *gin.Engine) error { return nil }
