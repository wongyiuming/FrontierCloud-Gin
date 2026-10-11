package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certedge"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return errors.New("TLS edge accepts initialize, watch or security only")
	}
	enabled, err := strconv.ParseBool(value("TLS_ENABLED", "false"))
	if err != nil {
		return errors.New("invalid TLS_ENABLED")
	}
	for key, standard := range map[string]string{"HTTP_PORT": "80", "HTTPS_PORT": "443"} {
		if raw := os.Getenv(key); raw != "" && raw != standard {
			return errors.New("HTTP/HTTPS public ports are fixed at 80/443")
		}
	}
	execute := func(ctx context.Context, args ...string) error {
		if !(len(args) == 1 && args[0] == "-t" || len(args) == 2 && args[0] == "-s" && args[1] == "reload") {
			return errors.New("Nginx control argument refused")
		}
		// Fixed executable and fixed arguments, with bounded execution and no output
		// containing certificate material. No host service or Docker API is used.
		return exec.CommandContext(ctx, "/usr/sbin/nginx", args...).Run()
	}
	edge := certedge.New(strings.ToLower(strings.TrimSpace(value("SERVER_NAME", "localhost"))), enabled, os.Getenv("PUBLIC_BIND_ADDRESS") == "::", execute)
	switch os.Args[1] {
	case "initialize":
		return edge.Initialize()
	case "security":
		return edge.SecurityUpdate()
	case "watch":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		edge.Watch(ctx)
		return nil
	}
	return errors.New("unknown TLS edge command")
}
func value(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
