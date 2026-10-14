package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

func composeRegisterCommand(ctx context.Context, directory string, diagnostic io.Writer) int {
	e := registerCompose(ctx, directory)
	if e != nil {
		fmt.Fprintln(diagnostic, "foc: automatic Compose registration failed:", e)
		return 2
	}
	fmt.Fprintln(diagnostic, "foc: verified and registered the current Compose deployment")
	return 0
}

func registerCompose(ctx context.Context, directory string) error {
	root, e := filepath.Abs(directory)
	if e != nil {
		return e
	}
	runner := dockerRunner{root}
	raw, e := runner.Run(ctx, "docker", "ps", "--all", "--filter", "label=com.docker.compose.project.working_dir="+root, "--filter", "label=frontiercloud.foc-bootstrap=1", "--format", "{{.ID}}")
	ids := strings.Fields(string(raw))
	if e != nil || len(ids) != 1 {
		return errors.New("one standard Compose foc installer is required for the selected directory")
	}
	raw, e = runner.Run(ctx, "docker", "inspect", "--format", "{{json .Config.Labels}}", ids[0])
	var labels map[string]string
	if e != nil || json.Unmarshal(raw, &labels) != nil || labels["frontiercloud.foc-bootstrap"] != "1" || filepath.Clean(labels["com.docker.compose.project.working_dir"]) != root {
		return errors.New("invalid Compose installer identity")
	}
	files := strings.Split(labels["com.docker.compose.project.config_files"], ",")
	role, database := "master", "sqlite"
	for i, file := range files {
		if filepath.Dir(filepath.Clean(file)) != root {
			return errors.New("Compose file lies outside the selected deployment directory")
		}
		files[i] = filepath.Base(file)
	}
	if len(files) == 1 && files[0] == "docker-compose.storage.yaml" {
		role = "storage"
	} else if len(files) == 2 && (files[0] == "docker-compose.yaml" || files[0] == "docker-compose.gin.yaml") && files[1] == "docker-compose.gin-mysql.yaml" {
		database = "mysql"
	} else if len(files) != 1 || files[0] != "docker-compose.yaml" && files[0] != "docker-compose.gin.yaml" {
		return errors.New("automatic registration requires the standard Master or Storage Compose selection")
	}
	d, e := operator.New(root, role, database)
	if e != nil {
		return e
	}
	d.Files = files
	d.Project = labels["com.docker.compose.project"]
	d.Runner = runner
	raw, e = runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil {
		return e
	}
	verifier, e := hostReleaseVerifier()
	if e != nil {
		return e
	}
	images := release.NewRegistryClient()
	defer images.Close()
	_, e = d.RegisterCompose(ctx, operator.Architecture(string(raw)), verifier, images)
	return e
}
