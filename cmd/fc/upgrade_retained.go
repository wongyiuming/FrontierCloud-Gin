package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

const retainedUpgradeEnvironment = "FOC_RETAINED_UPGRADE_GENERATION"

func dispatchRetainedUpgrade(ctx context.Context, directory, revision string, args []string, input io.Reader, out, diagnostic io.Writer, structured bool, generation int, home string) (bool, int) {
	d, r, err := operator.Open(directory)
	if err != nil {
		return false, 0
	}
	target, pendingGeneration, err := d.PendingUpgradeRouting(r)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return true, 2
	}
	if target == "" || pendingGeneration == generation {
		return false, 0
	}
	if revision != "" && revision != target {
		fmt.Fprintln(diagnostic, "unfinished upgrade has a different target; preserve its journal")
		return true, 2
	}
	for _, path := range []string{home, filepath.Join(home, "backends"), filepath.Join(home, "backends", "g"+strconv.Itoa(pendingGeneration))} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintln(diagnostic, "matching retained operator unavailable; pending upgrade and global tool unchanged")
			return true, 2
		}
	}
	marker, err := os.ReadFile(filepath.Join(home, ".managed"))
	if err != nil || string(marker) != "frontiercloud-foc-v2\n" {
		fmt.Fprintln(diagnostic, "retained operator ownership cannot be verified")
		return true, 2
	}
	path := filepath.Join(home, "backends", "g"+strconv.Itoa(pendingGeneration), "fc")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintln(diagnostic, "matching retained operator unavailable; pending upgrade and global tool unchanged")
		return true, 2
	}
	probe := func(command string) (string, error) {
		raw, err := exec.CommandContext(ctx, path, command).Output()
		return strings.TrimSpace(string(raw)), err
	}
	actual, err := probe("operator-generation")
	if err != nil || actual != strconv.Itoa(pendingGeneration) {
		fmt.Fprintln(diagnostic, "retained operator generation mismatch; pending upgrade unchanged")
		return true, 2
	}
	actual, err = probe("version")
	if err != nil || !release.ValidSHA(actual) {
		fmt.Fprintln(diagnostic, "retained operator version cannot be verified")
		return true, 2
	}
	childArgs := []string{"--directory", d.Directory, "--revision", target}
	if structured {
		childArgs = append(childArgs, "--json")
	}
	childArgs = append(childArgs, args...)
	if _, err = fmt.Fprintf(diagnostic, "Continuing recorded generation %d with its retained operator; global tool retained.\n", pendingGeneration); err != nil {
		return true, 2
	}
	return true, runOperatorBackend(ctx, path, childArgs, input, out, diagnostic, map[string]string{retainedUpgradeEnvironment: strconv.Itoa(pendingGeneration)})
}

func retainedUpgradeMode(d *operator.Deployment, r operator.Receipt, target string, generation int) (bool, error) {
	value := os.Getenv(retainedUpgradeEnvironment)
	if value == "" {
		return false, nil
	}
	pending, planGeneration, err := d.PendingUpgradeRouting(r)
	if err != nil {
		return false, err
	}
	if value != strconv.Itoa(generation) || planGeneration != generation || pending != target || pending == "" {
		return false, errors.New("retained operator may only finish its matching pending upgrade")
	}
	return true, nil
}
