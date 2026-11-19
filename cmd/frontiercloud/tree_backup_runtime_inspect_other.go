//go:build !linux

package main

import (
	"errors"
	"io"
)

func treeBackupRuntimeInspect(_ []string, _ io.Writer) error {
	return errors.New("tree backup runtime inspection requires Linux")
}
