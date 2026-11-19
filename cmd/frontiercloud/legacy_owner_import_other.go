//go:build !linux

package main

import (
	"errors"
	"io"
)

func legacyOwnerImportCommand([]string, io.Reader, io.Writer) error {
	return errors.New("legacy Owner import requires Linux")
}
