//go:build !linux

package main

import (
	"errors"
	"io"
)

func importBusinessStateCommand([]string, io.Reader, io.Writer) error {
	return errors.New("business state import requires Linux mount identity verification")
}
