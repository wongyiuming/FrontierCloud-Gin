//go:build !linux

package main

import (
	"errors"
	"io"
)

func resumeBusinessStateCommand([]string, io.Writer) error {
	return errors.New("business state resume requires Linux mount identity verification")
}
