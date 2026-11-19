//go:build !linux

package main

import (
	"errors"
	"io"
)

func prepareBusinessStateCommand([]string, io.Writer) error {
	return errors.New("business state preparation requires Linux mount identity verification")
}
