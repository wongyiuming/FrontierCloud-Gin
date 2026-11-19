//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func treeRetainedRecovery(context.Context, io.Reader, io.Writer, [2]string) error {
	return errors.New("native retained tree recovery requires Linux")
}
