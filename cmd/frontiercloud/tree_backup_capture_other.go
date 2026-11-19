//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func treeBackupCapture(context.Context, io.Reader, io.Writer, [3]string) error {
	return errors.New("native tree capture requires Linux")
}
