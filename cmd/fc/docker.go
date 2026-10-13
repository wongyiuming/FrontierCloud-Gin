package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

type dockerRunner struct{ Directory string }
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("command output exceeded limit")
	}
	return b.Buffer.Write(p)
}

func (d dockerRunner) RunTo(ctx context.Context, output io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = d.Directory
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return errors.New("Docker streaming command failed; secret-bearing output was not logged")
	}
	return nil
}

func (d dockerRunner) RunFrom(ctx context.Context, input io.Reader, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = d.Directory
	cmd.Stdin = input
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return errors.New("Docker input-stream command failed; credentials and SQL were not logged")
	}
	return nil
}
func (d dockerRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = d.Directory
	var out limitedBuffer
	cmd.Stdout = &out
	// Arbitrary Docker errors may contain credentials or signed URLs. Only
	// bounded structured facts leave the client; stderr is never a report.
	var diagnostic limitedBuffer
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		return nil, operator.ClassifyDockerFailure(diagnostic.String())
	}
	return out.Bytes(), nil
}
