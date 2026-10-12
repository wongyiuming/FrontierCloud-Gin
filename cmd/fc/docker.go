package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
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
		message := strings.ToLower(diagnostic.String())
		for _, word := range []string{"permission denied", "unauthorized", "access denied", "denied:"} {
			if strings.Contains(message, word) {
				return nil, errors.New("Docker access denied; check daemon permissions and public package access")
			}
		}
		for _, word := range []string{"manifest unknown", "no such image"} {
			if strings.Contains(message, word) {
				return nil, errors.New("requested image is absent; select a complete published release")
			}
		}
		for _, word := range []string{"no matching manifest", "unsupported platform"} {
			if strings.Contains(message, word) {
				return nil, errors.New("published image does not support this architecture")
			}
		}
		for _, word := range []string{"digest", "checksum"} {
			if strings.Contains(message, word) {
				return nil, errors.New("image content integrity check failed; do not deploy")
			}
		}
		for _, word := range []string{"timeout", "connection refused", "network", "tls handshake", "x509:", "no such host"} {
			if strings.Contains(message, word) {
				return nil, errors.New("Docker network or TLS connection failed; check DNS, registry and certificate trust")
			}
		}
		return nil, errors.New("Docker command failed; check daemon permissions, network and selected project")
	}
	return out.Bytes(), nil
}
