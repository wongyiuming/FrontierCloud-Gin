package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
)

type dockerRunner struct{ Directory string }
type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		b.exceeded = true
		return 0, operator.ErrDockerOutputLimit
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

// RunDuplex gives an internal protocol exclusive use of the child pipes. It
// never logs stderr or payload. Container identity/cleanup is the caller's
// responsibility; killing Docker CLI alone is not proof of container exit.
func (d dockerRunner) RunDuplex(ctx context.Context, name string, args []string, exchange func(io.WriteCloser, *bufio.Reader) error) error {
	if ctx == nil || exchange == nil {
		return errors.New("invalid Docker streaming operation")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("Docker streaming requires a deadline")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = d.Directory
	cmd.Stderr = io.Discard
	input, e := cmd.StdinPipe()
	if e != nil {
		return errors.New("Docker streaming setup failed")
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		input.Close()
		return errors.New("Docker streaming setup failed")
	}
	if e = cmd.Start(); e != nil {
		input.Close()
		output.Close()
		return errors.New("Docker streaming start failed")
	}
	defer func() {
		_ = input.Close()
		_ = output.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	// A descendant may retain the pipe even after CommandContext kills the
	// CLI. Closing our ends on cancellation also unblocks protocol reads.
	stopClose := context.AfterFunc(ctx, func() {
		_ = input.Close()
		_ = output.Close()
	})
	defer stopClose()
	buffered := bufio.NewReaderSize(output, 4096)
	exchangeErr := exchange(input, buffered)
	_ = input.Close()
	if exchangeErr != nil {
		_ = cmd.Process.Kill()
	}
	var extra [1]byte
	n, readErr := buffered.Read(extra[:])
	_ = output.Close()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if exchangeErr != nil || n != 0 || readErr != io.EOF || waitErr != nil {
		return errors.New("Docker bidirectional operation failed; output was not logged")
	}
	return nil
}

func (d dockerRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return d.RunEnv(ctx, nil, name, args...)
}
func (d dockerRunner) RunEnv(ctx context.Context, environment map[string]string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = d.Directory
	if environment != nil {
		for _, entry := range os.Environ() {
			if _, override := environment[strings.SplitN(entry, "=", 2)[0]]; !override {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		for key, value := range environment {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	var out limitedBuffer
	cmd.Stdout = &out
	// Arbitrary Docker errors may contain credentials or signed URLs. Only
	// bounded structured facts leave the client; stderr is never a report.
	var diagnostic limitedBuffer
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		category := operator.ClassifyDockerFailure(diagnostic.String())
		if ctx.Err() == context.DeadlineExceeded {
			category = operator.ErrDockerTimeout
		} else if ctx.Err() != nil {
			category = operator.ErrDockerCanceled
		} else if out.exceeded || diagnostic.exceeded {
			category = operator.ErrDockerOutputLimit
		}
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		return nil, &operator.CommandFailure{Category: category, ExitCode: exitCode}
	}
	return out.Bytes(), nil
}
