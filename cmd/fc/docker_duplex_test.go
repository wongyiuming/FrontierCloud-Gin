package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDuplexChildProcess(t *testing.T) {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[len(os.Args)-1], "duplex-child-") {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "duplex-child-grandchild" {
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}
	_, _ = io.WriteString(os.Stdout, "ready\n")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	switch mode {
	case "duplex-child-extra":
		_, _ = io.WriteString(os.Stdout, "result\nextra")
	case "duplex-child-fail":
		_, _ = io.WriteString(os.Stdout, "result\n")
		os.Exit(3)
	case "duplex-child-wait":
		_, _ = io.Copy(io.Discard, os.Stdin)
		select {}
	case "duplex-child-orphan":
		child := exec.Command(os.Args[0], "-test.run=^TestDuplexChildProcess$", "--", "duplex-child-grandchild")
		child.Stdout = os.Stdout
		if child.Start() != nil {
			os.Exit(4)
		}
		_, _ = io.WriteString(os.Stdout, "result\n")
	default:
		_, _ = io.WriteString(os.Stdout, "result\n")
	}
	os.Exit(0)
}

func TestDockerDuplexBoundsAndFailures(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	runner := dockerRunner{}
	for _, mode := range []string{"ok", "extra", "fail", "wait", "abort"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			childMode := mode
			if mode == "abort" {
				childMode = "wait"
			}
			err := runner.RunDuplex(ctx, os.Args[0], []string{"-test.run=^TestDuplexChildProcess$", "--", "duplex-child-" + childMode}, func(in io.WriteCloser, out *bufio.Reader) error {
				line, err := out.ReadString('\n')
				if err != nil || line != "ready\n" {
					return errors.New("unexpected ready")
				}
				if mode == "abort" {
					return errors.New("secret-must-not-escape")
				}
				if _, err := io.WriteString(in, "request\n"); err != nil {
					return err
				}
				if mode == "wait" {
					_, err = out.ReadString('\n')
					return err
				}
				line, err = out.ReadString('\n')
				if err != nil || line != "result\n" {
					return errors.New("unexpected response")
				}
				return nil
			})
			if mode == "ok" && err != nil || mode != "ok" && err == nil {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-must-not-escape") {
				t.Fatal("callback detail leaked")
			}
			if mode == "wait" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline not honored: %v", err)
			}
		})
	}
	if err := runner.RunDuplex(context.Background(), os.Args[0], nil, func(io.WriteCloser, *bufio.Reader) error { return nil }); err == nil {
		t.Fatal("missing deadline accepted")
	}
	// The direct child can exit while a descendant still owns stdout. The
	// deadline must close our read end instead of waiting for that descendant.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exchanged := false
	err := runner.RunDuplex(ctx, os.Args[0], []string{"-test.run=^TestDuplexChildProcess$", "--", "duplex-child-orphan"}, func(in io.WriteCloser, out *bufio.Reader) error {
		if line, e := out.ReadString('\n'); e != nil || line != "ready\n" {
			return errors.New("unexpected ready")
		}
		if _, e := io.WriteString(in, "request\n"); e != nil {
			return e
		}
		if line, e := out.ReadString('\n'); e != nil || line != "result\n" {
			return errors.New("unexpected response")
		}
		exchanged = true
		return nil
	})
	if !exchanged || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("inherited pipe did not respect deadline: %v", err)
	}
	// Allow the synthetic grandchild to exit normally before fixture cleanup.
	time.Sleep(1500 * time.Millisecond)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("callback panic was suppressed")
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = runner.RunDuplex(ctx, os.Args[0], []string{"-test.run=^TestDuplexChildProcess$", "--", "duplex-child-wait"}, func(io.WriteCloser, *bufio.Reader) error {
			panic("fixture panic")
		})
	}()
}
