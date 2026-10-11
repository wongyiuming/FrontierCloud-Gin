package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

// The host operator provisions this small unprivileged control service once.
// It has no business database, Docker access, shell execution or permanent HTTP port.
func certificateAgentCommand(args []string) error {
	f := flag.NewFlagSet("certificate-agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	host := f.String("hostname", "", "fixed storage hostname")
	directory := f.String("directory", "", "private persistent TLS state directory")
	socket := f.String("socket", "", "private Unix control socket")
	ca := f.String("acme-directory", certificate.ProductionDirectory, "approved production or staging ACME directory")
	email := f.String("email", "", "ACME contact email")
	httpDirectory := f.String("http01-directory", "", "fixed existing public HTTP-01 challenge directory")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid certificate agent options")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	issue, e := certificate.ACME(*host, *directory, *ca, *email)
	if e != nil {
		return e
	}
	agent, e := certificate.Open(ctx, *host, *directory, ":80", issue)
	if e != nil {
		return e
	}
	defer agent.Close()
	if *httpDirectory != "" {
		if e = agent.UseHTTP01Directory(*httpDirectory); e != nil {
			return e
		}
	}
	return agent.Serve(*socket)
}
