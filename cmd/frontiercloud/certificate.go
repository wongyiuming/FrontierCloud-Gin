package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

// Compose runs this bounded certificate process in its own container.
// It has no business database, Docker access, shell or host service control.
func certificateAgentCommand(args []string) error {
	f := flag.NewFlagSet("certificate-agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	host := f.String("hostname", "", "fixed storage hostname")
	directory := f.String("directory", "", "private persistent TLS state directory")
	socket := f.String("socket", "", "private Unix control socket")
	ca := f.String("acme-directory", certificate.ProductionDirectory, "approved production or staging ACME directory")
	email := f.String("email", "", "ACME contact email")
	httpDirectory := f.String("http01-directory", "", "fixed existing public HTTP-01 challenge directory")
	container := f.Bool("container", false, "share TLS with read-only storage group")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid certificate agent options")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	issue, e := certificate.ACME(*host, *directory, *ca, *email)
	if e != nil {
		return e
	}
	open := certificate.Open
	if *container {
		if os.Geteuid() != 0 || os.Getegid() != 10001 {
			return errors.New("certificate container requires root with storage group 10001")
		}
		if e := requireCertificateVolumes(); e != nil {
			return e
		}
		open = certificate.OpenContainer
	}
	agent, e := open(ctx, *host, *directory, ":80", issue)
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

// The exiting initializer only owns these explicitly mounted Docker volumes.
func initializeCertificateVolumes(args []string) error {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("certificate volume initializer requires root and no arguments")
	}
	if e := requireCertificateVolumes(); e != nil {
		return e
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{"/var/lib/frontiercloud-certificate", 0750},
		{"/run/frontiercloud-certificate", 0710},
		{"/run/frontiercloud-http01", 0755},
	} {
		if e := os.MkdirAll(entry.path, entry.mode); e != nil {
			return e
		}
		info, e := os.Lstat(entry.path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe certificate volume")
		}
		if e = os.Chown(entry.path, 0, 10001); e != nil {
			return e
		}
		if e = os.Chmod(entry.path, entry.mode); e != nil {
			return e
		}
	}
	return nil
}

func requireCertificateVolumes() error {
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return errors.New("certificate command requires Linux container volumes")
	}
	for _, path := range []string{"/var/lib/frontiercloud-certificate", "/run/frontiercloud-certificate", "/run/frontiercloud-http01"} {
		found := false
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 5 && fields[4] == path {
				found = true
				break
			}
		}
		if !found {
			return errors.New("certificate command requires all three isolated volume mounts")
		}
	}
	return nil
}

func certificateHealthcheck() error {
	_, e := queryCertificateContainerStatus()
	return e
}

func certificateContainerStatus(output io.Writer) error {
	v, e := queryCertificateContainerStatus()
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(v)
}

func queryCertificateContainerStatus() (certificate.View, error) {
	host := os.Getenv("SERVER_NAME")
	if !certificate.Hostname(host) {
		return certificate.View{}, errors.New("invalid certificate container hostname")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return (certificate.UnixClient{Socket: "/run/frontiercloud-certificate/control.sock", Hostname: host}).Control(ctx, certificate.Request{Action: "status"})
}
