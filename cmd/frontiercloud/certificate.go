package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certmanager"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

// Compose runs this bounded certificate process in its own container.
// It has no business database, Docker access, shell or host service control.
func certificateAgentCommand(args []string) error {
	if len(args) != 0 {
		return errors.New("certificate-agent accepts no options; TLS_ENABLED controls automatic TLS")
	}
	settings, e := config.Load()
	if e != nil {
		return e
	}
	if os.Geteuid() != 0 || os.Getegid() != 10001 {
		return errors.New("certificate controller requires root with group 10001")
	}
	if e = requireCertificateVolumes(); e != nil {
		return e
	}
	profile := certmanager.Business
	if settings.DeploymentMode == config.DeploymentStorage {
		profile = certmanager.Profile(settings.StorageTransport)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	manager, e := certmanager.New(ctx, settings.ServerName, settings.TLSEnabled, profile, settings.StoragePort)
	if e != nil {
		return e
	}
	defer manager.Close()
	return manager.Serve()
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
		{certmanager.PrivateDirectory, 0700},
		{certmanager.RuntimeDirectory, 0710},
		{certmanager.PublishedDirectory, 0750},
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
	for _, path := range []string{certmanager.PrivateDirectory, certmanager.PublishedDirectory, certmanager.RuntimeDirectory} {
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
	v, e := queryCertificateContainerStatus()
	if e == nil && !v.ControllerRunning {
		return errors.New("certificate controller not running")
	}
	return e
}

func certificateContainerStatus(output io.Writer) error {
	return certificateContainerAction("status", output)
}

func certificateContainerRenew(output io.Writer) error {
	return errors.New("manual renewal is retired; TLS_ENABLED enables automatic renewal")
}

func certificateContainerAction(action string, output io.Writer) error {
	v, e := queryCertificateContainer(action)
	if e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(v)
}

func queryCertificateContainerStatus() (certificate.View, error) {
	return queryCertificateContainer("status")
}

func queryCertificateContainer(action string) (certificate.View, error) {
	settings, e := config.Load()
	if e != nil {
		return certificate.View{}, e
	}
	host := settings.ServerName
	if settings.TLSEnabled && !certificate.Hostname(host) {
		return certificate.View{}, errors.New("invalid certificate container DNS/IP identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return (certificate.UnixClient{Socket: certmanager.ControlSocket, Hostname: host}).Control(ctx, certificate.Request{Action: action})
}
