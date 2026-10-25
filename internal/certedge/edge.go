// Package certedge controls only local Nginx TLS configuration. Its caller can
// execute exactly nginx -t or nginx -s reload; it has no container/host control.
package certedge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
)

const Directory = "/run/frontiercloud-tls"
const Runtime = "/etc/nginx/runtime"

type Edge struct {
	Host    string
	IPv6    bool
	Enabled bool
	Execute func(context.Context, ...string) error
	// Fixed in the executable; only package tests inject fixture paths/trust.
	config, runtime, published string
	roots                      *x509.CertPool
}

func New(host string, enabled, ipv6 bool, execute func(context.Context, ...string) error) *Edge {
	return &Edge{Host: host, Enabled: enabled, IPv6: ipv6, Execute: execute, config: "/etc/nginx/nginx.conf", runtime: Runtime, published: Directory}
}

// Ready checks the actual local listener, independently of controller liveness.
// Compose can keep the restricted bootstrap running without reporting TLS ready.
func (e *Edge) Ready(ctx context.Context) error {
	port := "80"
	if e.Enabled {
		port = "443"
	}
	if err := e.readyAt(ctx, net.JoinHostPort("127.0.0.1", port)); err != nil {
		return err
	}
	if e.Enabled {
		return e.readyAt(ctx, net.JoinHostPort(e.Host, port))
	}
	return nil
}
func (e *Edge) readyAt(ctx context.Context, address string) error {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if !e.Enabled {
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			connection.Close()
		}
		return err
	}
	generation, err := e.generation()
	if err != nil {
		return err
	}
	cert, err := read(filepath.Join(e.published, generation, "fullchain.pem"), 65536)
	if err != nil {
		return err
	}
	key, err := read(filepath.Join(e.published, generation, "privkey.pem"), 16384)
	if err != nil {
		return err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) == 0 {
		return errors.New("managed TLS pair unavailable")
	}
	connection, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: e.Host, RootCAs: e.roots, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	served := connection.(*tls.Conn).ConnectionState().PeerCertificates
	if len(served) == 0 || sha256.Sum256(served[0].Raw) != sha256.Sum256(pair.Certificate[0]) {
		return errors.New("Nginx is not serving the managed TLS generation")
	}
	return nil
}

var id = regexp.MustCompile(`^[a-f0-9]{32}$`)
var files = []string{"extra-servers.conf", "public-tls.conf"}

func read(path string, max int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Nginx TLS asset is not a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errors.New("Nginx TLS asset changed during read")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("Nginx TLS asset oversized")
	}
	return b, e
}
func write(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".tls-next-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0644); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}
func (e *Edge) lease() (func(), error) {
	f, err := os.OpenFile(filepath.Join(e.runtime, "tls-reload.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return filelease.Try(f, true)
}
func (e *Edge) generation() (string, error) {
	b, err := read(filepath.Join(e.published, "current.json"), 256)
	if err != nil {
		return "", err
	}
	var pointer struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(b, &pointer) != nil || !id.MatchString(pointer.Generation) {
		return "", errors.New("invalid managed TLS generation")
	}
	dir := filepath.Join(e.published, pointer.Generation)
	cert, err := read(filepath.Join(dir, "fullchain.pem"), 65536)
	if err != nil {
		return "", err
	}
	key, err := read(filepath.Join(dir, "privkey.pem"), 16384)
	if err != nil {
		return "", err
	}
	p, err := tls.X509KeyPair(cert, key)
	if err != nil || len(p.Certificate) == 0 || len(p.Certificate) > 8 {
		return "", errors.New("managed TLS pair mismatch")
	}
	leaf, err := x509.ParseCertificate(p.Certificate[0])
	if err != nil {
		return "", err
	}
	intermediates := x509.NewCertPool()
	for _, der := range p.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", err
		}
		intermediates.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: e.Host, Roots: e.roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return "", errors.New("managed TLS chain, DNS/IP identity or validity verification failed")
	}
	return pointer.Generation, nil
}
func (e *Edge) Initialize() error {
	if !e.Enabled {
		return nil
	}
	identity, err := certificate.NormalizeSubject(e.Host)
	if err != nil {
		return errors.New("automatic Nginx TLS requires a DNS hostname or public IP address")
	}
	e.Host = identity
	if err := os.MkdirAll(e.runtime, 0755); err != nil {
		return err
	}
	for _, file := range append([]string{"business.conf"}, files...) {
		path := filepath.Join(e.runtime, file)
		if file == "business.conf" {
			path = e.config
		}
		b, err := read(path, 1<<20)
		if err != nil {
			return err
		}
		b = canonicalServerNames(b, e.Host)
		if err = write(filepath.Join(e.runtime, file+".automatic-template"), b); err != nil {
			return err
		}
	}
	generation, err := e.generation()
	if err != nil {
		return write(e.config, []byte(e.bootstrap()))
	}
	return e.selectGeneration(generation)
}

var serverNameDirective = regexp.MustCompile(`(?m)(\bserver_name[ \t]+)([^;\r\n]+)(;)`)

func canonicalServerNames(body []byte, identity string) []byte {
	if !certificate.IsIP(identity) {
		return body
	}
	return serverNameDirective.ReplaceAllFunc(body, func(line []byte) []byte {
		parts := serverNameDirective.FindSubmatch(line)
		value := strings.TrimSpace(string(parts[2]))
		canonical, err := certificate.NormalizeSubject(strings.Trim(value, "[]"))
		if err != nil || canonical != identity {
			return line
		}
		if strings.Contains(identity, ":") {
			canonical = "[" + identity + "]"
		}
		return []byte(string(parts[1]) + canonical + ";")
	})
}
func (e *Edge) bootstrap() string {
	ipv6 := ""
	if e.IPv6 {
		ipv6 = "listen [::]:80;"
	}
	host := e.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf(`user nginx frontiercloud-media;
worker_processes 1;
error_log /dev/stderr warn;
pid /var/run/nginx.pid;
events { worker_connections 128; }
http {
 server_tokens off;
 access_log off;
 server {
  listen 80; %s
  server_name %s;
  client_max_body_size 0;
  location ^~ /.well-known/acme-challenge/ {
   proxy_pass http://certificate-agent:80;
   proxy_set_header Host $host;
   proxy_connect_timeout 2s;
   proxy_read_timeout 3s;
   proxy_send_timeout 3s;
   add_header Cache-Control "no-store" always;
  }
  location / { return 444; }
 }
}
`, ipv6, host)
}
func (e *Edge) selectGeneration(generation string) error {
	if !id.MatchString(generation) {
		return errors.New("invalid generation")
	}
	for _, file := range files {
		template, err := read(filepath.Join(e.runtime, file+".automatic-template"), 1<<20)
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(template), "/etc/nginx/certs/fullchain.pem", filepath.Join(e.published, generation, "fullchain.pem"))
		text = strings.ReplaceAll(text, "/etc/nginx/certs/privkey.pem", filepath.Join(e.published, generation, "privkey.pem"))
		if err = write(filepath.Join(e.runtime, file), []byte(text)); err != nil {
			return err
		}
	}
	body, err := read(filepath.Join(e.runtime, "business.conf.automatic-template"), 1<<20)
	if err != nil {
		return err
	}
	return write(e.config, body)
}
func (e *Edge) command(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return e.Execute(ctx, args...)
}
func (e *Edge) Apply() error {
	if !e.Enabled {
		return nil
	}
	generation, err := e.generation()
	if err != nil {
		return err
	}
	release, err := e.lease()
	if err != nil {
		return err
	}
	defer release()
	marker := filepath.Join(e.runtime, "tls-applied")
	if b, err := read(marker, 33); err == nil && string(b) == generation {
		return nil
	}
	old := map[string][]byte{}
	for _, path := range append([]string{e.config}, filepath.Join(e.runtime, files[0]), filepath.Join(e.runtime, files[1])) {
		old[path], err = read(path, 1<<20)
		if err != nil {
			return err
		}
	}
	rollback := func() error {
		var result error
		for path, b := range old {
			result = errors.Join(result, write(path, b))
		}
		if result != nil {
			return errors.New("Nginx configuration recovery could not be persisted; running certificate retained")
		}
		return nil
	}
	if err = e.selectGeneration(generation); err != nil {
		return errors.Join(err, rollback())
	}
	if err = e.command("-t"); err != nil {
		return errors.Join(errors.New("Nginx configuration validation failed; previous TLS retained"), rollback())
	}
	if err = e.command("-s", "reload"); err != nil {
		return errors.Join(errors.New("Nginx graceful reload failed; previous TLS retained"), rollback())
	}
	return write(marker, []byte(generation))
}
func (e *Edge) SecurityUpdate() error {
	release, err := e.lease()
	if err != nil {
		return err
	}
	defer release()
	rules := filepath.Join(e.runtime, "ip-security.conf")
	old, err := read(rules, 2<<20)
	if err != nil {
		return err
	}
	next, err := read(filepath.Join(e.runtime, "ip-security.candidate"), 2<<20)
	if err != nil {
		return err
	}
	if err = write(rules, next); err != nil {
		return err
	}
	if err = e.command("-t"); err == nil {
		err = e.command("-s", "reload")
	}
	if err != nil {
		_ = write(rules, old)
		return errors.New("Nginx rejected IP security update; previous rules retained")
	}
	return nil
}
func (e *Edge) Watch(ctx context.Context) {
	if !e.Enabled {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var previous string
	var reported time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := read("/var/run/nginx.pid", 32); err != nil {
				continue
			}
			err := e.Apply()
			if err == nil {
				previous = ""
				continue
			}
			// Bound repeated diagnostics while preserving the last working
			// configuration. No paths, certificate bytes or keys are logged.
			code := "tls_apply_failed"
			if strings.HasPrefix(err.Error(), "Nginx configuration validation failed") {
				code = "nginx_validation"
			}
			if strings.HasPrefix(err.Error(), "Nginx graceful reload failed") {
				code = "nginx_reload"
			}
			if previous != code || time.Since(reported) >= 5*time.Minute {
				slog.Warn("automatic Nginx TLS deployment pending", "domain", e.Host, "code", code)
				previous = code
				reported = time.Now()
			}
		}
	}
}
