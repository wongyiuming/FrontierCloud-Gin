package certificate

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"golang.org/x/net/netutil"
)

type Job struct {
	State        string `json:"state"`
	Code         string `json:"code,omitempty"`
	StartedAt    int64  `json:"started_at,omitempty"`
	CompletedAt  int64  `json:"completed_at,omitempty"`
	Port80Active bool   `json:"port80_active"`
}
type persisted struct {
	AutoRenew bool `json:"auto_renew"`
	Job       Job  `json:"job"`
}
type Issuer func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error)
type Agent struct {
	mu                       sync.Mutex
	host, directory, address string
	state                    persisted
	issue                    Issuer
	ctx                      context.Context
	wg                       sync.WaitGroup
	cancel                   context.CancelFunc
	release                  func()
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func Hostname(s string) bool {
	return hostnamePattern.MatchString(s) && strings.Contains(s, ".") && !strings.Contains(s, "..") && net.ParseIP(s) == nil
}
func Open(ctx context.Context, host, directory, address string, issue Issuer) (*Agent, error) {
	if !Hostname(host) || !filepath.IsAbs(directory) || issue == nil {
		return nil, errors.New("invalid certificate agent configuration")
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private certificate state directory required")
	}
	lock, e := os.OpenFile(filepath.Join(directory, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	release, e := filelease.Try(lock, true)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	ok := false
	defer func() {
		if !ok {
			cancel()
			release()
		}
	}()
	a := &Agent{host: host, directory: directory, address: address, issue: issue, ctx: ctx, cancel: cancel, release: release, state: persisted{Job: Job{State: "idle"}}}
	if b, e := os.ReadFile(filepath.Join(directory, "state.json")); e == nil {
		if len(b) > 4096 || json.Unmarshal(b, &a.state) != nil {
			return nil, errors.New("invalid certificate agent journal")
		}
		if a.state.Job.State == "running" {
			a.state.Job.State = "failed"
			a.state.Job.Code = "interrupted"
			a.state.Job.Port80Active = false
			a.state.Job.CompletedAt = time.Now().Unix()
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if a.state.Job.State != "idle" && a.state.Job.State != "failed" && a.state.Job.State != "success" {
		return nil, errors.New("invalid certificate job state")
	}
	if e := a.save(); e != nil {
		return nil, e
	}
	ok = true
	return a, nil
}

// Close cancels issuance, releases any challenge listener, then the host lease.
func (a *Agent) Close() { a.mu.Lock(); a.cancel(); a.mu.Unlock(); a.wg.Wait(); a.release() }
func atomicFile(path string, b []byte, mode os.FileMode) error {
	r := make([]byte, 16)
	if _, e := rand.Read(r); e != nil {
		return e
	}
	tmp := path + ".next-" + hex.EncodeToString(r)
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (a *Agent) save() error {
	b, _ := json.Marshal(a.state)
	return atomicFile(filepath.Join(a.directory, "state.json"), b, 0600)
}
func (a *Agent) Status() View {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := View{Hostname: a.host, State: "missing", Managed: true, AutoRenew: a.state.AutoRenew, Job: a.state.Job}
	if p, e := manifest(a.directory); e == nil {
		if pair, e := tls.LoadX509KeyPair(filepath.Join(a.directory, p.Generation, "fullchain.pem"), filepath.Join(a.directory, p.Generation, "privkey.pem")); e == nil {
			v = pairView(a.host, &pair)
			v.Managed = true
			v.AutoRenew = a.state.AutoRenew
			v.Job = a.state.Job
		}
	}
	return v
}
func (a *Agent) Start() (View, error) {
	v := a.Status()
	a.mu.Lock()
	if a.ctx.Err() != nil {
		a.mu.Unlock()
		return v, errors.New("agent stopping")
	}
	if a.state.Job.State == "running" {
		a.mu.Unlock()
		return a.Status(), nil
	}
	if v.State == "valid" && v.NotAfter > time.Now().Add(30*24*time.Hour).Unix() {
		a.mu.Unlock()
		return a.Status(), nil
	}
	if a.state.Job.StartedAt > time.Now().Add(-time.Hour).Unix() {
		a.mu.Unlock()
		return v, errors.New("certificate retry cooldown")
	}
	a.state.Job = Job{State: "running", StartedAt: time.Now().Unix()}
	if e := a.save(); e != nil {
		a.state.Job.State = "failed"
		a.mu.Unlock()
		return v, e
	}
	a.wg.Add(1)
	a.mu.Unlock()
	go a.run()
	return a.Status(), nil
}
func (a *Agent) SetAutoRenew(enabled bool) (View, error) {
	a.mu.Lock()
	previous := a.state.AutoRenew
	a.state.AutoRenew = enabled
	e := a.save()
	if e != nil {
		a.state.AutoRenew = previous
	}
	a.mu.Unlock()
	return a.Status(), e
}
func (a *Agent) run() {
	defer a.wg.Done()
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Minute)
	defer cancel()
	var cleanup []func()
	cert, key, e := a.issue(ctx, func(token, response string) (func(), error) {
		closeFn, e := a.present(ctx, token, response)
		if e == nil {
			cleanup = append(cleanup, closeFn)
		}
		return closeFn, e
	})
	for _, closeFn := range cleanup {
		closeFn()
	}
	if e == nil {
		e = ctx.Err()
	}
	code := "issuance_failed"
	if e == nil {
		e = a.publish(cert, key)
		code = "publication_failed"
	}
	if errors.Is(e, errPortBusy) {
		code = "port80_busy"
	}
	if ctx.Err() != nil {
		code = "timeout_or_shutdown"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Job.State = "success"
	a.state.Job.Code = ""
	if e != nil {
		a.state.Job.State = "failed"
		a.state.Job.Code = code
	}
	a.state.Job.Port80Active = false
	a.state.Job.CompletedAt = time.Now().Unix()
	if a.save() != nil {
		a.state.Job.State = "failed"
		a.state.Job.Code = "journal_io"
	}
}

var errPortBusy = errors.New("HTTP-01 port occupied")
var tokenPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,256}$`)

func (a *Agent) present(ctx context.Context, token, response string) (func(), error) {
	if !tokenPattern.MatchString(token) || len(response) > 512 {
		return nil, errors.New("invalid HTTP-01 challenge")
	}
	listener, e := net.Listen("tcp", a.address)
	if e != nil {
		if errors.Is(e, syscall.EADDRINUSE) {
			return nil, errPortBusy
		}
		return nil, e
	}
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 2048, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if r.Method != "GET" || strings.ToLower(host) != a.host || r.URL.Path != "/.well-known/acme-challenge/"+token || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, response)
	})}
	a.mu.Lock()
	a.state.Job.Port80Active = true
	a.mu.Unlock()
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(netutil.LimitListener(listener, 1)) }()
	var once sync.Once
	closeFn := func() {
		once.Do(func() {
			_ = server.Close()
			_ = listener.Close()
			<-done
			a.mu.Lock()
			a.state.Job.Port80Active = false
			a.mu.Unlock()
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeFn()
		case <-done:
		}
	}()
	return closeFn, nil
}
func (a *Agent) publish(cert, key []byte) error {
	previous := ""
	if p, e := manifest(a.directory); e == nil {
		pair, e := tls.LoadX509KeyPair(filepath.Join(a.directory, p.Generation, "fullchain.pem"), filepath.Join(a.directory, p.Generation, "privkey.pem"))
		if e == nil && pairView(a.host, &pair).NotAfter != 0 {
			previous = p.Generation
		}
	}
	r := make([]byte, 16)
	if _, e := rand.Read(r); e != nil {
		return e
	}
	generation := hex.EncodeToString(r)
	dir := filepath.Join(a.directory, generation)
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			// A rename followed by a directory-sync failure is ambiguous. Never
			// remove a complete generation already selected by the visible pointer.
			p, e := manifest(a.directory)
			if e != nil || p.Generation != generation {
				_ = os.RemoveAll(dir)
			}
		}
	}()
	if e := atomicFile(filepath.Join(dir, "fullchain.pem"), cert, 0600); e != nil {
		return e
	}
	if e := atomicFile(filepath.Join(dir, "privkey.pem"), key, 0600); e != nil {
		return e
	}
	if _, e := loadPair(a.host, filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")); e != nil {
		return e
	}
	b, _ := json.Marshal(Pair{generation})
	if e := atomicFile(filepath.Join(a.directory, "current.json"), b, 0600); e != nil {
		return e
	}
	committed = true
	// Keep the current and preceding complete pair; never accumulate renewals.
	entries, _ := os.ReadDir(a.directory)
	for _, v := range entries {
		if v.IsDir() && generationPattern.MatchString(v.Name()) && v.Name() != generation && v.Name() != previous {
			_ = os.RemoveAll(filepath.Join(a.directory, v.Name()))
		}
	}
	return nil
}
func (a *Agent) Serve(socket string) error {
	defer a.Close()
	if !filepath.IsAbs(socket) {
		return errors.New("absolute Unix socket required")
	}
	lock, e := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	unlock, e := filelease.Acquire(a.ctx, lock, true)
	if e != nil {
		return e
	}
	defer unlock()
	if i, e := os.Lstat(socket); e == nil {
		if i.Mode()&os.ModeSocket == 0 {
			return errors.New("unsafe certificate socket")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	}
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0600); e != nil {
		return e
	}
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/control" {
			http.NotFound(w, r)
			return
		}
		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil || d.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		v := a.Status()
		var e error
		switch request.Action {
		case "status":
		case "renew":
			v, e = a.Start()
		case "auto":
			v, e = a.SetAutoRenew(request.Enabled)
		default:
			http.Error(w, "invalid action", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if e != nil {
			w.WriteHeader(409)
		}
		_ = json.NewEncoder(w).Encode(v)
	})}
	stop := make(chan struct{})
	go func() {
		select {
		case <-a.ctx.Done():
			_ = server.Close()
		case <-stop:
		}
	}()
	defer close(stop)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if a.Status().AutoRenew {
					_, _ = a.Start()
				}
			}
		}
	}()
	e = server.Serve(listener)
	wasCancelled := a.ctx.Err() != nil
	a.cancel()
	a.wg.Wait()
	if errors.Is(e, http.ErrServerClosed) || wasCancelled {
		return nil
	}
	return e
}
