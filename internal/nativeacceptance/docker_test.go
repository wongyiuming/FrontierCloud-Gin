package nativeacceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

var ErrState = errors.New("unsafe private Docker fixture state")

var ErrNotFound = errors.New("Docker object not found")
var dockerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var dockerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type dockerFailure struct {
	operation string
	status    int
}

func (e *dockerFailure) Error() string { return "Docker operation rejected" }
func dockerOperation(path string) string {
	path, _, _ = strings.Cut(path, "?")
	switch {
	case path == "/images/json":
		return "image-list"
	case path == "/images/create":
		return "image-pull"
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/tag"):
		return "image-tag"
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		return "image-inspect"
	case path == "/containers/json":
		return "container-list"
	case path == "/containers/create":
		return "container-create"
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		return "container-inspect"
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/exec"):
		return "exec-create"
	case strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/start"):
		return "exec-start"
	case strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/json"):
		return "exec-inspect"
	case path == "/build":
		return "build"
	default:
		return "request"
	}
}

// Engine only talks to the configured local Unix socket; no proxy, redirect,
// remote host selection, shell interpolation or Docker CLI is involved.
type Engine struct {
	client  *http.Client
	version string
	Project string
}

func NewEngine(ctx context.Context, socket string) (*Engine, error) {
	if socket == "" {
		return nil, ErrState
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: 8}
	e := &Engine{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Docker redirects forbidden") }}}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var version struct {
		API     string `json:"ApiVersion"`
		Minimum string `json:"MinAPIVersion"`
	}
	// Engine version responses contain other documented fields.
	if err := e.call(probe, "GET", "/version", nil, &version); err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	parse := func(raw string) (int, error) {
		values := strings.Split(raw, ".")
		if len(values) != 2 || values[0] != "1" {
			return 0, ErrState
		}
		return strconv.Atoi(values[1])
	}
	maximum, err := parse(version.API)
	if err != nil {
		return nil, ErrState
	}
	minimum, err := parse(version.Minimum)
	if err != nil {
		return nil, ErrState
	}
	if maximum > 52 {
		maximum = 52
	}
	if maximum < 44 || minimum > maximum {
		return nil, errors.New("unsupported Docker API version")
	}
	e.version = fmt.Sprintf("/v1.%d", maximum)
	return e, nil
}
func (e *Engine) Close() {
	if t, ok := e.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func (e *Engine) request(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+e.version+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	r, err := e.client.Do(req)
	if err != nil {
		return nil, errors.New("Docker request failed")
	}
	allowedAlready := r.StatusCode == http.StatusNotModified && method == "POST" && (strings.HasSuffix(path, "/start") || strings.Contains(path, "/stop?t="))
	if (r.StatusCode < 200 || r.StatusCode >= 300) && !allowedAlready {
		r.Body.Close()
		if r.StatusCode == 404 {
			return nil, ErrNotFound
		}
		return nil, &dockerFailure{operation: dockerOperation(path), status: r.StatusCode}
	}
	return r, nil
}
func (e *Engine) call(ctx context.Context, method, path string, value, result any) error {
	// Docker stop sends headers only after its graceful timeout. A global
	// header timeout equal to that timeout incorrectly interrupts replacement.
	wait := 30 * time.Second
	if strings.Contains(path, "/stop?t=") {
		wait = 45 * time.Second
	}
	if strings.Contains(path, "/wait?condition=") {
		wait = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var body io.Reader
	if value != nil {
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > 16<<20 {
			return ErrState
		}
		body = bytes.NewReader(raw)
	}
	r, err := e.request(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if result == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (16<<20)+1))
	if err != nil {
		return err
	}
	if _, err = protocol.ParseStrictJSON(raw, 16<<20); err != nil {
		return errors.New("invalid Docker response")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(result) != nil {
		return errors.New("invalid Docker response")
	}
	return nil
}

type Container struct {
	ID              string         `json:"Id"`
	Name            string         `json:"Name"`
	Image           string         `json:"Image"`
	Config          map[string]any `json:"Config"`
	HostConfig      map[string]any `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
		Health   struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

func (c Container) valid() bool {
	return dockerID.MatchString(c.ID) && dockerID.MatchString(strings.TrimPrefix(c.Image, "sha256:")) && dockerName.MatchString(strings.TrimPrefix(c.Name, "/")) && c.Config != nil && c.HostConfig != nil
}
func (c Container) label(key string) string {
	labels, _ := c.Config["Labels"].(map[string]any)
	value, _ := labels[key].(string)
	return value
}
func (e *Engine) Inspect(ctx context.Context, name string) (Container, error) {
	var c Container
	if !dockerID.MatchString(name) && !dockerName.MatchString(name) {
		return c, ErrState
	}
	err := e.call(ctx, "GET", "/containers/"+name+"/json", nil, &c)
	if err == nil && !c.valid() {
		return c, ErrState
	}
	return c, err
}
func (e *Engine) Create(ctx context.Context, name string, body map[string]any) (string, error) {
	if !dockerName.MatchString(name) {
		return "", ErrState
	}
	var result struct {
		ID string `json:"Id"`
	}
	err := e.call(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), body, &result)
	if err != nil {
		return "", err
	}
	if !dockerID.MatchString(result.ID) {
		return "", ErrState
	}
	return result.ID, nil
}
func (e *Engine) Start(ctx context.Context, id string) error {
	if !dockerID.MatchString(id) {
		return ErrState
	}
	return e.call(ctx, "POST", "/containers/"+id+"/start", nil, nil)
}
func (e *Engine) Stop(ctx context.Context, id string) error {
	if !dockerID.MatchString(id) {
		return ErrState
	}
	return e.call(ctx, "POST", "/containers/"+id+"/stop?t=30", nil, nil)
}
func (e *Engine) Remove(ctx context.Context, id string) error {
	if !dockerID.MatchString(id) {
		return ErrState
	}
	return e.call(ctx, "DELETE", "/containers/"+id+"?force=false&v=false", nil, nil)
}
func (e *Engine) Wait(ctx context.Context, id string) error {
	if !dockerID.MatchString(id) {
		return ErrState
	}
	var result struct {
		Code  int `json:"StatusCode"`
		Error *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err := e.call(ctx, "POST", "/containers/"+id+"/wait?condition=not-running", nil, &result); err != nil {
		return err
	}
	if result.Code != 0 || result.Error != nil {
		return errors.New("native helper failed")
	}
	return nil
}
func (e *Engine) Healthy(ctx context.Context, id string) error {
	for {
		c, err := e.Inspect(ctx, id)
		if err != nil {
			return err
		}
		if c.State.Status == "running" && c.State.Health.Status == "healthy" {
			return nil
		}
		if c.State.Status == "dead" || c.State.Status == "exited" || c.State.Health.Status == "unhealthy" {
			return errors.New("release service failed health check")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
func (e *Engine) Exec(ctx context.Context, id string, command []string) error {
	if !dockerID.MatchString(id) || len(command) == 0 {
		return ErrState
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := e.call(ctx, "POST", "/containers/"+id+"/exec", map[string]any{"Cmd": command, "AttachStdout": false, "AttachStderr": false, "Tty": false}, &created); err != nil {
		return err
	}
	if !dockerID.MatchString(created.ID) {
		return ErrState
	}
	if err := e.call(ctx, "POST", "/exec/"+created.ID+"/start", map[string]any{"Detach": true, "Tty": false}, nil); err != nil {
		return err
	}
	for {
		var state struct {
			Running  bool `json:"Running"`
			ExitCode int  `json:"ExitCode"`
		}
		if err := e.call(ctx, "GET", "/exec/"+created.ID+"/json", nil, &state); err != nil {
			return err
		}
		if !state.Running {
			if state.ExitCode != 0 {
				return errors.New("native release command failed")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
