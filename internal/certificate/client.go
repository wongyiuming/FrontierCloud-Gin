package certificate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type Request struct {
	Action           string `json:"action"`
	Enabled          bool   `json:"enabled,omitempty"`
	BrowserPublicKey string `json:"browser_public_key,omitempty"`
	BrowserNonce     string `json:"browser_nonce,omitempty"`
}
type Client interface {
	Control(context.Context, Request) (View, error)
}
type UnixClient struct{ Socket, Hostname string }

func (c UnixClient) Control(ctx context.Context, value Request) (View, error) {
	var result View
	if c.Socket == "" {
		return result, errors.New("certificate agent not configured")
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", c.Socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	b, _ := json.Marshal(value)
	r, e := http.NewRequestWithContext(ctx, "POST", "http://certificate/control", bytes.NewReader(b))
	if e != nil {
		return result, e
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := client.Do(r)
	if e != nil {
		return result, errors.New("certificate agent unavailable")
	}
	defer response.Body.Close()
	limit := int64(8192)
	if value.Action == "download" {
		limit = 131072
	}
	b, e = io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || int64(len(b)) > limit || json.Unmarshal(b, &result) != nil || result.Hostname != c.Hostname {
		return View{}, errors.New("certificate agent response mismatch")
	}
	if response.StatusCode != 200 {
		return result, errors.New("certificate operation refused or retry cooling down")
	}
	return result, nil
}
