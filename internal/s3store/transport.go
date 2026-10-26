package s3store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const controlLimit int64 = 512 << 10
const controlTimeout = 15 * time.Second

// The unexported seams exist solely for HTTPS fixture tests. New never takes
// caller-supplied transports, roots, resolvers, proxy settings or TLS overrides.
type transportOptions struct {
	roots   *x509.CertPool
	resolve func(context.Context, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

type boundedTransport struct {
	inner     *http.Transport
	authority string
	host      string
	port      string
	options   transportOptions
	mu        sync.Mutex
	addresses []netip.Addr
}

// LAN endpoints are explicitly administrator selected. All resolved answers
// must be usable; a mixed public/metadata answer is refused as a whole.
func allowedAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.Zone() != "" {
		return false
	}
	// Alibaba's metadata service is not in 169.254/16. Do not let an explicit
	// LAN endpoint turn any supported provider's metadata service into S3.
	for _, metadata := range []string{"100.100.100.200", "168.63.129.16", "fd00:ec2::254", "fd20:ce::254"} {
		if address == netip.MustParseAddr(metadata) {
			return false
		}
	}
	// Reject IPv6 transition encodings that can smuggle forbidden IPv4 peers.
	for _, prefix := range []string{"0.0.0.0/8", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::/96"} {
		if netip.MustParsePrefix(prefix).Contains(address) {
			return false
		}
	}
	return true
}

func newBoundedHTTP(c Config, options transportOptions) (*http.Client, *boundedTransport) {
	u, _ := url.Parse(c.Endpoint)
	host := u.Hostname()
	if c.AddressStyle == "virtual" {
		host = c.Bucket + "." + host
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if options.resolve == nil {
		options.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if options.dial == nil {
		dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 20 * time.Second}
		options.dial = dialer.DialContext
	}
	authority := host
	if port != "443" || strings.Contains(host, ":") {
		authority = net.JoinHostPort(host, port)
	}
	// An IPv6 URL on default 443 has brackets but no explicit port.
	if strings.Contains(host, ":") && port == "443" {
		authority = "[" + host + "]"
	}
	t := &boundedTransport{host: host, port: port, authority: authority, options: options}
	t.inner = &http.Transport{
		Proxy: nil, DialContext: t.dialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.roots},
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: time.Second, IdleConnTimeout: 20 * time.Second,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4,
		MaxResponseHeaderBytes: 16 << 10, DisableCompression: true,
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: t, Timeout: controlTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrEndpoint }}
	return client, t
}

func (t *boundedTransport) pinned(ctx context.Context) ([]netip.Addr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.addresses) != 0 {
		return append([]netip.Addr(nil), t.addresses...), nil
	}
	var addresses []netip.Addr
	var err error
	if literal, parseErr := netip.ParseAddr(t.host); parseErr == nil {
		addresses = []netip.Addr{literal}
	} else {
		addresses, err = t.options.resolve(ctx, t.host)
	}
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrEndpoint
	}
	for _, address := range addresses {
		if !allowedAddress(address) {
			return nil, ErrEndpoint
		}
	}
	// Pin every subsequent connection for this client to this validated set.
	t.addresses = append([]netip.Addr(nil), addresses...)
	return append([]netip.Addr(nil), addresses...), nil
}

func (t *boundedTransport) dialContext(ctx context.Context, network, authority string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host != t.host || port != t.port || network != "tcp" {
		return nil, ErrEndpoint
	}
	addresses, err := t.pinned(ctx)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		connection, err := t.options.dial(ctx, "tcp", net.JoinHostPort(address.String(), t.port))
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrNetwork
}

func (t *boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	u := request.URL
	if u == nil || len(u.String()) > 16384 || u.Scheme != "https" || u.User != nil || u.Host != t.authority || u.Fragment != "" || (request.Host != "" && request.Host != u.Host) {
		return nil, ErrEndpoint
	}
	headerBytes := 0
	for name, values := range request.Header {
		for _, value := range values {
			headerBytes += len(name) + len(value) + 4
		}
	}
	if headerBytes > 32<<10 {
		return nil, ErrResponse
	}
	if request.ContentLength > controlLimit {
		return nil, ErrResponse
	}
	// Only control XML and the fixed <=1KiB capability probe reach this client.
	// SDK streaming, an accidental application payload, or an unbounded reader
	// cannot turn the Master into a media relay.
	if request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(request.Body, controlLimit+1))
		request.Body.Close()
		if err != nil || int64(len(body)) > controlLimit {
			return nil, ErrResponse
		}
		request = request.Clone(request.Context())
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	response, err := t.inner.RoundTrip(request)
	if err != nil {
		return nil, ErrNetwork
	}
	defer response.Body.Close()
	if request.Method != http.MethodHead && response.ContentLength > controlLimit {
		return nil, ErrResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, controlLimit+1))
	if err != nil {
		return nil, ErrNetwork
	}
	if int64(len(body)) > controlLimit {
		return nil, ErrResponse
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
