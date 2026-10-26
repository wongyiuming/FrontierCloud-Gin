package s3store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTransportPinsResolvedAddressesAndIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://169.254.169.254")
	f := newFakeS3(t, "path")
	f.client.transport.inner.DisableKeepAlives = true
	for _, key := range []string{"objects/one", "objects/two"} {
		if _, err := f.client.CreateMultipart(context.Background(), key, map[string]string{"fc-owner": "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolved != 1 || len(f.dials) != 2 || f.client.transport.inner.Proxy != nil {
		t.Fatal("client re-resolved its pinned origin or used ambient proxy", f.resolved, len(f.dials))
	}
	for _, authority := range f.dials {
		host, _, _ := net.SplitHostPort(authority)
		if host != "192.168.6.20" {
			t.Fatal("dial used hostname instead of the validated fixed IP")
		}
	}
}

func TestBlockedAddressAnswersNeverReachADial(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "0.0.0.1", "127.0.0.1", "127.3.2.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "fd00:ec2::254", "fd20:ce::254", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001::1"} {
		t.Run(raw, func(t *testing.T) {
			if allowedAddress(netip.MustParseAddr(raw)) {
				t.Fatal("forbidden endpoint address admitted")
			}
		})
	}
	for _, raw := range []string{"192.168.6.201", "10.0.0.2", "172.16.1.2", "fd01::20", "8.8.8.8", "2606:4700:4700::1111"} {
		if !allowedAddress(netip.MustParseAddr(raw)) {
			t.Fatal("explicit HTTPS LAN/public service refused", raw)
		}
	}
	f := newFakeS3(t, "path")
	f.client.transport.options.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	_, err := f.client.CreateMultipart(context.Background(), "objects/one", map[string]string{"fc-owner": "fixture"})
	if err == nil {
		t.Fatal("mixed public/forbidden DNS result admitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dials) != 0 {
		t.Fatal("forbidden resolution reached socket creation")
	}
}

func TestNormalTLSValidationCannotBeDisabledByProviderResponse(t *testing.T) {
	for _, wrong := range []string{"roots", "hostname"} {
		t.Run(wrong, func(t *testing.T) {
			f := newFakeS3(t, "path")
			if wrong == "roots" {
				f.client.transport.inner.TLSClientConfig.RootCAs = x509.NewCertPool()
			} else {
				f.client.transport.inner.TLSClientConfig.ServerName = "wrong.fixture.test"
			}
			_, err := f.client.CreateMultipart(context.Background(), "objects/one", map[string]string{"fc-owner": "fixture"})
			if err == nil || !IsUncertain(err) || f.client.transport.inner.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("TLS verification bypassed", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 0 {
				t.Fatal("unverified TLS connection sent an HTTP credential")
			}
		})
	}
}

func TestTransportRefusesForeignAuthorityAndOversizedRequests(t *testing.T) {
	f := newFakeS3(t, "path")
	for _, raw := range []string{"http://" + f.client.transport.authority, "https://foreign.fixture.test/", "https://user:secret@" + f.client.transport.authority + "/"} {
		request, _ := http.NewRequest(http.MethodGet, raw, nil)
		if _, err := f.client.http.Do(request); err == nil {
			t.Fatal("foreign/nonHTTPS authority admitted")
		}
	}
	request, _ := http.NewRequest(http.MethodPost, f.client.config.Endpoint, bytes.NewReader(make([]byte, controlLimit+1)))
	if _, err := f.client.http.Do(request); err == nil {
		t.Fatal("bulk request reached the control transport")
	}
	request, _ = http.NewRequest(http.MethodGet, f.client.config.Endpoint, nil)
	request.Header.Set("X-Large", strings.Repeat("x", 33<<10))
	if _, err := f.client.http.Do(request); err == nil {
		t.Fatal("unbounded request headers admitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dials) != 0 {
		t.Fatal("refused request reached a socket")
	}
}

func TestHeadLargeObjectDoesNotReadOrRelayItsBody(t *testing.T) {
	f := newFakeS3(t, "path")
	checksum := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=-1"
	f.objects["music/v1/objects/large"] = fakeObject{size: PartSize, etag: `"opaque"`, checksum: checksum, metadata: map[string]string{"fc-owner": "fixture"}}
	proof, err := f.client.Head(context.Background(), "objects/large", "fixture-version")
	if err != nil || proof.Size != PartSize {
		t.Fatal("HEAD content length was mistaken for a response body", err)
	}
}

func TestBoundedResponseAndCredentialDebugRedaction(t *testing.T) {
	f := newFakeS3(t, "path")
	f.mode = "large"
	_, err := f.client.CreateMultipart(context.Background(), "objects/large", map[string]string{"fc-owner": "fixture"})
	if err == nil || !errors.Is(err, ErrResponse) || !IsUncertain(err) {
		t.Fatal("large response was parsed as an ordinary provider result", err)
	}
	grant := Grant{URL: "https://secret.example?signature=DO-NOT-LOG", Headers: map[string]string{"secret": "DO-NOT-LOG"}}
	if strings.Contains(grant.String(), "DO-NOT-LOG") || strings.Contains(f.client.GoString(), f.client.credentials.SecretKey) {
		t.Fatal("debug rendering disclosed bearer material")
	}
}

// A request reader cannot bypass the same ceiling by omitting Content-Length.
func TestUnknownLengthControlBodyIsStillBounded(t *testing.T) {
	f := newFakeS3(t, "path")
	request, _ := http.NewRequest(http.MethodPost, f.client.config.Endpoint, io.NopCloser(bytes.NewReader(make([]byte, controlLimit+1))))
	request.ContentLength = -1
	if _, err := f.client.http.Do(request); err == nil {
		t.Fatal("unbounded unknown-length body accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dials) != 0 {
		t.Fatal("oversized body reached provider")
	}
}

func TestSigningDoesNotBypassEndpointAddressAdmission(t *testing.T) {
	for _, endpoint := range []string{"https://100.100.100.200", "https://[fd00:ec2::254]", "https://[fd20:ce::254]"} {
		config := baseConfig()
		config.Endpoint = endpoint
		if _, err := New(config, validCredentials()); !errors.Is(err, ErrEndpoint) {
			t.Fatal("literal metadata endpoint received a signer", endpoint, err)
		}
	}
	f := newFakeS3(t, "path")
	f.client.transport.options.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	sum := sha256.Sum256([]byte("part"))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	if _, err := f.client.PresignPart(context.Background(), "objects/one", "upload", 1, 4, checksum, 60*1e9); !errors.Is(err, ErrEndpoint) {
		t.Fatal("blocked DNS endpoint received a browser upload grant", err)
	}
	if _, err := f.client.PresignGet(context.Background(), "objects/one", "", `"etag"`, "", 60*1e9); !errors.Is(err, ErrEndpoint) {
		t.Fatal("blocked DNS endpoint received a browser download grant", err)
	}
}

func TestLiteralIPTLSUsesRealIPSANAndNoDNSResolution(t *testing.T) {
	for _, host := range []string{"192.168.6.20", "[fd01::20]", "192.168.6.21"} {
		t.Run(host, func(t *testing.T) {
			f := newFakeS3(t, "path")
			_, port, _ := net.SplitHostPort(f.server.Listener.Addr().String())
			config := baseConfig()
			config.Endpoint = "https://" + host + ":" + port
			config.AddressStyle = "path"
			client, err := newClient(config, validCredentials(), f.client.transport.options)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			f.client = client
			_, err = client.CreateMultipart(context.Background(), "objects/ip", map[string]string{"fc-owner": "fixture"})
			if host == "192.168.6.21" {
				if err == nil {
					t.Fatal("wrong IP SAN accepted")
				}
			} else if err != nil {
				t.Fatal("correct real IP SAN refused", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.resolved != 0 {
				t.Fatal("literal IP unexpectedly consulted DNS")
			}
		})
	}
}

func TestRequestDeadlinePreservesUnknownMutation(t *testing.T) {
	f := newFakeS3(t, "path")
	f.mode = "delay"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := f.client.CreateMultipart(ctx, "objects/cancelled", map[string]string{"fc-owner": "fixture"})
	if err == nil || !IsUncertain(err) {
		t.Fatal("canceled mutating request was treated as absent", err)
	}
}
