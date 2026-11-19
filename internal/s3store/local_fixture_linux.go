//go:build linux && ledger_fixture

package s3store

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
)

// FixtureLocalTLSClient is compiled only into isolated tests. The production
// constructor never accepts DNS, dial or trust overrides.
func FixtureLocalTLSClient(config Config, credentials Credentials, roots *x509.CertPool, listen string) (*Client, error) {
	address, err := netip.ParseAddrPort(listen)
	if err != nil || !address.Addr().IsLoopback() || roots == nil {
		return nil, ErrEndpoint
	}
	return newClient(config, credentials, transportOptions{
		roots: roots,
		resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.44")}, nil
		},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listen)
		},
	})
}
