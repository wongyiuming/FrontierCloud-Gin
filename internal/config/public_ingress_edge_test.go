package config

import (
	"net/http/httptest"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

func TestPublicIngressEdgeTrustIsExplicitAndIndependent(t *testing.T) {
	defaults, err := LoadFrom(environment(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults.PublicIngressTrustedProxyNetworks) != 0 || len(defaults.TrustedProxyNetworks) == 0 {
		t.Fatalf("unexpected defaults: ingress=%v general=%v", defaults.PublicIngressTrustedProxyNetworks, defaults.TrustedProxyNetworks)
	}
	resolver, err := network.New(defaults.PublicIngressTrustedProxyNetworks)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.20.0.2:1234"
	r.Header.Set("X-Real-IP", "192.0.2.10")
	r.Header.Set("X-Forwarded-Proto", "https")
	if resolver.Resolve(r).FromTrustedProxy {
		t.Fatal("default accepted forged proxy assertion")
	}
	configured, err := LoadFrom(environment(map[string]string{"PUBLIC_INGRESS_TRUSTED_PROXY_NETWORKS": "10.20.0.0/16"}))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err = network.New(configured.PublicIngressTrustedProxyNetworks)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "10.20.0.5:1234"
	if !resolver.Resolve(r).FromTrustedProxy || !resolver.SecureAdmin(r) {
		t.Fatal("explicit HTTPS edge not recognized")
	}
	r.RemoteAddr = "172.20.0.2:1234"
	if resolver.Resolve(r).FromTrustedProxy {
		t.Fatal("general trusted CIDR leaked into ingress trust")
	}
}
