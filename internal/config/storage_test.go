package config

import "testing"

func TestRelayStorageConfigurationIsExplicitAndHighPortTLSOnly(t *testing.T) {
	valid := map[string]string{"DEPLOYMENT_MODE": "only_stroge", "TLS_ENABLED": "true", "NGINX_MEDIA_ACCEL": "false", "STORAGE_TRANSPORT": "relay", "SERVER_NAME": "storage.example.com", "STORAGE_ENDPOINT": "https://storage.example.com:8443", "HTTP_ADDR": ":8443"}
	if c, err := LoadFrom(func(k string) string { return valid[k] }); err != nil || c.DeploymentMode != DeploymentStorage {
		t.Fatal(c, err)
	}
	for key, values := range map[string][]string{
		"DEPLOYMENT_MODE": {"follower", "only_storage"}, "DB_TYPE": {"mysql"}, "TLS_ENABLED": {"false"}, "NGINX_MEDIA_ACCEL": {"true"},
		"HTTP_ADDR": {":80", ":443", ":0", "bad"}, "STORAGE_PORT": {"80", "443", "65536", "8444"}, "SERVER_NAME": {"other.example.com"},
		"STORAGE_ENDPOINT": {"http://storage.example.com:8443", "https://storage.example.com", "https://storage.example.com:443", "https://storage.example.com:80", "https://storage.example.com:65536", "https://user:pass@storage.example.com:8443", "https://storage.example.com:8443/path", "https://storage.example.com:8443?x=y", "https://storage.example.com:8443#fragment"},
	} {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				if _, err := LoadFrom(func(k string) string {
					if k == key {
						return value
					}
					return valid[k]
				}); err == nil {
					t.Fatal("unsafe storage configuration accepted")
				}
			})
		}
	}
}

func TestDirectStorageEnforcesStandardHTTPSAndIgnoresRetiredCertificateSelectors(t *testing.T) {
	values := map[string]string{"DEPLOYMENT_MODE": "only_stroge", "TLS_ENABLED": "true", "NGINX_MEDIA_ACCEL": "false", "SERVER_NAME": "storage.4399.com", "STORAGE_ENDPOINT": "https://storage.4399.com"}
	got, e := LoadFrom(environment(values))
	if e != nil || got.StorageTransport != "direct" || got.StoragePort != 443 || got.HTTPAddress != ":443" {
		t.Fatal(got, e)
	}
	for key, raw := range map[string]string{"STORAGE_PORT": "8443", "HTTP_ADDR": ":8443", "STORAGE_ENDPOINT": "https://storage.4399.com:8443", "STORAGE_TRANSPORT": "automatic"} {
		clone := map[string]string{}
		for k, v := range values {
			clone[k] = v
		}
		clone[key] = raw
		if _, e = LoadFrom(environment(clone)); e == nil {
			t.Fatal("nonstandard direct listener accepted", key)
		}
	}
	for _, key := range []string{"SSL_CERT_PATH", "SSL_KEY_PATH", "STORAGE_TLS_CERT", "STORAGE_TLS_KEY", "ACME_WEBROOT", "STORAGE_CERTIFICATE_DIRECTORY", "STORAGE_CERTIFICATE_SOCKET"} {
		values[key] = "/untrusted/operator/path"
	}
	got, e = LoadFrom(environment(values))
	if e != nil || got.StoragePort != 443 {
		t.Fatal("retired path altered automatic TLS config", e)
	}
}
