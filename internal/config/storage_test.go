package config

import "testing"

func TestOnlyStrogeConfigurationIsExplicitAndHighPortTLSOnly(t *testing.T) {
	valid := map[string]string{"DEPLOYMENT_MODE": "only_stroge", "TLS_ENABLED": "true", "NGINX_MEDIA_ACCEL": "false", "SERVER_NAME": "storage.example.com", "STORAGE_ENDPOINT": "https://storage.example.com:8443", "HTTP_ADDR": ":8443"}
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
