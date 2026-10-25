package config

import "testing"

func TestPublicIPCertificateConfiguration(t *testing.T) {
	for _, test := range []struct{ host, endpoint, canonical, origin string }{
		{"124.220.156.46", "https://124.220.156.46", "124.220.156.46", "https://124.220.156.46"},
		{"2606:4700:4700:0:0:0:0:1111", "https://[2606:4700:4700::1111]", "2606:4700:4700::1111", "https://[2606:4700:4700::1111]"},
	} {
		for _, storage := range []bool{false, true} {
			values := map[string]string{"SERVER_NAME": test.host, "TLS_ENABLED": "true"}
			if storage {
				values["DEPLOYMENT_MODE"], values["NGINX_MEDIA_ACCEL"], values["STORAGE_ENDPOINT"] = "only_stroge", "false", test.endpoint
			}
			got, err := LoadFrom(environment(values))
			if err != nil || got.ServerName != test.canonical || got.PublicOrigin != test.origin || storage && (got.StorageEndpoint != test.endpoint || got.HTTPAddress != ":443") {
				t.Fatal("IP automatic HTTPS config", storage, got.ServerName, got.PublicOrigin, got.StorageEndpoint, err)
			}
			values["PUBLIC_ORIGIN"] = test.endpoint + ":443/"
			if _, err := LoadFrom(environment(values)); err != nil {
				t.Fatal("standard explicit HTTPS port rejected", err)
			}
		}
	}
}

func TestPublicIPStorageRelayAndMatchingIdentity(t *testing.T) {
	values := map[string]string{"DEPLOYMENT_MODE": "only_stroge", "TLS_ENABLED": "true", "NGINX_MEDIA_ACCEL": "false", "STORAGE_TRANSPORT": "relay", "SERVER_NAME": "2606:4700:4700::1111", "STORAGE_ENDPOINT": "https://[2606:4700:4700:0:0:0:0:1111]:8443"}
	got, err := LoadFrom(environment(values))
	if err != nil || got.StorageEndpoint != "https://[2606:4700:4700::1111]:8443" || got.HTTPAddress != ":8443" || got.PublicOrigin != "https://[2606:4700:4700::1111]" {
		t.Fatal("IPv6 relay config", got.StorageEndpoint, got.HTTPAddress, err)
	}
	for _, endpoint := range []string{"https://[2606:4700:4700::1112]:8443", "https://2606:4700:4700::1111:8443", "https://[2606:4700:4700::1111%25eth0]:8443", "https://[2606:4700:4700::1111]:443", "http://[2606:4700:4700::1111]:8443"} {
		values["STORAGE_ENDPOINT"] = endpoint
		if _, err := LoadFrom(environment(values)); err == nil {
			t.Fatal("unsafe or mismatched IPv6 endpoint accepted", endpoint)
		}
	}
}

func TestAutomaticTLSRejectsNonPublicIPAndNonBareSubjects(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "3fff::1", "[2606:4700:4700::1111]", "2606:4700:4700::1111%eth0", "124.220.156.46:443"} {
		if _, err := LoadFrom(environment(map[string]string{"SERVER_NAME": host, "TLS_ENABLED": "true"})); err == nil {
			t.Fatal("non-public/non-bare automatic certificate subject accepted", host)
		}
	}
}

func TestStorageEndpointMatchesPersistedCanonicalIdentity(t *testing.T) {
	for _, test := range []struct{ host, endpoint, want string }{
		{"storage.example.test", "https://STORAGE.example.test:443", "https://storage.example.test"},
		{"124.220.156.46", "https://124.220.156.46:0443", "https://124.220.156.46"},
		{"::ffff:124.220.156.46", "https://[::ffff:124.220.156.46]:443", "https://124.220.156.46"},
		{"2606:4700:4700:0:0:0:0:1111", "https://[2606:4700:4700:0:0:0:0:1111]:443", "https://[2606:4700:4700::1111]"},
	} {
		values := map[string]string{"DEPLOYMENT_MODE": "only_stroge", "TLS_ENABLED": "true", "NGINX_MEDIA_ACCEL": "false", "SERVER_NAME": test.host, "STORAGE_ENDPOINT": test.endpoint}
		got, err := LoadFrom(environment(values))
		if err != nil || got.StorageEndpoint != test.want {
			t.Fatal("storage endpoint differs from native canonical identity", got.StorageEndpoint, test.want, err)
		}
	}
}
