package config

import "testing"

func TestStagingCDCannotEnableOnProductionOrStorage(t *testing.T) {
	for _, site := range []string{"520mall.cc", "storage.example.com", "ml.520mall.cc", "www4399.sbs"} {
		_, err := LoadFrom(func(k string) string {
			switch k {
			case "STAGING_CD", "TLS_ENABLED":
				return "true"
			case "SERVER_NAME":
				return site
			}
			return ""
		})
		if (err == nil) != (site == "www4399.sbs") {
			t.Fatal(site, err)
		}
	}
}

func TestStagingCDRequiresBusinessTLSOnSharedRNHost(t *testing.T) {
	for _, mode := range []string{"business", "only_stroge"} {
		for _, tls := range []string{"true", "false"} {
			_, err := LoadFrom(func(k string) string {
				switch k {
				case "STAGING_CD":
					return "true"
				case "TLS_ENABLED":
					return tls
				case "SERVER_NAME":
					return "www4399.sbs"
				case "DEPLOYMENT_MODE":
					return mode
				}
				return ""
			})
			if (err == nil) != (mode == "business" && tls == "true") {
				t.Fatal(mode, tls, err)
			}
		}
	}
}
