package config

import "testing"

func TestStagingCDCannotEnableOnProductionOrStorage(t *testing.T) {
	for _, site := range []string{"520mall.cc", "storage.example.com", "ml.520mall.cc"} {
		_, err := LoadFrom(func(k string) string {
			switch k {
			case "STAGING_CD", "TLS_ENABLED":
				return "true"
			case "SERVER_NAME":
				return site
			}
			return ""
		})
		if (err == nil) != (site == "ml.520mall.cc") {
			t.Fatal(site, err)
		}
	}
}
