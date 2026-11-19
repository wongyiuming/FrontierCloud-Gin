package config

import "testing"

func TestAdminOriginIsConfiguredSeparatelyAndValidated(t *testing.T) {
	load := func(admin string) (Config, error) {
		return LoadFrom(func(name string) string {
			switch name {
			case "TLS_ENABLED":
				return "true"
			case "SERVER_NAME":
				return "master.example"
			case "PUBLIC_ORIGIN":
				return "https://master.example"
			case "ADMIN_ORIGIN":
				return admin
			default:
				return ""
			}
		})
	}
	for _, value := range []string{"", "https://master.example"} {
		cfg, err := load(value)
		if err != nil || cfg.AdminOrigin != "https://master.example" {
			t.Fatalf("origin %q: %+v %v", value, cfg, err)
		}
	}
	cfg, err := load("https://admin.example")
	if err != nil || cfg.AdminOrigin != "https://admin.example" || cfg.PublicOrigin != "https://master.example" {
		t.Fatalf("independent management origin: %+v %v", cfg, err)
	}
	for _, value := range []string{"http://master.example", "https://user@admin.example", "https://admin.example:8443", "https://master.example/path", "https://master.example?key=secret"} {
		if _, err := load(value); err == nil {
			t.Fatalf("invalid admin origin accepted: %q", value)
		}
	}
}
