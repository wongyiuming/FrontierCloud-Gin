package config

import "testing"

func TestFollowerResourceOriginDoesNotDefaultToOtherOrigins(t *testing.T) {
	load := func(resource string) (Config, error) {
		return LoadFrom(func(name string) string {
			switch name {
			case "TLS_ENABLED":
				return "true"
			case "SERVER_NAME":
				return "entry.example"
			case "PUBLIC_ORIGIN":
				return "https://entry.example"
			case "FOLLOWER_RESOURCE_ORIGIN":
				return resource
			default:
				return ""
			}
		})
	}
	for _, origin := range []string{"", "https://storage.example"} {
		settings, err := load(origin)
		if err != nil || settings.FollowerResourceOrigin != origin || settings.MasterResourceOrigin != "" {
			t.Fatal(origin, settings.FollowerResourceOrigin, err)
		}
	}
}
