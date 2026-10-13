package operator

// Recovered deployments turn these exact original state consumers into binds.
// No arbitrary bind, TLS override, external database mount, or unclassified
// directory can be silently treated as a complete recovery state class.
func recoveredMountClass(service, target string) string {
	switch target {
	case "/run/frontiercloud-secrets":
		return "runtime_secrets"
	case "/var/lib/frontiercloud-certificate":
		return "certificate_state"
	case "/run/frontiercloud-tls":
		return "certificate_published"
	case "/data":
		if service == "redis" {
			return "redis_data"
		}
	}
	return ""
}
