package config

import (
	"log/slog"
	"strings"
)

// Old mounts must be migrated with the documented offline handoff. Old values
// are ignored with a visible diagnostic; they can never select private keys.
func reportRetiredTLS(getenv func(string) string) {
	for _, key := range []string{"SSL_CERT_PATH", "SSL_KEY_PATH", "STORAGE_TLS_CERT", "STORAGE_TLS_KEY", "ACME_WEBROOT", "STORAGE_CERTIFICATE_DIRECTORY", "STORAGE_CERTIFICATE_SOCKET", "CERTIFICATE_ACME_DIRECTORY"} {
		if strings.TrimSpace(getenv(key)) != "" {
			slog.Warn("retired TLS configuration ignored; certificates are automatically managed", "variable", key)
		}
	}
}
