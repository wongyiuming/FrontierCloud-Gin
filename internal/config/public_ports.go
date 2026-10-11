package config

import (
	"fmt"
	"net/url"
	"strings"
)

// PublicPort validates advertised HTTP(S) addresses. Private container listeners
// are separate: the business process remains reachable only through its edge.
func PublicPort(u *url.URL) error {
	standard := "80"
	if u.Scheme == "https" {
		standard = "443"
	} else if u.Scheme != "http" {
		return fmt.Errorf("public endpoint must use HTTP or HTTPS")
	}
	if u.Port() != "" && u.Port() != standard {
		return fmt.Errorf("public %s endpoint must use port %s; other HTTP(S) ports are prohibited", u.Scheme, standard)
	}
	return nil
}

// Retired variables cannot silently turn into a successful nonstandard-port
// deployment. Standard legacy values are harmless during a rolling migration.
func validateRetiredPublicPorts(getenv func(string) string) error {
	for _, entry := range []struct{ key, port string }{{"HTTP_PORT", "80"}, {"HTTPS_PORT", "443"}} {
		if raw := strings.TrimSpace(getenv(entry.key)); raw != "" && raw != entry.port {
			return fmt.Errorf("%s is retired: public HTTP uses 80 and HTTPS uses 443; remove the nonstandard setting", entry.key)
		}
	}
	return nil
}
